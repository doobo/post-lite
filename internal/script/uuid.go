package script

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// UUIDModule serves pm.require('npm:uuid@9.0.0'). Postman scripts use it for the
// nonce of a signature, which is why it ships instead of letting a script try to
// reach npm.
//
// Implemented surface:
//
//	uuid.v1()               -> string (time based, monotonic within the process)
//	uuid.v4()               -> string (random)
//	uuid.v5(name, ns)       -> string (SHA-1, ns defaults to uuid.DNS)
//	uuid.validate(s)        -> boolean
//	uuid.version(s)         -> number (throws for an invalid uuid)
//	uuid.parse(s)           -> Uint8Array(16)
//	uuid.stringify(bytes)   -> string
//	uuid.NIL / uuid.MAX / uuid.DNS / uuid.URL / uuid.OID / uuid.X500
type UUIDModule struct{}

// uuidID is the canonical ID; the same module also answers to "npm:uuid".
const uuidID = "npm:uuid@9.0.0"

// ID implements BuiltinModule.
func (UUIDModule) ID() string { return uuidID }

// Register implements BuiltinModule.
func (UUIDModule) Register(vm *goja.Runtime) goja.Value {
	obj := vm.NewObject()
	obj.Set("v1", func(goja.FunctionCall) goja.Value { return vm.ToValue(newV1()) })
	obj.Set("v4", func(goja.FunctionCall) goja.Value { return vm.ToValue(newV4()) })
	obj.Set("v5", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		ns := uuidDNS
		if a := call.Argument(1); !goja.IsUndefined(a) && !goja.IsNull(a) {
			parsed, err := parseUUID(a.String())
			if err != nil {
				throwType(vm, "uuid.v5: %v", err)
			}
			ns = parsed
		}
		return vm.ToValue(newV5(ns, name))
	})
	obj.Set("validate", func(call goja.FunctionCall) goja.Value {
		_, err := parseUUID(call.Argument(0).String())
		return vm.ToValue(err == nil)
	})
	obj.Set("version", func(call goja.FunctionCall) goja.Value {
		id, err := parseUUID(call.Argument(0).String())
		if err != nil {
			throwType(vm, "uuid.version: %v", err)
		}
		return vm.ToValue(int(id[6] >> 4))
	})
	obj.Set("parse", func(call goja.FunctionCall) goja.Value {
		id, err := parseUUID(call.Argument(0).String())
		if err != nil {
			throwType(vm, "uuid.parse: %v", err)
		}
		return NewBytes(vm, id[:])
	})
	obj.Set("stringify", func(call goja.FunctionCall) goja.Value {
		b, err := Bytes(vm, call.Argument(0))
		if err != nil {
			throwType(vm, "uuid.stringify: %v", err)
		}
		if len(b) != 16 {
			throwType(vm, "uuid.stringify: bad length: %d (want 16)", len(b))
		}
		return vm.ToValue(formatUUID(b))
	})

	obj.Set("NIL", uuidNIL)
	obj.Set("MAX", uuidMAX)
	obj.Set("DNS", formatUUID(uuidDNS[:]))
	obj.Set("URL", formatUUID(uuidURL[:]))
	obj.Set("OID", formatUUID(uuidOID[:]))
	obj.Set("X500", formatUUID(uuidX500[:]))
	return obj
}

const (
	uuidNIL = "00000000-0000-0000-0000-000000000000"
	uuidMAX = "ffffffff-ffff-ffff-ffff-ffffffffffff"
)

var (
	uuidDNS  = [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	uuidURL  = [16]byte{0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	uuidOID  = [16]byte{0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	uuidX500 = [16]byte{0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
)

// gregorianOffset is the number of 100ns intervals between the UUID epoch
// (1582-10-15) and the Unix epoch.
const gregorianOffset = 122192928000000000

// v1 state. A single process-wide generator keeps clock sequence and node
// stable, and makes two calls inside the same 100ns tick still distinct.
var v1State struct {
	sync.Mutex
	lastTS   uint64
	clockSeq uint16
	node     [6]byte
	ready    bool
}

func newV1() string {
	v1State.Lock()
	defer v1State.Unlock()
	if !v1State.ready {
		var seed [8]byte
		_, _ = rand.Read(seed[:])
		v1State.node = [6]byte{seed[0], seed[1], seed[2], seed[3], seed[4], seed[5]}
		v1State.node[0] |= 0x01 // multicast bit: the node id is random, not a MAC
		v1State.clockSeq = (uint16(seed[6])<<8 | uint16(seed[7])) & 0x3fff
		v1State.ready = true
	}

	ts := uint64(time.Now().UnixNano()/100) + gregorianOffset
	if ts <= v1State.lastTS {
		// Same 100ns tick, or the clock was set back: keep the timestamp
		// monotonic and bump the clock sequence, so ids stay unique and ordered.
		ts = v1State.lastTS + 1
		v1State.clockSeq = (v1State.clockSeq + 1) & 0x3fff
	}
	v1State.lastTS = ts

	var id [16]byte
	binary.BigEndian.PutUint32(id[0:4], uint32(ts))
	binary.BigEndian.PutUint16(id[4:6], uint16(ts>>32))
	binary.BigEndian.PutUint16(id[6:8], uint16(ts>>48)&0x0fff|0x1000)
	id[8] = byte(0x80 | (v1State.clockSeq>>8)&0x3f)
	id[9] = byte(v1State.clockSeq)
	copy(id[10:], v1State.node[:])
	return formatUUID(id[:])
}

func newV4() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic("script: no entropy available: " + err.Error())
	}
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return formatUUID(id[:])
}

func newV5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var id [16]byte
	copy(id[:], sum[:16])
	id[6] = id[6]&0x0f | 0x50
	id[8] = id[8]&0x3f | 0x80
	return formatUUID(id[:])
}

// formatUUID renders 16 bytes in the canonical 8-4-4-4-12 form.
func formatUUID(b []byte) string {
	h := hex.EncodeToString(b[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// parseUUID is the inverse of formatUUID. Besides the canonical form it accepts
// the braced and urn:uuid: spellings, like the uuid package does.
func parseUUID(s string) ([16]byte, error) {
	var out [16]byte
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(strings.TrimPrefix(t, "urn:uuid:"), "urn:UUID:")
	t = strings.TrimPrefix(strings.TrimSuffix(t, "}"), "{")
	if len(t) != 36 || t[8] != '-' || t[13] != '-' || t[18] != '-' || t[23] != '-' {
		return out, fmt.Errorf("invalid uuid %q", s)
	}
	h := t[0:8] + t[9:13] + t[14:18] + t[19:23] + t[24:36]
	raw, err := hex.DecodeString(h)
	if err != nil {
		return out, fmt.Errorf("invalid uuid %q", s)
	}
	copy(out[:], raw)
	return out, nil
}
