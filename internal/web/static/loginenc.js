/* PostLite login encryption, no-crypto.subtle fallback.
 *
 * WebCrypto is only exposed in a secure context (HTTPS or localhost), so over
 * plain HTTP on an intranet address the login page has no crypto.subtle to
 * encrypt the password with. This file is the self-contained replacement: RSA
 * OAEP (RFC 8017 EME-OAEP, MGF1-SHA-256, empty label) over BigInt, matching what
 * internal/auth/loginenc.go decrypts with rsa.DecryptOAEP(sha256.New(), ...).
 *
 * Deliberately not a general-purpose crypto library:
 *   - only the encrypt side exists, and only for one 2048-bit key per login;
 *   - the modulus/exponent come from GET /api/auth/login-key, so no DER parsing;
 *   - a wrong result is not a security hole for the callers of this file: an
 *     encrypted payload that does not decrypt is rejected by the server, and the
 *     password never leaves the page in clear text either way.
 *
 * Randomness comes from crypto.getRandomValues, which (unlike crypto.subtle) is
 * available in insecure contexts. Without it we refuse to encrypt rather than
 * fall back to Math.random.
 */
var LoginEnc = (function () {
  'use strict';

  var H_LEN = 32;

  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  // sha256 returns the FIPS 180-4 digest of bytes as a Uint8Array(32).
  function sha256(bytes) {
    var len = bytes.length;
    var padded = new Uint8Array((((len + 9) >> 6) + 1) << 6);
    padded.set(bytes);
    padded[len] = 0x80;
    var view = new DataView(padded.buffer);
    var bits = len * 8;
    view.setUint32(padded.length - 8, Math.floor(bits / 0x100000000));
    view.setUint32(padded.length - 4, bits >>> 0);

    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Uint32Array(64);

    for (var off = 0; off < padded.length; off += 64) {
      var i, s0, s1;
      for (i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
      for (i = 16; i < 64; i++) {
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
      h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
      h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }

    var out = new Uint8Array(32);
    var ov = new DataView(out.buffer);
    for (var j = 0; j < 8; j++) ov.setUint32(j * 4, h[j]);
    return out;
  }

  // mgf1 is the MGF1 mask of RFC 8017 B.2.1 with SHA-256 as the hash.
  function mgf1(seed, len) {
    var blocks = Math.ceil(len / H_LEN);
    var out = new Uint8Array(blocks * H_LEN);
    var buf = new Uint8Array(seed.length + 4);
    buf.set(seed);
    for (var i = 0; i < blocks; i++) {
      buf[seed.length] = (i >>> 24) & 0xff;
      buf[seed.length + 1] = (i >>> 16) & 0xff;
      buf[seed.length + 2] = (i >>> 8) & 0xff;
      buf[seed.length + 3] = i & 0xff;
      out.set(sha256(buf), i * H_LEN);
    }
    return out.subarray(0, len);
  }

  // xorInto resolves to a ^= b for equal-length arrays.
  function xorInto(a, b, from) {
    for (var i = 0; i < b.length; i++) a[from + i] ^= b[i];
  }

  function randomBytes(n) {
    var c = (typeof globalThis !== 'undefined' && globalThis.crypto) || null;
    if (!c || typeof c.getRandomValues !== 'function') {
      throw new Error('no secure random source available');
    }
    return c.getRandomValues(new Uint8Array(n));
  }

  // os2ip / i2osp are RFC 8017 4.2 and 4.1 for non-negative integers.
  function os2ip(bytes) {
    var x = 0n;
    for (var i = 0; i < bytes.length; i++) x = (x << 8n) | BigInt(bytes[i]);
    return x;
  }

  function i2osp(x, len) {
    var out = new Uint8Array(len);
    for (var i = len - 1; i >= 0; i--) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return out;
  }

  function modPow(base, exp, mod) {
    var result = 1n;
    var b = base % mod;
    var e = exp;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % mod;
      b = (b * b) % mod;
      e >>= 1n;
    }
    return result;
  }

  function normalizeHex(hex) {
    var h = String(hex).trim().replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]+$/.test(h)) throw new Error('bad RSA modulus');
    return (h.length % 2 ? '0' + h : h).toLowerCase();
  }

  function toBase64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  // encrypt returns base64(RSA-OAEP-SHA256(message)) for the public key (n, e).
  function encrypt(message, nHex, e) {
    var hex = normalizeHex(nHex);
    var k = hex.length >> 1;
    var msg = new TextEncoder().encode(message);
    if (msg.length > k - 2 * H_LEN - 2) {
      throw new Error('payload too long for the login key');
    }

    var n = BigInt('0x' + hex);
    var db = new Uint8Array(k - H_LEN - 1);
    db.set(sha256(new Uint8Array(0)), 0);           // lHash("")
    db[db.length - msg.length - 1] = 0x01;          // 0x00.. : separator
    db.set(msg, db.length - msg.length);

    var seed = randomBytes(H_LEN);
    xorInto(db, mgf1(seed, db.length), 0);          // maskedDB
    var maskedSeed = new Uint8Array(H_LEN);
    maskedSeed.set(seed);
    xorInto(maskedSeed, mgf1(db, H_LEN), 0);        // maskedSeed

    var em = new Uint8Array(k);
    em.set(maskedSeed, 1);                          // EM = 0x00 || maskedSeed || maskedDB
    em.set(db, 1 + H_LEN);

    return toBase64(i2osp(modPow(os2ip(em), BigInt(e), n), k));
  }

  return { encrypt: encrypt };
})();
