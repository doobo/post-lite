package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

func TestExecuteFormDataSendsTextAndFileParts(t *testing.T) {
	ts := newTestServer(t)
	ts.allowLoopback()
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	up := newRecordingUpstream(t, `{"ok":true}`)

	rows := []map[string]any{
		{"k": "name", "v": "{{who}}", "type": "text", "on": true},
		{"k": "drop", "v": "ignored", "type": "text", "on": false},
		{
			"k": "upload", "type": "file", "on": true,
			"filename": "hello.txt",
			"v":        base64.StdEncoding.EncodeToString([]byte("file body")),
		},
	}
	fields, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method":    "POST",
			"url":       up.srv.URL + "/upload",
			"body_type": "form-data",
			"body":      string(fields),
		},
		"vars": map[string]string{"who": "ada"},
	})
	if code != http.StatusOK {
		t.Fatalf("form-data execute = %d (%s)", code, raw)
	}
	var out struct {
		Body string `json:"body"`
	}
	resp.decode(t, &out)
	if !strings.Contains(out.Body, `"ok":true`) {
		t.Errorf("response body = %q", out.Body)
	}

	ct := up.lastContentType()
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "multipart/form-data" {
		t.Fatalf("upstream Content-Type = %q, want multipart/form-data", ct)
	}
	mr := multipart.NewReader(strings.NewReader(up.lastBody()), params["boundary"])
	values := map[string]string{}
	filenames := map[string]string{}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading multipart body: %v", err)
		}
		b, _ := io.ReadAll(part)
		values[part.FormName()] = string(b)
		if part.FileName() != "" {
			filenames[part.FormName()] = part.FileName()
		}
	}
	if values["name"] != "ada" {
		t.Errorf("text part = %q, want resolved \"ada\"", values["name"])
	}
	if _, ok := values["drop"]; ok {
		t.Errorf("unchecked row %q reached the wire", values["drop"])
	}
	if values["upload"] != "file body" {
		t.Errorf("file part = %q, want decoded bytes", values["upload"])
	}
	if filenames["upload"] != "hello.txt" {
		t.Errorf("file name = %q, want hello.txt", filenames["upload"])
	}
}

func TestExecuteRejectsMalformedFormData(t *testing.T) {
	ts := newTestServer(t)
	ts.allowLoopback()
	admin := ts.cookie(ts.createUser("admin", "admin", loginPassword))
	code, resp, raw := ts.call("POST", "/api/execute", admin, map[string]any{
		"ad_hoc": map[string]any{
			"method":    "POST",
			"url":       "http://10.0.0.1/x",
			"body_type": "form-data",
			"body":      `not json`,
		},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("malformed form-data = %d, want 400 (%s)", code, raw)
	}
	if resp.Error == nil || resp.Error.Code != "bad_request" {
		t.Errorf("error = %+v, want bad_request", resp.Error)
	}
}
