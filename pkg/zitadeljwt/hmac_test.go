package zitadeljwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHMACVerifier_ValidSignature(t *testing.T) {
	key := "my-secret-key"
	body := []byte(`{"event_type":"user.human.added","user":{"id":"123"}}`)

	// Compute expected signature.
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	v := newHMACVerifier(key)

	if err := v.VerifyWithSignature(body, sig); err != nil {
		t.Fatalf("expected valid signature, got error: %v", err)
	}
}

func TestHMACVerifier_InvalidSignature(t *testing.T) {
	v := newHMACVerifier("my-secret-key")
	body := []byte(`{"event_type":"user.human.added"}`)

	err := v.VerifyWithSignature(body, "sha256=deadbeef")
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestHMACVerifier_MissingHeader(t *testing.T) {
	v := newHMACVerifier("my-secret-key")
	body := []byte(`{"event_type":"user.human.added"}`)

	err := v.VerifyWithSignature(body, "")
	if err == nil {
		t.Fatal("expected error for missing header")
	}
}

func TestHMACVerifier_InvalidFormat(t *testing.T) {
	v := newHMACVerifier("my-secret-key")
	body := []byte(`test`)

	err := v.VerifyWithSignature(body, "md5=abcdef")
	if err == nil {
		t.Fatal("expected error for invalid format (not sha256=)")
	}
}
