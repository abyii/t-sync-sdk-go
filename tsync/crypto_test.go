package tsync

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// ---------------------------------------------------------
// Unit Tests for Crypto Functions
// ---------------------------------------------------------

func TestCryptoGenerateAndEncryptDecrypt(t *testing.T) {
	vmPub, vmPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate VM keys: %v", err)
	}

	clearPass, err := GenerateZipCryptoPassword()
	if err != nil {
		t.Fatalf("failed to generate password: %v", err)
	}
	if len(clearPass) != 32 {
		t.Errorf("expected 32 chars password, got %d", len(clearPass))
	}

	ephPub, encPass, err := EncryptPassword(clearPass, vmPub[:])
	if err != nil {
		t.Fatalf("failed to encrypt password: %v", err)
	}
	if len(ephPub) != 32 {
		t.Errorf("expected 32 bytes ephemeral public key, got %d", len(ephPub))
	}

	decryptedPass, err := DecryptPassword(encPass, ephPub, vmPriv[:])
	if err != nil {
		t.Fatalf("failed to decrypt password: %v", err)
	}

	if decryptedPass != clearPass {
		t.Fatalf("passwords mismatch: expected %q, got %q", clearPass, decryptedPass)
	}
}
