package tsync

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

// GenerateZipCryptoPassword generates a random 32-character ZipCrypto password.
func GenerateZipCryptoPassword() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(bytes), nil
}

// EncryptPassword encrypts a ZIP password using a VM public key and an ephemeral keypair.
// Returns the ephemeral public key (32 bytes) and the encrypted password (24-byte nonce + ciphertext + 16-byte Poly1305 tag).
func EncryptPassword(password string, vmPubKeySlice []byte) (ephPubKey []byte, encryptedPassword []byte, err error) {
	if len(vmPubKeySlice) != 32 {
		return nil, nil, fmt.Errorf("invalid VM public key length: expected 32 bytes, got %d", len(vmPubKeySlice))
	}

	var vmPubKey [32]byte
	copy(vmPubKey[:], vmPubKeySlice)

	// 1. Generate ephemeral Curve25519 keypair
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// 2. Generate random 24-byte nonce
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to read random nonce: %w", err)
	}

	// 3. Encrypt using NaCl Box
	// The ciphertext returned by box.Seal has a 16-byte Poly1305 tag appended.
	// We pass nonce[:] as the prefix (out) to automatically prepend it,
	// or we can slice it separately. Prepended nonce is exactly what's requested:
	// wire format: nonce (24 bytes) || ciphertext || Poly1305 tag (16 bytes)
	ciphertext := box.Seal(nonce[:], []byte(password), &nonce, &vmPubKey, ephPriv)

	return ephPub[:], ciphertext, nil
}

// DecryptPassword decrypts the encrypted ZIP password using the VM's private key and the ephemeral public key.
func DecryptPassword(encryptedPassword []byte, ephPubKeySlice []byte, vmPrivKeySlice []byte) (string, error) {
	if len(ephPubKeySlice) != 32 {
		return "", fmt.Errorf("invalid ephemeral public key length: expected 32 bytes, got %d", len(ephPubKeySlice))
	}
	if len(vmPrivKeySlice) != 32 {
		return "", fmt.Errorf("invalid VM private key length: expected 32 bytes, got %d", len(vmPrivKeySlice))
	}
	if len(encryptedPassword) < 24+16 {
		return "", fmt.Errorf("invalid encrypted password length: must be at least 40 bytes (24 nonce + 16 tag), got %d", len(encryptedPassword))
	}

	var ephPubKey [32]byte
	copy(ephPubKey[:], ephPubKeySlice)

	var vmPrivKey [32]byte
	copy(vmPrivKey[:], vmPrivKeySlice)

	// 1. Extract 24-byte nonce
	var nonce [24]byte
	copy(nonce[:], encryptedPassword[:24])

	// 2. The remaining bytes are the ciphertext + Poly1305 tag
	ciphertext := encryptedPassword[24:]

	// 3. Decrypt using NaCl Box
	decrypted, ok := box.Open(nil, ciphertext, &nonce, &ephPubKey, &vmPrivKey)
	if !ok {
		return "", fmt.Errorf("failed to decrypt password: NaCl Box decryption failed (key mismatch or corrupted data)")
	}

	return string(decrypted), nil
}
