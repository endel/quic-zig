// Isolated benchmark of the cryptographic primitives used in QUIC TLS 1.3.
// Compare with: zig build-exe -OReleaseFast tools/bench_crypto.zig && ./bench_crypto
//
// Usage:
//   go run tools/bench_crypto.go
//
// Operations benchmarked (matching the Zig benchmark exactly):
//   1. ECDSA P-256 Sign
//   2. ECDSA P-256 Verify
//   3. X25519 scalarmult
//   4. AES-128-GCM Seal (encrypt)
//   5. AES-128-GCM Open (decrypt)
//   6. HKDF-SHA256 Extract
//   7. HKDF-SHA256 Expand
//   8. AES-128-ECB (header protection mask)

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func benchNs(f func(), iterations int) float64 {
	// Warmup
	for i := 0; i < 10; i++ {
		f()
	}

	start := time.Now()
	for i := 0; i < iterations; i++ {
		f()
	}
	elapsed := time.Since(start)
	return float64(elapsed.Nanoseconds()) / float64(iterations)
}

func main() {
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  Crypto Primitive Benchmark (Go crypto)")
	fmt.Println("  Compare with: zig build-exe -OReleaseFast tools/bench_crypto.zig")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	// ── Setup keys ──

	// ECDSA P-256
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signContent := make([]byte, 130)
	for i := 0; i < 64; i++ {
		signContent[i] = 0x20
	}
	copy(signContent[64:98], "TLS 1.3, server CertificateVerify")
	signContent[98] = 0x00
	for i := 99; i < 130; i++ {
		signContent[i] = 0xAA
	}

	// Pre-hash for ECDSA (Go's crypto/ecdsa signs a hash, not raw message)
	msgHash := sha256.Sum256(signContent)

	var ecSig []byte
	var ecErr error

	// X25519
	x25519Secret := make([]byte, 32)
	rand.Read(x25519Secret)
	x25519Public, _ := curve25519.X25519(x25519Secret, curve25519.Basepoint)

	// AES-128-GCM
	aesKey := make([]byte, 16)
	rand.Read(aesKey)
	aesNonce := make([]byte, 12)
	rand.Read(aesNonce)
	plaintext := make([]byte, 1200)
	rand.Read(plaintext)
	ad := make([]byte, 20)
	rand.Read(ad)

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	ciphertext := gcm.Seal(nil, aesNonce, plaintext, ad)

	// HKDF
	hkdfSalt := make([]byte, 32)
	hkdfIKM := make([]byte, 32)
	hkdfInfo := make([]byte, 50)
	rand.Read(hkdfSalt)
	rand.Read(hkdfIKM)
	rand.Read(hkdfInfo)

	// Precompute PRK for expand benchmark
	prkReader := hkdf.Extract(sha256.New, hkdfIKM, hkdfSalt)

	// AES-128-ECB (header protection)
	hpBlock, _ := aes.NewCipher(aesKey)
	hpSample := make([]byte, 16)
	rand.Read(hpSample)

	// ── Run benchmarks ──

	const N_SIGN = 1000
	const N_VERIFY = 1000
	const N_X25519 = 5000
	const N_AES = 100000
	const N_HKDF = 100000
	const N_HP = 500000

	signNs := benchNs(func() {
		ecSig, ecErr = ecdsa.SignASN1(rand.Reader, ecKey, msgHash[:])
		_ = ecErr
	}, N_SIGN)

	verifyNs := benchNs(func() {
		ecdsa.VerifyASN1(&ecKey.PublicKey, msgHash[:], ecSig)
	}, N_VERIFY)

	x25519Ns := benchNs(func() {
		curve25519.X25519(x25519Secret, x25519Public)
	}, N_X25519)

	encNs := benchNs(func() {
		gcm.Seal(ciphertext[:0], aesNonce, plaintext, ad)
	}, N_AES)

	decNs := benchNs(func() {
		gcm.Open(plaintext[:0], aesNonce, ciphertext, ad)
	}, N_AES)

	extractNs := benchNs(func() {
		hkdf.Extract(sha256.New, hkdfIKM, hkdfSalt)
	}, N_HKDF)

	expandNs := benchNs(func() {
		r := hkdf.Expand(sha256.New, prkReader, hkdfInfo)
		buf := make([]byte, 32)
		io.ReadFull(r, buf)
	}, N_HKDF)

	hpOut := make([]byte, 16)
	hpNs := benchNs(func() {
		hpBlock.Encrypt(hpOut, hpSample)
	}, N_HP)

	type result struct {
		name string
		ns   float64
	}

	results := []result{
		{"ECDSA P-256 Sign", signNs},
		{"ECDSA P-256 Verify", verifyNs},
		{"X25519 scalarmult", x25519Ns},
		{"AES-128-GCM encrypt (1200B)", encNs},
		{"AES-128-GCM decrypt (1200B)", decNs},
		{"HKDF-SHA256 extract", extractNs},
		{"HKDF-SHA256 expand", expandNs},
		{"AES-128-ECB (HP mask)", hpNs},
	}

	fmt.Printf("  %-28s %10s  %10s\n", "Operation", "ns/op", "ops/sec")
	fmt.Printf("  ────────────────────────── ──────────  ──────────\n")
	for _, r := range results {
		opsSec := 1_000_000_000.0 / r.ns
		fmt.Printf("  %-28s %10.0f  %10.0f\n", r.name, r.ns, opsSec)
	}

	hsNs := signNs + verifyNs + x25519Ns + 4*(extractNs+expandNs)
	fmt.Printf("\n  Handshake estimate (sign + verify + x25519 + 4×HKDF):\n")
	fmt.Printf("  %.0fµs per handshake (%.0f handshakes/s)\n", hsNs/1000.0, 1_000_000_000.0/hsNs)

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════")
}
