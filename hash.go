package xmss

import (
	"crypto/sha256"
)

// SHA2 does not provide a keyed-mode itself.  To implement the keyed
// hash functions, the following is used for SHA2 with n = 32

// PRF: SHA2-256(toByte(3, 32) || KEY || M)
// Message must be exactly 32 bytes
func hashPRF(out, key, m []byte) {
	h := sha256.New()
	h.Write(toByte(3, n))
	h.Write(key)
	h.Write(m)
	copy(out, h.Sum(nil))
}

// H_msg: SHA2-256(toByte(2, 32) || KEY || M)
// Computes the message hash using R, the public root, the index of the leaf
// node, and the message.
func hashMsg(out, R, root, mPlus []byte, idx uint64) {
	h := sha256.New()
	copy(mPlus[:n], toByte(2, n))
	copy(mPlus[n:2*n], R)
	copy(mPlus[2*n:3*n], root)
	copy(mPlus[3*n:4*n], toByte(int(idx), n))
	h.Write(mPlus)
	copy(out, h.Sum(nil))
}

// H: SHA2-256(toByte(1, 32) || KEY || M)
// A cryptographic hash function H.  H accepts n-byte keys and byte
// strings of length 2n and returns an n-byte string.
// Includes: Algorithm 7: RAND_HASH
func hashH(out, seed, m []byte, a *address) {
	h := sha256.New()
	h.Write(toByte(1, n))

	// Generate the n-byte key
	a.setKeyAndMask(0)
	buf := make([]byte, 3*n)
	hashPRF(buf[:n], seed, a.toByte())

	// Generate the 2n-byte mask
	a.setKeyAndMask(1)
	bitmask := make([]byte, 2*n)
	hashPRF(bitmask[:n], seed, a.toByte())
	a.setKeyAndMask(2)
	hashPRF(bitmask[n:], seed, a.toByte())

	xor(buf[n:], m, bitmask)
	h.Write(buf)

	copy(out, h.Sum(nil))
}

// F: SHA2-256(toByte(0, 32) || KEY || M)
func hashF(out, seed, m []byte, a *address) {
	h := sha256.New()
	h.Write(make([]byte, n))

	// Generate the n-byte key
	a.setKeyAndMask(0)
	buf := make([]byte, 2*n)
	hashPRF(buf[:n], seed, a.toByte())

	// Generate the n-byte mask
	a.setKeyAndMask(1)
	bitmask := make([]byte, n)
	hashPRF(bitmask, seed, a.toByte())
	xor(buf[n:], m, bitmask)
	h.Write(buf)

	copy(out, h.Sum(nil))
}
