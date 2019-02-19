package xmss

import "crypto/sha256"

// PRF: SHA2-256(toByte(3, 32) || KEY || M)
// Message must be exactly 32 bytes
func hashPRF(params *Params, out, key, m []byte) {
	h := sha256.New()
	h.Write(toByte(3, params.n))
	h.Write(key)
	h.Write(m)
	copy(out, h.Sum(nil))
}

// H_msg: SHA2-256(toByte(2, 32) || KEY || M)
// Computes the message hash using R, the public root, the index of the leaf
// node, and the message.
func hashMsg(params *Params, out, R, root, mPlus []byte, idx uint64) {
	h := sha256.New()
	copy(mPlus[:params.n], toByte(2, params.n))
	copy(mPlus[params.n:2*params.n], R)
	copy(mPlus[2*params.n:3*params.n], root)
	copy(mPlus[3*params.n:4*params.n], toByte(int(idx), params.n))
	h.Write(mPlus)
	copy(out, h.Sum(nil))
}

// H: SHA2-256(toByte(1, 32) || KEY || M)
// A cryptographic hash function H.  H accepts n-byte keys and byte
// strings of length 2n and returns an n-byte string.
// Includes: Algorithm 7: RAND_HASH
func hashH(params *Params, out, seed, m []byte, a *address) {
	h := sha256.New()
	h.Write(toByte(1, params.n))

	// Generate the n-byte key
	a.setKeyAndMask(0)
	buf := make([]byte, 3*params.n)
	hashPRF(params, buf[:params.n], seed, a.toByte())

	// Generate the 2n-byte mask
	a.setKeyAndMask(1)
	bitmask := make([]byte, 2*params.n)
	hashPRF(params, bitmask[:params.n], seed, a.toByte())
	a.setKeyAndMask(2)
	hashPRF(params, bitmask[params.n:], seed, a.toByte())

	xor(buf[params.n:], m, bitmask)
	h.Write(buf)

	copy(out, h.Sum(nil))
}

// F: SHA2-256(toByte(0, 32) || KEY || M)
func hashF(params *Params, out, seed, m []byte, a *address) {
	h := sha256.New()
	h.Write(make([]byte, params.n))

	// Generate the n-byte key
	a.setKeyAndMask(0)
	buf := make([]byte, 2*params.n)
	hashPRF(params, buf[:params.n], seed, a.toByte())

	// Generate the n-byte mask
	a.setKeyAndMask(1)
	bitmask := make([]byte, params.n)
	hashPRF(params, bitmask, seed, a.toByte())
	xor(buf[params.n:], m, bitmask)
	h.Write(buf)

	copy(out, h.Sum(nil))
}
