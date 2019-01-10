package xmss

import "math"

// Section 3.1.1.
// The value of n is determined by the cryptographic hash function used
// for WOTS+. SHA256 -> n = 32
const (
	n     = 32
	w     = 16
	log2w = 4 // log_2 (16) = 4
)

var (
	len1        = uint32(math.Ceil(8 * n / log2w))
	len2        = uint32(math.Floor(math.Log2(float64(len1*(w-1)))/math.Log2(w))) + 1 // len2 = 3
	wlen        = len1 + len2
	wotsSignLen = wlen * n
)

// Expands an n-byte array into a len*n byte array using the `prf` function
func expandSeed(inseed []byte) (expanded []byte) {
	expanded = make([]byte, wotsSignLen)

	ctr := make([]byte, 32)
	var idx int
	for i := 0; i < int(wlen); i++ {
		ctr = toByte(i, 32)
		idx = i * n
		hashPRF(expanded[idx:idx+n], inseed, ctr)
	}
	return
}

// Section 2.6 Strings of Base w Numbers
// Algorithm 1: base_w
func basew(x, output []byte) {
	in := 0
	out := 0
	total := uint(0)
	bits := uint(0)
	for i := 0; i < len(output); i++ {
		if bits == 0 {
			total = uint(x[in])
			in++
			bits += 8
		}
		bits -= log2w
		output[out] = uint8(total>>bits) & (uint8(w) - 1)
		out++
	}
}

// Section 3.1.2. Algorithm 2: chain - Chaining Function
// out and in have to be n-byte arrays, a is the address of the chain
func chain(out, in, seed []byte, start, steps uint32, a *address) {
	copy(out, in)

	for i := start; i < (start + steps); i++ {
		a.setHashAddr(i)
		hashF(out, seed, out, a)
	}
}

// Takes a message and derives the matching chain lengths.
// Computes the WOTS+ checksum over a message (in base_w)
// lengths is a wlen-byte array (e.g. 67)
func wotsChecksum(lengths, in []byte) {
	basew(in, lengths[:len1])

	var csum uint16
	for i := 0; i < int(len1); i++ {
		csum += w - 1 - uint16(lengths[i])
	}
	csum <<= 4
	csumBytes := toByte(int(csum), int(len2*log2w+7)/8)
	basew(csumBytes, lengths[len1:])
}

type privateWOTS []byte
type publicWOTS []byte
type signatureWOTS []byte

// Section 3.1.3. Algorithm 3: WOTS_genSK - Generating a WOTS+ Private Key
func generatePrivate(seed []byte) *privateWOTS {
	var prv privateWOTS
	prv = expandSeed(seed)
	return &prv
}

// Section 3.1.4. Algorithm 4: WOTS_genPK - Generating a WOTS+ Public Key From a Private Key
// WOTS key generation. Takes a 32 byte seed for the private key, expands it to
// a full WOTS private key and computes the corresponding public key.
// It requires the seed pubSeed (used to generate bitmasks and hash keys)
// and the address of this WOTS key pair.
func (prv privateWOTS) generatePublic(pubSeed []byte, a *address) *publicWOTS {
	var pub publicWOTS
	// prv is wotsSignLen(wlen*n)-byte array
	pub = make([]byte, len(prv))

	for i := uint32(0); i < wlen; i++ {
		a.setChainAddr(i)
		idx := i * n
		chain(pub[idx:idx+n], prv[idx:idx+n], pubSeed, 0, w-1, a)
	}

	return &pub
}

// Section 3.1.5. Algorithm 5: WOTS_sign - Generating a signature from a private key and a message
// Takes a n-byte message and the 32-byte seed for the private key to compute a
// signature that is placed at 'sig'.
func (prv privateWOTS) sign(in, pubSeed []byte, a *address) *signatureWOTS {
	lengths := make([]byte, wlen)
	wotsChecksum(lengths, in)

	var sign signatureWOTS
	sign = make([]byte, len(prv))
	copy(sign, prv)

	for i := uint32(0); i < wlen; i++ {
		a.setChainAddr(i)
		idx := i * n
		chain(sign[idx:idx+n], sign[idx:idx+n], pubSeed, 0, uint32(lengths[i]), a)
	}

	return &sign
}

// Section 3.1.6. Algorithm 6: WOTS_pkFromSig - Computing a WOTS+ public key from a message and its signature
// Takes a WOTS signature and an n-byte message, computes a WOTS public key.
func (sign signatureWOTS) getPublic(in, pubSeed []byte, a *address) *publicWOTS {
	lengths := make([]byte, wlen)
	wotsChecksum(lengths, in)

	var pub publicWOTS
	pub = make([]byte, wotsSignLen)

	for i := uint32(0); i < wlen; i++ {
		a.setChainAddr(i)
		idx := i * n
		chain(pub[idx:idx+n], sign[idx:idx+n], pubSeed, uint32(lengths[i]), w-1-uint32(lengths[i]), a)
	}

	return &pub
}
