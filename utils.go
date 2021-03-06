package xmss

import "encoding/binary"

func xor(out, a, b []byte) {
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}
}

// If x and y are non-negative integers, we define Z = toByte(x, y) to
// be the y-byte string containing the binary representation of x in
// big-endian byte order.
func toByte(x, y int) (z []byte) {
	z = make([]byte, y)
	ux := uint64(x)
	var xByte byte
	for i := y - 1; i >= 0; i-- {
		xByte = byte(ux)
		z[i] = xByte & 0xff
		ux = ux >> 8
	}
	return
}

func fromByte(x []byte, y int) (z uint64) {
	z = 0

	for i := 0; i < y; i++ {
		z |= (uint64(x[i])) << (8 * uint64(y-1-i))
	}
	return
}

func byteToUint32(in []byte) (out uint32) {
	out = binary.BigEndian.Uint32(in)
	return
}

func uint32ToByte(in uint32) (out []byte) {
	out = make([]byte, 4)
	binary.BigEndian.PutUint32(out, in)
	return
}

func uint64ToByte(in uint64) (out []byte) {
	out = make([]byte, 8)
	binary.BigEndian.PutUint64(out, in)
	return
}
