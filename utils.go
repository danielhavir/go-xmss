/*
	utils.go

	Utility script for reading, writing files and hex encoding/decoding

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
	A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
	OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	utils.go Daniel Havir, 2018
*/

package xmss

import (
	"encoding/binary"
)

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
