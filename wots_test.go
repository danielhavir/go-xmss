package xmss

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// Randomly initialize address, for testing purposes only
func (a *address) initRandom() {
	randBytes := make([]byte, 32)
	rand.Read(randBytes)
	for i := 0; i < 32; i += 4 {
		a[i/4] = byteToUint32(randBytes[i : i+4])
	}
}

func TestWOTS(t *testing.T) {
	seed := make([]byte, n)
	rand.Read(seed)
	pubSeed := make([]byte, n)
	rand.Read(pubSeed)
	m := make([]byte, n)
	rand.Read(m)

	var a address
	a.initRandom()

	prv := *generatePrivate(seed)
	pub1 := *prv.generatePublic(pubSeed, &a)
	sign := *prv.sign(m, pubSeed, &a)
	pub2 := *sign.getPublic(m, pubSeed, &a)

	if !bytes.Equal(pub1, pub2) {
		t.Error("WOTS+ test failed. Public keys do not match")
	} else {
		fmt.Println("WOTS+ test successful.")
	}

}
