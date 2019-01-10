package xmss

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestXMSS(t *testing.T) {
	prv, pub := GenerateXMSSKeypair()

	msg := make([]byte, 32)
	rand.Read(msg)
	m := make([]byte, int(signBytes)+len(msg))

	initIndex := make([]byte, indexBytes)
	copy(initIndex, (*prv)[:indexBytes])
	signature := *prv.Sign(msg)
	afterIndex := (*prv)[:indexBytes]

	if !Verify(m, signature, *pub) {
		t.Error("XMSS test failed. Verification does not match")
	} else {
		fmt.Println("XMSS signature matches.")
	}

	signature[len(signature)-1] ^= 1
	if Verify(m, signature, *pub) {
		t.Error("XMSS test failed. Flipped bit did not invalidate")
	} else {
		fmt.Println("Flipping a bit correctly invalides the XMSS signature.")
	}
	signature[len(signature)-1] ^= 1

	if bytes.Equal(initIndex, afterIndex) {
		t.Error("XMSS test failed. The signature did not update the private key's index")
		fmt.Println("Init: ", initIndex)
		fmt.Println("After: ", afterIndex)
	} else {
		fmt.Println("XMSS signature updated the private key's index.")
	}
}
