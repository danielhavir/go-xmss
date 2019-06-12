package xmss

import (
	"bytes"
	"crypto/rand"
	"testing"
	"io/ioutil"
)

const (
	dataDir string = "test/testdata"
)

func TestXMSS(t *testing.T) {
	t.Parallel()
	params := SHA2_10_256
	prv, pub := GenerateXMSSKeypair(params)
	var sig SignatureXMSS
	msg := make([]byte, 32)
	rand.Read(msg)
	m := make([]byte, params.SignBytes()+len(msg))

	t.Run("sign_and_check_index", func(t *testing.T) {
		initIndex := make([]byte, params.indexBytes)
		copy(initIndex, (*prv)[:params.indexBytes])
		sig = *prv.Sign(params, msg)
		afterIndex := (*prv)[:params.indexBytes]
		if bytes.Equal(initIndex, afterIndex) {
			t.Error("XMSS test failed. The signature did not update the private key's index")
			t.Log("Init: ", initIndex)
			t.Log("After: ", afterIndex)
		}
	})

	t.Run("verify_generated", func(t *testing.T){
		if !Verify(params, m, sig, *pub) {
			t.Error("XMSS test failed. Verification does not match")
		}
	})
}

func TestVerify(t *testing.T) {
	t.Parallel()
	testParams := map[string]*Params{
		"SHA2_10_256": SHA2_10_256,
		"SHA2_16_256": SHA2_16_256,
		"SHA2_20_256": SHA2_20_256,
	}
	msg, err := ioutil.ReadFile(dataDir + "/message_data")
	if err != nil {
		t.Fatal(err)
	}
	for name, params := range testParams {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var pub PublicXMSS
			var sig SignatureXMSS
			fileName := dataDir + "/" + name
			pub, err := ioutil.ReadFile(fileName + ".pub")
			if err != nil {
				t.Fatal(err)
			}
			sig, err = ioutil.ReadFile(fileName + ".sig")
			if err != nil {
				t.Fatal(err)
			}
			m := make([]byte, params.SignBytes()+len(msg))
			if !Verify(params, m, sig, pub) {
				t.Error("XMSS test failed. Verification does not match")
			}
			sig[len(sig)-1] ^= 1
			if Verify(params, m, sig, pub) {
				t.Error("XMSS test failed. Flipped bit did not invalidate")
			}
		})
	}
}