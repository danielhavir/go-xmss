// gen_test_data is a helper tool to generate test data to speed up
// the unit test process since the larger height Merkle trees take
// a long time to generate the keypairs.
//
// Files for the public and private key in test/testdata directory
// with the format of:
//
// test/testdata/message_data      // message data used by signature
// test/testdata/{param_name}.pub  // public  key bytes blob
// test/testdata/{param_name}.key  // private key bytes blob
// test/testdata/{param_name}.sig  //  signature for message data
//
// Note: on a laptop with a 2.2GHz i7 processor key generation times are:
// SHA2_10_256 	             ~5 seconds
// SHA2_16_256  ~  2 minutes 40 seconds
// SHA2_20_256  ~ 42 minutes
//
// Note: Double these times for expected runtime, signing takes roughly as long
// as key generation.

package main

import (
	"crypto/rand"
	"io/ioutil"
	"log"
	"os"

	"github.com/danielhavir/go-xmss"
)

const (
	testDataDir = "../../test/testdata"
)

func main() {
	lookup := map[string]*xmss.Params{
		"SHA2_10_256": xmss.SHA2_10_256,
		"SHA2_16_256": xmss.SHA2_16_256,
		"SHA2_20_256": xmss.SHA2_20_256,
	}
	msg := make([]byte, 32)
	rand.Read(msg)
	os.RemoveAll(testDataDir)
	os.MkdirAll(testDataDir, 0755)
	if err := ioutil.WriteFile(testDataDir+"/message_data", msg, 0644); err != nil {
		log.Fatal(err)
	}
	for k, v := range lookup {
		gen(k, v, msg)
	}
}

func gen(name string, params *xmss.Params, msg []byte) {
	log.Printf("generating %v keys\n", name)
	priv, pub := xmss.GenerateXMSSKeypair(params)
	fileName := testDataDir + "/" + name
	if err := ioutil.WriteFile(fileName+".pub", []byte(*pub), 0644); err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile(fileName+".key", []byte(*priv), 0644); err != nil {
		log.Fatal(err)
	}
	sig := *priv.Sign(params, msg)
	if err := ioutil.WriteFile(fileName+".sig", []byte(sig), 0644); err != nil {
		log.Fatal(err)
	}
}
