# XMSS: eXtended Merkle Signature Scheme

### XMSS Parameters
This project implements a single scenario with the following parameters (see section 5.3. for reference):
* Hash function: SHA-256
* n: 32
* w: 16
* h: 16
* len: 67
* Full height: 16
* d: 1
* index bytes: 4

### Tests
* WOTS+ - ✅
* XMSS - ✅

## Example
```go
package main

import (
    "fmt"
    "github.com/danielhavir/go-xmss"
)

func main() {
    prv, pub := xmss.GenerateXMSSKeypar()

    msg := ...

    sig := (*prv).Sign(msg)

    m := make([]byte, int(xmss.SignBytes)+len(msg))

    if xmss.Verify(m, *sig, *pub) {
        fmt.Println("Signature matches.")
    } else {
        fmt.Println("Verification does not match.")
    }
}

```

## References
* XMSS: eXtended Merkle Signature Scheme [RFC8391](https://tools.ietf.org/html/rfc8391)
* [Official refence C implementation](https://github.com/joostrijneveld/xmss-reference)
