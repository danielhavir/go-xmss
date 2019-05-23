![Dependency Status](https://danielhavir.github.io/badges/04f9fc479ab2f30ebef5ee393801dd82/dependencies_none.svg) [![Build Status](https://travis-ci.org/danielhavir/go-xmss.svg?branch=master)](https://travis-ci.org/danielhavir/go-xmss) [![Go Report Card](https://goreportcard.com/badge/github.com/danielhavir/go-xmss)](https://goreportcard.com/report/github.com/danielhavir/go-xmss)

# XMSS: eXtended Merkle Signature Scheme

This project implements [RFC8391](https://tools.ietf.org/html/rfc8391), the eXtended Merkle Signature Scheme (XMSS), a hash-based digital signature system that can so far withstand known attacks using quantum computers. This repostiory contains code implementing the **single-tree** scheme, namely the following parameter sets (see [section 5.3.](https://tools.ietf.org/html/rfc8391#section-5.3) for reference):

| Name              | Functions |  n |  w | len |  h |
|-------------------|-----------|----|----|-----|----|
| SHA2_10_256       | SHA2-256  | 32 | 16 |  67 | 10 |
| SHA2_16_256       | SHA2-256  | 32 | 16 |  67 | 16 |
| SHA2_20_256       | SHA2-256  | 32 | 16 |  67 | 20 |

This code has no dependencies and is compatible with the official C implementation assuming the appropriate settings (see above) are presumed.

### Install
* Run `go get https://github.com/danielhavir/go-xmss`

## Example
```go
package main

import (
    "fmt"
    "github.com/danielhavir/go-xmss"
)

func main() {
    params := xmss.SHA2_16_256
    
    prv, pub := xmss.GenerateXMSSKeypar(params)

    msg := ...

    sig := prv.Sign(params, msg)

    m := make([]byte, params.SignBytes()+len(msg))

    if xmss.Verify(params, m, *sig, *pub) {
        fmt.Println("Signature matches.")
    } else {
        fmt.Println("Verification does not match.")
    }
}

```

## References
* XMSS: eXtended Merkle Signature Scheme [RFC8391](https://tools.ietf.org/html/rfc8391)
* [Official reference C implementation](https://github.com/joostrijneveld/xmss-reference)
