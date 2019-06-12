# attestation

A SafetyNet Attestation API response parser for golang.


## Install

```
go get github.com/okzk/attestation
```


## How to use

```go
package main

import (
	"fmt"
	"github.com/okzk/attestation"
)

func main() {
	jws := "....."
	claims, err := attestation.Parse(jws)
	if err != nil {
		panic(err)
	}
	fmt.Println(claims)
}
```

## License

MIT
