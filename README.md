# PBKDF2

[![Go Reference](https://pkg.go.dev/badge/github.com/i9si-sistemas/pbkdf2.svg)](https://pkg.go.dev/github.com/i9si-sistemas/pbkdf2)
[![Go Report Card](https://goreportcard.com/badge/github.com/i9si-sistemas/pbkdf2)](https://goreportcard.com/report/github.com/i9si-sistemas/pbkdf2)
[![Github Actions](https://github.com/i9si-sistemas/pbkdf2/actions/workflows/test.yml/badge.svg)](https://github.com/i9si-sistemas/pbkdf2/actions/workflows/test.yml)


- pbkdf2 provides password-based key derivation based on
[RFC 8018](https://tools.ietf.org/html/rfc8018).

## Usage

```go
package main

import (
    "crypto/sha256"

    "github.com/i9si-sistemas/pbkdf2"
)

func main() {
    keyGenerator := pbkdf2.New(sha256.New, 32, 10000)
    pswd := getPassword()
    salt, err := keyGenerator.GenerateSalt()
    if err != nil {
        panic(err)
    }
    derivedKey, err := keyGenerator.GenerateKey(pswd, salt...)
    if err != nil {
        panic(err)
    }
    println(derivedKey)
}

func getPassword() string {
    return "password"
}
```

## License

-  Licensed under the [MIT License](LICENSE).
