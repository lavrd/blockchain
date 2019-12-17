package main

import (
	"crypto/sha256"
	"fmt"
)

func calcHash(data string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}
