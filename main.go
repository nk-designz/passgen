package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"time"

	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

func randomString(len int) string {
	rand.Seed(time.Now().Unix())
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(65 + rand.Intn(25)) //A=65 and Z = 65+25
	}
	return string(bytes)
}

func main() {
	var value struct {
		Value string `json:"value"`
		Salt  string `json:"salt"`
	}

	password := flag.String("pass", "start-123", "A password")
	salt := flag.String("salt", "", "A salt for the password if empty it's random")
	saltiness := flag.Int("saltiness", 16, "The salt length")
	iterations := flag.Int("iter", 27500, "The iterations for the hash")
	length := flag.Int("dkLen", 64, "The length for the password")

	flag.Parse()

	if *salt == "" {
		*salt = base64.StdEncoding.EncodeToString(
			[]byte(
				randomString((*saltiness))))
	}

	value.Value = base64.StdEncoding.EncodeToString(
		pbkdf2.Key(
			[]byte(*password),
			[]byte(*salt),
			*iterations,
			*length,
			sha256.New))
	value.Salt = *salt
	hash, err := json.Marshal(value)
	if err != nil {
		panic(
			fmt.Sprintf("Could not convert to json: %x", err))
	}
	fmt.Printf("%s", hash)
}
