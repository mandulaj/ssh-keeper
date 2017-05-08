package main

import (
	"fmt"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func main() {
	plaintext := []byte("Hello World, this is a very secret string...")
	plaintext2 := make([]byte, 0, len(plaintext))
	ciphertext := make([]byte, 0, len(plaintext))

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, gcm.NonceSize())
	_, err = rand.Read(iv)
	if err != nil {
		panic(err)
	}

	ciphertext = gcm.Seal(ciphertext, iv, plaintext, []byte{})

	fmt.Println(plaintext)
	fmt.Println(ciphertext)

	aesCipher, err = aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err = cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}

	//iv = make([]byte, gcm.NonceSize())
	//_, err = rand.Read(iv)
	if err != nil {
		panic(err)
	}

	plaintext2, err = gcm.Open(plaintext2, iv, ciphertext, []byte{})
	if err != nil {
		panic(err)
	}
	fmt.Println(plaintext2)

	//fmt.Println(key)
}
