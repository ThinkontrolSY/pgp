package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/openpgp"
)

// create gpg keys with
// $ gpg --gen-key
// ensure you correct paths and passphrase

const mySecretString = "this is so very secret!"
const prefix, passphrase = "C:\\Users\\sheny\\Workspace\\gpg\\", "joinus@2020"
const secretKeyring = prefix + "private-key.gpg"
const publicKeyring = prefix + "public-key.gpg"

func decTest(encString []byte) (string, error) {

	log.Println("Secret Keyring:", secretKeyring)
	log.Println("Passphrase:", passphrase)

	// init some vars
	var entity *openpgp.Entity
	var entityList openpgp.EntityList

	// Open the private key file
	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		log.Fatalln(err)
		return "", err
	}
	defer keyringFileBuffer.Close()
	entityList, err = openpgp.ReadArmoredKeyRing(keyringFileBuffer)
	if err != nil {
		log.Fatalln(err)
		return "", err
	}
	entity = entityList[0]

	// Get the passphrase and read the private key.
	// Have not touched the encrypted string yet
	passphraseByte := []byte(passphrase)
	log.Println("Decrypting private key using passphrase")
	e := entity.PrivateKey.Decrypt(passphraseByte)
	log.Println(e)
	for _, subkey := range entity.Subkeys {
		tt := subkey.PrivateKey.Decrypt(passphraseByte)
		log.Println(tt)
	}
	log.Println("Finished decrypting private key using passphrase")

	// Decode the base64 string
	// log.Println(encString)
	// dec, err := base64.StdEncoding.DecodeString(encString)
	// log.Println(dec)
	// log.Fatalln(err)
	// if err != nil {
	// 	return "", err
	// }

	// Decrypt it with the contents of the private key
	md, err := openpgp.ReadMessage(bytes.NewBuffer(encString), entityList, nil, nil)
	if err != nil {
		log.Fatalln(err)
		return "", err
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		log.Fatalln(err)
		return "", err
	}
	decStr := string(bytes)

	return decStr, nil
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	file, _ := ioutil.ReadFile(prefix + "demo.en.txt")

	decStr, err := decTest(file)
	if err != nil {
		log.Fatal(err)
	}
	// should be done
	log.Println("Decrypted Secret:", decStr)
}
