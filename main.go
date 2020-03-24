package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "golang.org/x/crypto/ripemd160"

	"compress/gzip"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	// Goencrypt app
	app           = kingpin.New("goencrypt", "A command line tool for encrypting files")
	bits          = app.Flag("bits", "Bits for keys").Default("4096").Int()
	privateKey    = app.Flag("private", "Private key").String()
	publicKey     = app.Flag("public", "Public key").String()
	signatureFile = app.Flag("sig", "Signature File").String()

	// Generates new public and private keys
	keyGenCmd       = app.Command("keygen", "Generates a new public/private key pair")
	keyOutputPrefix = keyGenCmd.Arg("prefix", "Prefix of key files").Required().String()
	keyOutputDir    = keyGenCmd.Flag("d", "Output directory of key files").Default(".").String()

	// Encrypts a file with a public key
	encryptionCmd = app.Command("encrypt", "Encrypt from stdin")

	// Signs a file with a private key
	signCmd = app.Command("sign", "Sign stdin")

	// Verifies a file was signed with the public key
	verifyCmd = app.Command("verify", "Verify a signature of stdin")

	// Decrypts a file with a private key
	decryptionCmd = app.Command("decrypt", "Decrypt from stdin")

	SECRET = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQEmBF54rVIBCACe2ke4wFIP0E5wNMH1smrl11YUDWf6krklrBNcm4ArlRJ5BsG8
BDNgstyDDL+VvWpyCH0udDF9yBy3hWM16K6YrrepF29+H5jiPoNmDXmKa2d0vyYc
1zZDWt/xUpvKmpLhejH5QtnHLbut3CQq5ByleaPtAxtwCSGcPiVbrv5s8ZO17Lmv
+LqKlV7ICpJymp66cn6P0Cgk/83FUhiM13BpJreKCNgKcboC42DwYzWF6Ol+Uxst
JJ5Ty37j3U5AmDPG/Nkx3njGXcUIaMM+ZXDdXfwGabEQdDi6ZNqagWMkcV7GGSwL
WYN66lJywzYxldJdlykMk9neR8CJBfOzVC5fABEBAAH/AGUAR05VAhDSdgABJAEC
AQAGB4QhdgAAtC1TaGVuIFlhbmcgKGpvaW51cykgPHNoZW55YW5nQHRoaW5rb250
cm9sLmNvbT6JASIEEwEIABYFAl54rVIJEBdR2boAGPcCAhsDAhkBAACTqAf/cTcU
0lNxdsphxpCeBWWfaNCfU+gdxrjCPwf9JQdnbaL0henufCN2hyzaFwJpzUlvSNqy
ypyaJNw482eRGykfAr4dK21yjF+Z9+ZFkDAzLh1E0P4+5UeGpwsP+LW9I1t6C+Y9
AO/EQnWlFByHqONf9QD0TASsOVhkPleuCi/1WZupgXqNmRS8oNoePARayqHd8063
IENagn3lG6CgPqbot0yt4W2gdP+J00Fwy4ckuxTPaxqZ604178Cw22duq+obWrgd
QajcbAbHrEsmmrWkN3liwaLEruTnbGJ8uEZIuvRqd3uxZbClNUUD9sxOnAHfxqEL
p/5989hJbbRgrdCP5J0BJgReeK1SAQgAxiRjcd1BnG9fnjPCLuizzwLE4zA/haRd
0VIJl+Vo8C5bmtW+O7aeBP0nQI6flEYbzP04R7Q1hZDfqeUJmqimYXJv5iRE5+aq
0PTSY8DdF/cMWxAq2V4Q6wUzg0whRvqkR6e4CPr9h4h7CGnxlke5Wd54kKK8Fnfl
lbcotVsmAFkH/R4oTnKEKjmdFLVoYYSJR17keltdaY7mCMtv32dHuczfbvWmqbiW
NCePSeKuGhSVIrs4ongwtNICAgs0Pyz81/x/eyHq9oHmjp8pTn9Y4aST8dCPWSxB
kdQ/uORWzY/FwfmG8Y1vb56llkM2XlYTCgenbhM8oxby3h24cV/H4QARAQAB/wBl
AEdOVQIQ0nYAASQBAgEABgeEIXYAAIkBHwQYAQgAEwUCXnitUgkQF1HZugAY9wIC
GwwAANFLB/9bElbBMzqxS1ldR4fcZbfaZdARMjjgusBhonGR6goNtX2FHXo2Fvq7
xBoNLOzW6om2ecWHJ7pbNOSPGuNXVz9knbCg81Nf6T2PZSsZkRKuB7d0IOMqyWdh
u1ew7ktfteG04YZi2jzILhbH/MdcRfpvB94gI0smGx8640FCUE5AFLb6BIyBZY8X
2KxABrporFeXZTBV3zep8eXi5I6bYWLiXZHIk73TLVwcC9dJtKfBuu4pA6f6r6nI
/gTHn/EhBi60z6/HoU7H5TOsT+d5v1KnHyKhMk41ufnfSwYC9erCEeWBzz3vJRs3
6ujUuTIUUTrnwiQc5uPX2dm5AIpLAF1l
=6oAH
-----END PGP PRIVATE KEY BLOCK-----`

	PUB_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xsBNBF54rVIBCACe2ke4wFIP0E5wNMH1smrl11YUDWf6krklrBNcm4ArlRJ5BsG8
BDNgstyDDL+VvWpyCH0udDF9yBy3hWM16K6YrrepF29+H5jiPoNmDXmKa2d0vyYc
1zZDWt/xUpvKmpLhejH5QtnHLbut3CQq5ByleaPtAxtwCSGcPiVbrv5s8ZO17Lmv
+LqKlV7ICpJymp66cn6P0Cgk/83FUhiM13BpJreKCNgKcboC42DwYzWF6Ol+Uxst
JJ5Ty37j3U5AmDPG/Nkx3njGXcUIaMM+ZXDdXfwGabEQdDi6ZNqagWMkcV7GGSwL
WYN66lJywzYxldJdlykMk9neR8CJBfOzVC5fABEBAAHNLVNoZW4gWWFuZyAoam9p
bnVzKSA8c2hlbnlhbmdAdGhpbmtvbnRyb2wuY29tPsLAYgQTAQgAFgUCXnitUgkQ
F1HZugAY9wICGwMCGQEAAJOoCABxNxTSU3F2ymHGkJ4FZZ9o0J9T6B3GuMI/B/0l
B2dtovSF6e58I3aHLNoXAmnNSW9I2rLKnJok3DjzZ5EbKR8Cvh0rbXKMX5n35kWQ
MDMuHUTQ/j7lR4anCw/4tb0jW3oL5j0A78RCdaUUHIeo41/1APRMBKw5WGQ+V64K
L/VZm6mBeo2ZFLyg2h48BFrKod3zTrcgQ1qCfeUboKA+pui3TK3hbaB0/4nTQXDL
hyS7FM9rGpnrTjXvwLDbZ26r6htauB1BqNxsBsesSyaataQ3eWLBosSu5OdsYny4
Rki69Gp3e7FlsKU1RQP2zE6cAd/GoQun/n3z2ElttGCt0I/kzsBNBF54rVIBCADG
JGNx3UGcb1+eM8Iu6LPPAsTjMD+FpF3RUgmX5WjwLlua1b47tp4E/SdAjp+URhvM
/ThHtDWFkN+p5QmaqKZhcm/mJETn5qrQ9NJjwN0X9wxbECrZXhDrBTODTCFG+qRH
p7gI+v2HiHsIafGWR7lZ3niQorwWd+WVtyi1WyYAWQf9HihOcoQqOZ0UtWhhhIlH
XuR6W11pjuYIy2/fZ0e5zN9u9aapuJY0J49J4q4aFJUiuziieDC00gICCzQ/LPzX
/H97Ier2geaOnylOf1jhpJPx0I9ZLEGR1D+45FbNj8XB+YbxjW9vnqWWQzZeVhMK
B6duEzyjFvLeHbhxX8fhABEBAAHCwF8EGAEIABMFAl54rVIJEBdR2boAGPcCAhsM
AADRSwgAWxJWwTM6sUtZXUeH3GW32mXQETI44LrAYaJxkeoKDbV9hR16Nhb6u8Qa
DSzs1uqJtnnFhye6WzTkjxrjV1c/ZJ2woPNTX+k9j2UrGZESrge3dCDjKslnYbtX
sO5LX7XhtOGGYto8yC4Wx/zHXEX6bwfeICNLJhsfOuNBQlBOQBS2+gSMgWWPF9is
QAa6aKxXl2UwVd83qfHl4uSOm2Fi4l2RyJO90y1cHAvXSbSnwbruKQOn+q+pyP4E
x5/xIQYutM+vx6FOx+UzrE/neb9Spx8ioTJONbn530sGAvXqwhHlgc897yUbN+ro
1LkyFFE658IkHObj19nZuQCKSwBdZQ==
=nRHs
-----END PGP PUBLIC KEY BLOCK-----`
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	// generate keys
	case keyGenCmd.FullCommand():
		generateKeys()
	// case createEntityCmd.FullCommand():
	// 	newEntity()
	case encryptionCmd.FullCommand():
		encryptFile()
	case signCmd.FullCommand():
		signFile()
	case verifyCmd.FullCommand():
		verifyFile()
	case decryptionCmd.FullCommand():
		decryptFile()
	default:
		kingpin.FatalUsage("Unknown command")
	}
}

func encodePrivateKey(out io.Writer, key *rsa.PrivateKey) {
	w, err := armor.Encode(out, openpgp.PrivateKeyType, make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)

	pgpKey := packet.NewRSAPrivateKey(time.Now(), key)
	kingpin.FatalIfError(pgpKey.Serialize(w), "Error serializing private key: %s", err)
	kingpin.FatalIfError(w.Close(), "Error serializing private key: %s", err)
}

func decodePrivateKey(filename string) *packet.PrivateKey {

	// open ascii armored private key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening private key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PrivateKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid private key"), "Error parsing private key")
	}
	return key
}

func encodePublicKey(out io.Writer, key *rsa.PrivateKey) {
	w, err := armor.Encode(out, openpgp.PublicKeyType, make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)

	pgpKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
	kingpin.FatalIfError(pgpKey.Serialize(w), "Error serializing public key: %s", err)
	kingpin.FatalIfError(w.Close(), "Error serializing public key: %s", err)
}

func decodePublicKey(filename string) *packet.PublicKey {

	// open ascii armored public key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.PublicKeyType {
		kingpin.FatalIfError(errors.New("Invalid private key file"), "Error decoding private key")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading private key")

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid public key"), "Error parsing public key")
	}
	return key
}

func decodeSignature(filename string) *packet.Signature {

	// open ascii armored public key
	in, err := os.Open(filename)
	kingpin.FatalIfError(err, "Error opening public key: %s", err)
	defer in.Close()

	block, err := armor.Decode(in)
	kingpin.FatalIfError(err, "Error decoding OpenPGP Armor: %s", err)

	if block.Type != openpgp.SignatureType {
		kingpin.FatalIfError(errors.New("Invalid signature file"), "Error decoding signature")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	kingpin.FatalIfError(err, "Error reading signature")

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		kingpin.FatalIfError(errors.New("Invalid signature"), "Error parsing signature")
	}
	return sig
}

func encryptFile() {
	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	to := createEntityFromKeys(pubKey, privKey)

	w, err := armor.Encode(os.Stdout, "Message", make(map[string]string))
	kingpin.FatalIfError(err, "Error creating OpenPGP Armor: %s", err)
	defer w.Close()

	plain, err := openpgp.Encrypt(w, []*openpgp.Entity{to}, nil, nil, nil)
	kingpin.FatalIfError(err, "Error creating entity for encryption")
	defer plain.Close()

	compressed, err := gzip.NewWriterLevel(plain, gzip.BestCompression)
	kingpin.FatalIfError(err, "Invalid compression level")

	n, err := io.Copy(compressed, os.Stdin)
	kingpin.FatalIfError(err, "Error writing encrypted file")
	kingpin.Errorf("Encrypted %d bytes", n)

	compressed.Close()
}

func decryptFile2() {
	// var entity *openpgp.Entity
	var entityList openpgp.EntityList
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer([]byte(SECRET)))
	if err != nil {
		log.Println(err)
	}

	block, err := armor.Decode(os.Stdin)
	kingpin.FatalIfError(err, "Error reading OpenPGP Armor: %s", err)

	if block.Type != "Message" {
		kingpin.FatalIfError(err, "Invalid message type")
	}
	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	kingpin.FatalIfError(err, "Error reading message")

	compressed, err := gzip.NewReader(md.UnverifiedBody)
	kingpin.FatalIfError(err, "Invalid compression level")
	defer compressed.Close()

	n, err := io.Copy(os.Stdout, compressed)
	kingpin.FatalIfError(err, "Error reading encrypted file")
	kingpin.Errorf("Decrypted %d bytes", n)
}

func decryptFile() {
	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	entity := createEntityFromKeys(pubKey, privKey)

	block, err := armor.Decode(os.Stdin)
	kingpin.FatalIfError(err, "Error reading OpenPGP Armor: %s", err)

	if block.Type != "Message" {
		kingpin.FatalIfError(err, "Invalid message type")
	}

	var entityList openpgp.EntityList
	entityList = append(entityList, entity)

	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	kingpin.FatalIfError(err, "Error reading message")

	compressed, err := gzip.NewReader(md.UnverifiedBody)
	kingpin.FatalIfError(err, "Invalid compression level")
	defer compressed.Close()

	n, err := io.Copy(os.Stdout, compressed)
	kingpin.FatalIfError(err, "Error reading encrypted file")
	kingpin.Errorf("Decrypted %d bytes", n)
}

func signFile() {
	pubKey := decodePublicKey(*publicKey)
	privKey := decodePrivateKey(*privateKey)

	signer := createEntityFromKeys(pubKey, privKey)

	err := openpgp.ArmoredDetachSign(os.Stdout, signer, os.Stdin, nil)
	kingpin.FatalIfError(err, "Error signing input")
}

func verifyFile() {
	pubKey := decodePublicKey(*publicKey)
	sig := decodeSignature(*signatureFile)

	hash := sig.Hash.New()
	io.Copy(hash, os.Stdin)

	err := pubKey.VerifySignature(hash, sig)
	kingpin.FatalIfError(err, "Error signing input")
	kingpin.Errorf("Verified signature")
}

func createEntityFromKeys(pubKey *packet.PublicKey, privKey *packet.PrivateKey) *openpgp.Entity {
	config := packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		CompressionConfig: &packet.CompressionConfig{
			Level: 9,
		},
		RSABits: *bits,
	}
	currentTime := config.Now()
	uid := packet.NewUserId("", "", "")

	e := openpgp.Entity{
		PrimaryKey: pubKey,
		PrivateKey: privKey,
		Identities: make(map[string]*openpgp.Identity),
	}
	isPrimaryId := false

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:   uid.Name,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   packet.PubKeyAlgoRSA,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	keyLifetimeSecs := uint32(86400 * 365)

	e.Subkeys = make([]openpgp.Subkey, 1)
	e.Subkeys[0] = openpgp.Subkey{
		PublicKey:  pubKey,
		PrivateKey: privKey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                packet.PubKeyAlgoRSA,
			Hash:                      config.Hash(),
			PreferredHash:             []uint8{8}, // SHA-256
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
			KeyLifetimeSecs:           &keyLifetimeSecs,
		},
	}
	return &e
}

func generateKeys() {
	var entity *openpgp.Entity
	entity, err := openpgp.NewEntity("Shen Yang", "joinus", "shenyang@thinkontrol.com", nil)
	if err != nil {
		log.Fatalln(err)
		return
	}

	for _, id := range entity.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, entity.PrimaryKey, entity.PrivateKey, nil)
		if err != nil {
			log.Fatalln(err)
			return
		}
	}

	// key, err := rsa.GenerateKey(rand.Reader, *bits)
	// kingpin.FatalIfError(err, "Error generating RSA key: %s", err)

	priv, err := os.Create(filepath.Join(*keyOutputDir, *keyOutputPrefix+".privkey"))
	kingpin.FatalIfError(err, "Error writing private key to file: %s", err)
	defer priv.Close()

	pub, err := os.Create(filepath.Join(*keyOutputDir, *keyOutputPrefix+".pubkey"))
	kingpin.FatalIfError(err, "Error writing public key to file: %s", err)
	defer pub.Close()

	// encodePrivateKey(priv, key)
	// encodePublicKey(pub, key)

	wpub, err := armor.Encode(pub, openpgp.PublicKeyType, nil)
	if err != nil {
		log.Fatalln(err)
		return
	}
	defer wpub.Close()

	entity.Serialize(wpub)

	wpriv, err := armor.Encode(priv, openpgp.PrivateKeyType, nil)
	if err != nil {
		log.Fatalln(err)
		return
	}
	defer wpriv.Close()

	entity.SerializePrivate(wpriv, nil)
}
