package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/jaypipes/ghw"
	"golang.org/x/crypto/openpgp"
)

const (
	PUB_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF55opABEACYy4Fadl60FNJ+R86WGXwBiAOT/Jxelwv0Y9GRYbDFrQ7dP+V/
/VXS9Ul/gu/0sQpsQVyoL3I9MwdK5SUxSVs9En1gwEu600h3PPPj3Dp9rI2UUITO
fdvUuVRRuSXl+OmbrpRARTc/qW9O0rAHUhMjIEBpK8khxpcjpTf1Zz641B34VZMR
sUWttto4pprZkBqG5Adx1Kkg9yZeHGk6jCttEJr0VnNCdNt2ZWXU/XXEQ753aqYO
AsauVCDqOrq87IFt5pUH05x9pmuJlLsNnSkJCRqsRslLz5NQxRceJF9a5vZpPSNk
rcn8J8nMPAiNQ3VuxYGJb+lVsHpSFmi7hU138CX423JZgRP5te+7YtkBcVF8W5QG
jo++oXrjls/H8j5AfjGqF/qHg0J//JJ9JXWgXhq8I9+FAq1m46ri/NoLwut9MmJR
74POjF4hDDP53lJH31Q9mgeh9K3zZfRlLo/qjAbQNOlwfsLD8Fey+tO+Cbg4RL7H
Tm9mEKhCrYB0CZ5OsnwRAOfJB+ZCbluAPpmT3QfO/2aC/0R0d8rqs/unoZiZvTCl
u2nZafpPWwHuTcnd8lWw3VCvdTZWKePEK4a6jYlK2o48/3BawFsCBIe4GOM4P8fI
eX5PQJhBpfmTPLKWa8yFa+97vv1qEowNng95iuq/i+Vhn8rJAhqRvQIVkQARAQAB
tCJZYW5nIFNoZW4gPHNoZW55YW5nLmRhaUBnbWFpbC5jb20+iQJOBBMBCAA4FiEE
2qqjUEyIM5pCQnsK+lINw84uo6wFAl55opACGwMFCwkIBwIGFQoJCAsCBBYCAwEC
HgECF4AACgkQ+lINw84uo6zaKg//ZpOQDi+Xt5+GpSsuposKUf2EHnRQtMc/FPds
SajIJFqHvXfmyDh5DcG4FL+hbIBkVR+onHUQrtwRKMAoSQeRmiYGABmYt/l6zEDB
w4ELXCC4De+SF4IUYE9L0C4ztP+49Dr9kwjzeNkBPFxCuTBh4HlZgC+ZkV6y6ETy
2j/JtXhY3okaxsO//FKtkCGs9RlMRLOwBjkWGvUM8ljPcdlWXl+HoZS47fjD25ms
TspjgBhpb4wTRthpaiEgcKPLDS2Pbvo8gntgAg3IKWDTmHMfgehTFdSs8fH4A0rm
GPdX3hRKMZ4gAXdRkAaQcnDvUQ0Pa07VucXjX6q7ZqVhGYsFsfNRRumhQR/qM17X
aHmLtH8R2dvbIHOxzZkVRMldDOc17JJOuRy/piclZ3EhHjQmCrM8wO9UkrcUNFU6
7O4KKjYq1JUmTfVESuZWfcMxxNn8hiEOuHaCYDKPPBkTft7K0gPM6rZ8CHoBafHx
Jq7qFzaBCWW0G+06UZhmFlBgdtHHP3ixsqnK4qdsdovTLfByO/CsTjGj5rdYZF14
mUEuMhCBxbXbsMuSjQXB1sbfQomKxlzms8H4otan6I4l2kaobrTWw0ciTCeTQ1tH
izySPHw8saDQ3NeBxj/iGf4so2Q0BA2QMEp5sLN1XqiTzPEcj4SnWQ6ZYjVMy1bv
GT0QhwS5Ag0EXnmikAEQANvOKgHESASLu/oUXUTG46Z2ndcSeX4Q27hRwi5NHdOf
cO3pGLDJLHc+2CFoIPyz9w3NbJjnjjr3mlSiVrUbylja+aGt+zRV6qRl7a+z4J5+
wTMUuY92kTQH+czHp8aBKM/FmxxXRGHpQ8U8ROx+P9aOA6KFhTlyWRKZE2zXq9VV
btLWCFkUwa9kmnVlU57urDrANXD2+WQ4RGW8xO/Q1YSERpVqG57K1fsK6lj+qpLz
Mfc6lRqIhfcHMwOaj4YOyP+Ii6qUM3yccYUYwotDPD3zwF1OrjQymazYnM1O9WgK
Bk9LfIFyRPG4V1cNICRAWeuE6/Ggm8L5KZQ9bhMGW2SsT36wiW8iOT5K+VlKdWIW
E37be/wKMA0CrsW5ys88XR2vTi8R9nQZowB4chci/CmkXGPsqjRo/qI1eEO8yQ9i
Y9Q5nDtyMmdoBasqDji5pCazHrfI8I4zpECNoI4H9VAEl09Nwp6R/g6qxa7qgCwB
61f4j3IjRsxu5W8b2vLRlUGt/1mB1LgDRf2rMzulo5h+r8R9UbYZ5f+Nw/x1EeYL
K8Okc8UJMmvZZevnK1L1G4G81OuUi2FxiV7zh55nB2VOfk88U1hBgRlLxgwmrKRR
+eQNxMIsggMCS1p2hY0FbZp0hxnlcIdGTpJehDw3QgQehf7rhl51r/Xicux6cPyN
ABEBAAGJAjYEGAEIACAWIQTaqqNQTIgzmkJCewr6Ug3Dzi6jrAUCXnmikAIbDAAK
CRD6Ug3Dzi6jrJ5HD/48q3avboOgx4oAsRsmp5WeWhpIo+AiVLd/K2lYNlv9o6Yo
AB8Ry+EHVaP2ZywcjlMlNbUdEAmqDbxsMkF9J+4A/q8/gfNHwfXitvirHcAF0BxD
Fa0bCZnC9iA+/8zPGnyc0FJ2sGouDdlVtj/TtC0tAnOwXC9UlKGvscNhtHZv8G2W
oazy/67RvRfRgq9iQDvM4NRK7fV2aSVvxn0QaqcnmGQiCocjKCjqel6z7nIpBAR1
ds3al0Ski3pbGCFHBChWhhufHMgobNRy1UiMiTX1BylXrQHq++aRoCBk20b1R8HX
nkcv4n0TtdZaM+PR0fWcf6cDJB8LUa3+WStVrsguD/WyzmEdWkVZ/u8qZc+3Z/U6
r/w+qEKlyFWYi0I8F00RtiiaZEiP2cpjYB5zqPdQ3cLBypgo0xbyp/OyzAO8rz2K
mRR+l98hPgtnPuvxUgdSvN9xNy1KsltlAAicTrU+/2zCTgP3QCC6sNeq0LSQQAcG
mNj+I2wZK7uueoZ5FBBXUGr7aMCKQ3lLHYwHfTQtc9TQqnVezvxu1RYPjKt0oP2l
rjAfhfRR+Ex7ytnbgrQl6psj+N+bS0evp9kCXwHuDuUp/KKsnuzAxa4pQLNLfJIl
qnQBbihxbcTeMn5LIH3Qt5a4nZnFIKiwYezyYM4KE3HJ/a9sNsJg+1XtNA/Bfw==
=vpLJ
-----END PGP PUBLIC KEY BLOCK-----`
)

type SysInfo struct {
	BOARD   string
	PRODUCT string
}

func main() {
	baseboard, err := ghw.Baseboard()
	if err != nil {
		fmt.Printf("Error getting baseboard info: %v", err)
	}

	product, err := ghw.Product()
	if err != nil {
		fmt.Printf("Error getting product info: %v", err)
	}

	sysInfo := SysInfo{
		BOARD:   baseboard.SerialNumber,
		PRODUCT: product.UUID,
	}

	str, _ := json.Marshal(sysInfo)

	encTest(str)
}

func encTest(secret []byte) {

	pubKeyBuf := bytes.NewBuffer([]byte(PUB_KEY))
	entityList, err := openpgp.ReadArmoredKeyRing(pubKeyBuf)
	if err != nil {
		panic(err)
	}

	// encrypt string
	buf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		panic(err)
	}
	_, err = w.Write([]byte(secret))
	if err != nil {
		panic(err)
	}
	err = w.Close()
	if err != nil {
		panic(err)
	}

	// Encode to base64
	bytes, err := ioutil.ReadAll(buf)
	if err != nil {
		panic(err)
	}
	encStr := base64.StdEncoding.EncodeToString(bytes)

	// Output encrypted/encoded string
	log.Println("Encrypted Secret:", encStr)

	err = ioutil.WriteFile("dongle", []byte(encStr), 0644)
	if err != nil {
		panic(err)
	}
}
