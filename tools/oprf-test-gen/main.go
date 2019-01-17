package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"strings"

	ristretto "github.com/bwesterb/go-ristretto"
	log "github.com/sirupsen/logrus"
)

func DeriveFromUniformBytes(in []byte) *ristretto.Point {
	var p ristretto.Point
	var p2 ristretto.Point
	var buf [32]byte
	copy(buf[:], in[:32])
	p.SetElligator(&buf)
	copy(buf[:], in[32:])
	p2.SetElligator(&buf)
	p.Add(&p, &p2)
	return &p
}

type Vector struct {
	elements []string
}

func (v *Vector) Add(key string, value string) {
	log.Debug(key + ": " + value)
	v.elements = append(v.elements, value)
}

func (v Vector) String() string {
	return "(\"" + strings.Join(v.elements, "\", \"") + "\"),"
}

var verbose = flag.Bool("v", false, "verbose output")
var num = flag.Int("n", 10, "num vectors")

func main() {
	flag.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	for i := 0; i < *num; i++ {
		var k ristretto.Scalar
		var Y ristretto.Point

		vector := Vector{}
		k.Rand() // generate a new secret key
		Y.ScalarMultBase(&k)

		vector.Add("k", base64.StdEncoding.EncodeToString(k.Bytes()))

		Y.ScalarMultBase(&k) // compute public key
		vector.Add("Y", base64.StdEncoding.EncodeToString(Y.Bytes()))

		seed := make([]byte, 64)
		_, err := rand.Read(seed)
		if err != nil {
			log.Fatal(err)
		}

		vector.Add("seed", base64.StdEncoding.EncodeToString(seed))

		var T ristretto.Point
		T.DeriveDalek(seed)

		var P ristretto.Point
		var r ristretto.Scalar

		r.Rand()

		vector.Add("r", base64.StdEncoding.EncodeToString(r.Bytes()))

		P.ScalarMult(&T, &r)

		vector.Add("P", base64.StdEncoding.EncodeToString(P.Bytes()))

		var Q ristretto.Point
		Q.ScalarMult(&P, &k)

		vector.Add("Q", base64.StdEncoding.EncodeToString(Q.Bytes()))

		var r_inv ristretto.Scalar
		r_inv.Inverse(&r)

		var W ristretto.Point
		W.ScalarMult(&Q, &r_inv)

		vector.Add("W", base64.StdEncoding.EncodeToString(W.Bytes()))

		fmt.Println(vector)
	}
}
