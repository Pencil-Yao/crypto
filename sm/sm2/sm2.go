// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sm2 implements china crypto standards.
package sm2

import (
	"crypto"
	"crypto/elliptic"
	"crypto/sm/sm3"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type sm2Signature struct {
	R, S *big.Int
}

var generateRandK = _generateRandK

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sign(rand, priv, msg)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	var sm2Sign sm2Signature
	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return false
	}
	return Verify(pub, msg, sm2Sign.R, sm2Sign.S)
}

var one = new(big.Int).SetInt64(1)

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := P256Sm2()
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

var errZeroParam = errors.New("zero parameter")

func _generateRandK(rand io.Reader, c elliptic.Curve) (k *big.Int) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func getZById(pub *PublicKey, id []byte) []byte {
	var lena = uint16(len(id) * 8) //bit len of IDA
	var ENTLa = []byte{byte(lena >> 8), byte(lena)}
	var z = make([]byte, 0, 1024)

	z = append(z, ENTLa...)
	z = append(z, id...)
	z = append(z, SM2PARAM_A.Bytes()...)
	z = append(z, P256Sm2().Params().B.Bytes()...)
	z = append(z, P256Sm2().Params().Gx.Bytes()...)
	z = append(z, P256Sm2().Params().Gy.Bytes()...)
	z = append(z, pub.X.Bytes()...)
	z = append(z, pub.Y.Bytes()...)
	return sm3.SumSM3(z)
}

//Za = sm3(ENTL||IDa||a||b||Gx||Gy||Xa||Xy)
func getZ(pub *PublicKey) []byte {
	return getZById(pub, []byte("1234567812345678"))
}

func Sign(rand io.Reader, priv *PrivateKey, msg []byte) (r, s *big.Int, err error) {
	var one = new(big.Int).SetInt64(1)
	//if len(hash) < 32 {
	//	err = errors.New("The length of hash has short than what SM2 need.")
	//	return
	//}

	var m = make([]byte, 32+len(msg))
	copy(m, getZ(&priv.PublicKey))
	copy(m[32:], msg)

	e := new(big.Int).SetBytes(sm3.SumSM3(m))
	k := generateRandK(rand, priv.PublicKey.Curve)

	x1, _ := priv.PublicKey.Curve.ScalarBaseMult(k.Bytes())

	n := priv.PublicKey.Curve.Params().N

	r = new(big.Int).Add(e, x1)

	r.Mod(r, n)

	s1 := new(big.Int).Mul(r, priv.D)
	s1.Mod(s1, n)
	s1.Sub(k, s1)
	s1.Mod(s1, n)

	s2 := new(big.Int).Add(one, priv.D)
	s2.Mod(s2, n)
	s2.ModInverse(s2, n)
	s = new(big.Int).Mul(s1, s2)
	s.Mod(s, n)

	return
}

func VerifyById(pub *PublicKey, msg, id []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	n := pub.Curve.Params().N

	var m = make([]byte, 32+len(msg))
	copy(m, getZById(pub, id))
	copy(m[32:], msg)
	e := new(big.Int).SetBytes(sm3.SumSM3(m))

	t := new(big.Int).Add(r, s)
	x11, y11 := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x12, y12 := pub.Curve.ScalarBaseMult(s.Bytes())
	x1, _ := pub.Curve.Add(x11, y11, x12, y12)
	x := new(big.Int).Add(e, x1)
	x = x.Mod(x, n)

	return x.Cmp(r) == 0
}

func Verify(pub *PublicKey, msg []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	n := pub.Curve.Params().N

	var m = make([]byte, 32+len(msg))
	copy(m, getZ(pub))
	copy(m[32:], msg)
	e := new(big.Int).SetBytes(sm3.SumSM3(m))

	t := new(big.Int).Add(r, s)
	x11, y11 := pub.Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x12, y12 := pub.Curve.ScalarBaseMult(s.Bytes())
	x1, _ := pub.Curve.Add(x11, y11, x12, y12)
	x := new(big.Int).Add(e, x1)
	x = x.Mod(x, n)

	return x.Cmp(r) == 0
}

type zr struct {
	io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}
