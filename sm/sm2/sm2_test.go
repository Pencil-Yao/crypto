// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sm2 implements china crypto standards.
package sm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sm/sm2"
	"crypto/sm/sm3"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"math/big"
	"testing"
)

func TestSignVerify(t *testing.T) {
	msg := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		panic("GenerateKey failed")
	}

	hfunc := sm3.New()
	hfunc.Write(msg)
	hash := hfunc.Sum(nil)

	r, s, err := Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}

	ret := Verify(&priv.PublicKey, hash, r, s)
	fmt.Println(ret)
}

func TestBase(t *testing.T) {
	msg := []byte{1, 2, 3, 4}
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		panic("GenerateKey failed")
	}
	fmt.Printf("D:%s\n", priv.D.Text(16))
	fmt.Printf("X:%s\n", priv.X.Text(16))
	fmt.Printf("Y:%s\n", priv.Y.Text(16))

	hfunc := sm3.New()
	hfunc.Write(msg)
	hash := hfunc.Sum(nil)
	fmt.Printf("hash:%02X\n", hash)
	var done = make(chan struct{})
	go func() {
		for i := 0; ; i += 1 {
			sig, err := priv.Sign(rand.Reader, hash, nil)
			if err != nil {
				panic(err)
			}
			if len(sig) == 73 {
				fmt.Println("found it")
				done <- struct{}{}
				break
			}
			if i%100 == 0 {
				break
			}
		}
	}()

	r, s, err := Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}

	fmt.Printf("R:%s\n", r.Text(16))
	fmt.Printf("S:%s\n", s.Text(16))

	ret := Verify(&priv.PublicKey, hash, r, s)
	fmt.Println(ret)
	<-done
}

func TestKeyGeneration(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}

	if !priv.PublicKey.Curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func BenchmarkSign(b *testing.B) {
	b.ResetTimer()
	origin := []byte("testing")
	hashed := sm3.SumSM3(origin)
	priv, _ := GenerateKey(rand.Reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Sign(rand.Reader, priv, hashed[:])
	}
}

func TestSignAndVerify(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)

	origin := []byte("testintestintestintestintestintestinggggggtesting")
	hash := sm3.New()
	hash.Write(origin)
	hashed := hash.Sum(nil)
	r, s, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf(" error signing: %s", err)
		return
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf(" Verify failed")
	}

	//hashed[0] ^= 0xff
	hashed[0] = 0x53
	for i := 0; i < len(hashed); i++ {
		hashed[i] = byte(i)
	}
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}

func TestKDF(t *testing.T) {
	x2, err := hex.DecodeString("64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	y2, err := hex.DecodeString("58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	expect, err := hex.DecodeString("006E30DAE231B071DFAD8AA379E90264491603")
	klen := 152
	actual := keyDerivation(append(x2, y2...), klen)
	assert.Equal(t, expect, actual)
}

func TestENC_GMT_EX1(t *testing.T) {
	p256Sm2ParamsTest := &elliptic.CurveParams{Name: "SM2-P-256-TEST"} // 注明为SM2
	//SM2椭	椭 圆 曲 线 公 钥 密 码 算 法 推 荐 曲 线 参 数
	p256Sm2ParamsTest.P, _ = new(big.Int).SetString("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16)
	p256Sm2ParamsTest.N, _ = new(big.Int).SetString("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16)
	p256Sm2ParamsTest.B, _ = new(big.Int).SetString("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16)
	p256Sm2ParamsTest.Gx, _ = new(big.Int).SetString("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16)
	p256Sm2ParamsTest.Gy, _ = new(big.Int).SetString("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16)
	p256Sm2ParamsTest.BitSize = 256

	p256sm2CurveTest := p256Curve{p256Sm2ParamsTest}

	generateRandK = func(rand io.Reader, c elliptic.Curve) (k *big.Int) {
		k, _ = new(big.Int).SetString("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F", 16)
		return k
	}
	expectA, _ := new(big.Int).SetString("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16)
	Gy2 := p256sm2CurveTest.Gy.Mul(p256sm2CurveTest.Gy, p256sm2CurveTest.Gy)
	gx := new(big.Int).SetBytes(p256sm2CurveTest.Gx.Bytes())
	Gx2 := gx.Mul(p256sm2CurveTest.Gx, p256sm2CurveTest.Gx)
	Gx3 := gx.Mul(Gx2, p256sm2CurveTest.Gx)
	A := Gy2.Sub(Gy2, Gx3)
	A = A.Sub(A, p256sm2CurveTest.B)
	A = A.Div(A, p256sm2CurveTest.Gx)
	assert.Equal(t, expectA.Bytes(), A.Bytes())

	expectX, _ := new(big.Int).SetString("435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A", 16)
	expectY, _ := new(big.Int).SetString("75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42", 16)
	priv := &PrivateKey{}
	priv.PublicKey.Curve = p256sm2CurveTest
	priv.D, _ = new(big.Int).SetString("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0", 16)
	priv.PublicKey.X, priv.PublicKey.Y = p256sm2CurveTest.ScalarBaseMult(priv.D.Bytes())
	assert.True(t, p256sm2CurveTest.IsOnCurve(expectX, expectY))

	//assert.Equal(t, expectX.Bytes(), priv.PublicKey.X.Bytes())
	//assert.Equal(t, expectY.Bytes(), priv.PublicKey.Y.Bytes())
}

func TestCryptoToolCompare(t *testing.T) {
	generateRandK = func(rand io.Reader, c elliptic.Curve) (k *big.Int) {
		k, _ = new(big.Int).SetString("88E0271D16363C00D6456E151C095BAD4B75968E708234A9762146711D327FF3", 16)
		return
	}
	priv := &PrivateKey{}
	priv.PublicKey.Curve = P256Sm2()
	priv.D, _ = new(big.Int).SetString("88E0271D16363C00D6456E151C095BAD4B75968E708234A9762146711D327FF3", 16)
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.ScalarBaseMult(priv.D.Bytes())

	msg, _ := hex.DecodeString("88E0271D16363C00D6456E151C095BAD4B75968E708234A9762146711D327FF3")
	Encrypt(rand.Reader, &priv.PublicKey, msg)
}

func TestEnc(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)
	var msg = "asdfasdf"

	enc, err := Encrypt(rand.Reader, &priv.PublicKey, []byte(msg))
	if err != nil {
		t.Fatalf("encrypt failed : %s", err.Error())
	}
	dec, err := Decrypt(enc, priv)
	if err != nil {
		t.Fatalf("dec failed : %s", err.Error())
	}

	if !bytes.Equal([]byte(msg), dec) {
		t.Error("enc-dec failed")
	}
}

func TestVerifyThird(t *testing.T)  {
	X, _ := new(big.Int).SetString("5b945fdaf1e6c5d331ea2794f21ec23fc73416d1d5529ed2d48b75137dd23fa4", 16)
	Y, _ := new(big.Int).SetString("cf0f4af64b56fc399115541d79fa19c1708e3d7e9a9d22a7dfe575339e3218f3", 16)
	pk := PublicKey{
		sm2.P256Sm2(),
		X,
		Y,
	}
	msg_str, _ := hex.DecodeString("3082020ea003020102021100eb32c264d4fd76adae85958e2a06cabd300a06082a811ccf550183753076310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f31193017060355040a13106f7267312e6578616d706c652e636f6d311f301d06035504031316746c7363612e6f7267312e6578616d706c652e636f6d301e170d3230303731353039333230305a170d3330303731333039333230305a305b310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630140603550407130d53616e204672616e636973636f311f301d0603550403131670656572302e6f7267312e6578616d706c652e636f6d3059301306072a8648ce3d020106082a811ccf5501822d03420004db169a4dfd46cd5b7670b45cd717af987620c032b0788ccabbb78d500ddee860c51f1b6a5c270b215624904f0cce14890d343446f5ca40040f08077594941668a38197308194300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000302b0603551d2304243022802062c312bc5eaf99e23770be51e3be0d834ec7111ff785b05400950bfab7df4e3c30280603551d110421301f821670656572302e6f7267312e6578616d706c652e636f6d82057065657230")
	sig, _ := hex.DecodeString("3046022100c29c6ac83b3b502e46a7fd82670981e2c31137d2631b35b34484254344379c2a022100cdcec14afe1dfe54fe1a37e2590e25fd39a8c7a0090cfeb43cb815544f17e31c")
	if pk.Verify([]byte(msg_str), sig) {
		println("right sig")
	} else {
		println("bad sig")
	}
}