package xeddsa

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"

	"github.com/cloudflare/circl/ecc/goldilocks"
)

type cachedKeys struct {
	A []byte
}

type Xeddsa struct {
	Public  []byte
	private []byte
	cache   cachedKeys
}

func New(private []byte) Xeddsa {
	a, A := calculate_key_pair448(private)
	return Xeddsa{
		Public:  A,
		private: a,
	}
}

var _PREFIX = [57]byte{
	0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff}

var c = goldilocks.Curve{}

func calculate_key_pair448(private []byte) ([]byte, []byte) {
	a := goldilocks.Scalar{}
	copy(a[:], private[:])
	a[0] &= 252
	a[55] |= 128
	A := make([]byte, goldilocks.ScalarSize+1)
	c.ScalarBaseMult(&a).ToBytes(A)
	if A[56] == 128 {
		a.Neg()
	}
	return a[:], A
}

func (x *Xeddsa) unsign() {
	if x.cache.A != nil {
		return
	}
	x.cache.A = make([]byte, 57)
	copy(x.cache.A, x.Public)
	if x.Public[56] == 128 {
		x.cache.A[56] = 0
	}
}

func (x Xeddsa) Sign(message []byte) []byte {
	x.unsign()
	Z := make([]byte, 64)
	R := make([]byte, 57)
	r := goldilocks.Scalar{}
	h := goldilocks.Scalar{}
	rand.Read(Z[:])
	_r := hash(append(x.private, append(message, Z...)...))
	r.FromBytes(_r[:])
	c.ScalarBaseMult(&r).ToBytes(R)
	_h := hash(append(R, append(x.cache.A, message...)...))
	h.FromBytes(_h[:])
	h.Mul((*goldilocks.Scalar)(h[:]), (*goldilocks.Scalar)(x.private))
	r.Add(&r, &h)
	r.Red()
	return append(R, r[:]...)
}

func Verify(_key []byte, message []byte, sig []byte) bool {
	key := make([]byte, 57)
	copy(key, _key[:56])
	key[56] = 0
	A, err := goldilocks.FromBytes(key)
	if err != nil {
		return false
	}
	h := goldilocks.Scalar{}
	R := make([]byte, 57)
	s := make([]byte, 56)
	R_check := make([]byte, 57)
	copy(R, sig[0:57])
	copy(s, sig[57:])
	_h := hash(append(R, append(key, message...)...))
	h.FromBytes(_h[:])
	h.Neg()
	c.CombinedMult((*goldilocks.Scalar)(s), (*goldilocks.Scalar)(h[:]), A).ToBytes(R_check)
	return bytes.Equal(R, R_check)
}

func hash(message []byte) [64]byte {
	return sha512.Sum512(append(_PREFIX[:], message...))
}
