package x3dh

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	crypto "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"gcrypt/xeddsa"
	"math/rand"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/ecc/goldilocks"
	"github.com/cloudflare/circl/math/fp448"
	"golang.org/x/crypto/hkdf"
)

type Identity [57]byte
type SignKey [56]byte
type Opt [56]byte

var _F []byte = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF,
}

var _SALT []byte = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var info = []byte("x448;sha-256;x3dh")

type X3dh struct {
	eddsa   xeddsa.Xeddsa
	private []byte
	Spk     SignKey
	Otps    []Opt
	keys    keys
}

type keys struct {
	signedKey map[string][]byte
	otp       map[string][]byte
}

type PublicKeys struct {
	Identity       Identity
	SignedPreKey   SignKey
	Signature      []byte
	OneTimePreKeys Opt
}

type InitialMessage struct {
	Identity string
	Epk      string
	Prekeys  [2]string
	Text     string
	N        uint32
	Path     string //this is not part of the x3dh protocol but used for the art algorithm
}

func appendDH(dh1, dh2, dh3, dh4 []byte) []byte {
	var dhs [][]byte
	var result []byte
	if dh4 != nil {
		dhs = [][]byte{dh1, dh2, dh3, dh4}
		result = make([]byte, 56*4)
	} else {
		dhs = [][]byte{dh1, dh2, dh3}
		result = make([]byte, 56*3)
	}
	for i, arr := range dhs {
		for j := range arr {
			result[56*i+j] = arr[j]
		}
	}
	return result
}

func encrypt(key, associatedData, data []byte, n uint32) []byte {
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead.Seal(nil, nonce(n, key), data, associatedData)
}

func decrypted(key, associatedData, data []byte, n uint32) bool {
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	_, err := aead.Open(nil, nonce(n, key), data, associatedData)
	return err == nil
}

func generate_key_pair() (private, public []byte) {
	private = make([]byte, 56)
	crypto.Read(private[:])
	public = make([]byte, 56)
	x448.KeyGen((*x448.Key)(public), (*x448.Key)(private))
	return
}

func convert_goldilock(point Identity) ([]byte, error) {
	u := fp448.Elt{}
	p, err := goldilocks.FromBytes(point[:])
	if err != nil {
		return nil, err
	}
	x, y := p.ToAffine()
	fp448.Mul(&x, &x, &x)
	fp448.Mul(&y, &y, &y)
	fp448.Inv(&x, &x)
	fp448.Mul(&u, &y, &x)
	return u[:], nil
}

func _KDF(km []byte) (k []byte) {
	k = make([]byte, 32)
	hkdf.New(sha256.New, append(km, _F...), _SALT, info).Read(k)
	return
}

func nonce(c uint32, k []byte) []byte {
	hash := hmac.New(md5.New, k)
	hash.Write(binary.BigEndian.AppendUint32(nil, c))
	return hash.Sum(nil)[:12]
}

func New(private []byte) X3dh {
	eddsa := xeddsa.New(private)
	psk_pri, psk_pub := generate_key_pair()
	signed_key := make(map[string][]byte)
	otp := make(map[string][]byte)
	otp_pub := make([]Opt, 5)
	signed_key[base64.RawStdEncoding.EncodeToString(psk_pub)] = psk_pri
	for i := 0; i < 5; i++ {
		private, public := generate_key_pair()
		otp[base64.RawStdEncoding.EncodeToString(public)] = private
		otp_pub[i] = Opt(public)
	}
	return X3dh{
		Spk:     SignKey(psk_pub),
		Otps:    otp_pub,
		eddsa:   eddsa,
		private: private,
		keys:    keys{signed_key, otp},
	}
}

func (x X3dh) Identity() Identity { return Identity(x.eddsa.Public) }

func (x X3dh) Keys() PublicKeys {
	return PublicKeys{
		x.Identity(),
		x.Spk,
		x.Sign(x.Spk[:]),
		x.Otps[0],
	}
}

func (x X3dh) associatedData(ik []byte, sender bool) []byte {
	i := x.Identity()
	if sender {
		return append(i[:], ik...)
	} else {
		return append(ik[:], i[:]...)
	}
}

func (x X3dh) PrepareInitialMessage(keys PublicKeys, messagecontent []byte) ([]byte, InitialMessage) {
	shared, epk := x.SharedKey(keys)
	n := rand.Uint32()
	cipherText := encrypt(shared, x.associatedData(keys.Identity[:], true), messagecontent, n)
	b64Encoder := base64.RawStdEncoding.EncodeToString
	identity := x.Identity()
	message := InitialMessage{
		Identity: b64Encoder(identity[:]),
		Epk:      b64Encoder(epk),
		Prekeys:  [2]string{b64Encoder(keys.SignedPreKey[:]), b64Encoder(keys.OneTimePreKeys[:])},
		Text:     b64Encoder(cipherText),
		N:        n,
		Path:     "",
	}
	return shared, message
}

func (x X3dh) Identity_Converted() ([]byte, error) {
	return convert_goldilock(x.Identity())
}

func (x X3dh) SharedKey(keys PublicKeys) ([]byte, []byte) {
	if !xeddsa.Verify(keys.Identity[:], keys.SignedPreKey[:], keys.Signature) {
		return nil, nil
	}
	ikb, err := convert_goldilock(keys.Identity)
	if err != nil {
		return nil, nil
	}
	ek_prv, ek_pub := generate_key_pair()
	dh1 := new(x448.Key)
	dh2 := new(x448.Key)
	dh3 := new(x448.Key)
	x448.Shared(dh1, (*x448.Key)(x.private), (*x448.Key)(keys.SignedPreKey[:]))
	x448.Shared(dh2, (*x448.Key)(ek_prv), (*x448.Key)(ikb))
	x448.Shared(dh3, (*x448.Key)(ek_prv), (*x448.Key)(keys.SignedPreKey[:]))
	if &keys.OneTimePreKeys != nil { //one time key is not empty
		dh4 := new(x448.Key)
		x448.Shared(dh4, (*x448.Key)(ek_prv), (*x448.Key)(keys.OneTimePreKeys[:]))
		return _KDF(appendDH(dh1[:], dh2[:], dh3[:], dh4[:])), ek_pub
	} else {
		return _KDF(appendDH(dh1[:], dh2[:], dh3[:], nil)), ek_pub
	}
}

func (x X3dh) SharedKeyFromMessage(initialMessage InitialMessage) []byte {
	var shared []byte
	//decode message from base64 to byte
	decode64 := base64.RawStdEncoding.DecodeString
	peer_identity, _ := decode64(initialMessage.Identity)
	message, _ := decode64(initialMessage.Text)
	epk, _ := decode64(initialMessage.Epk)
	peer_identity_mont, _ := convert_goldilock(Identity(peer_identity))
	spk := x.keys.signedKey[initialMessage.Prekeys[0]]

	dh1 := new(x448.Key)
	dh2 := new(x448.Key)
	dh3 := new(x448.Key)
	x448.Shared(dh1, (*x448.Key)(spk), (*x448.Key)(peer_identity_mont))
	x448.Shared(dh2, (*x448.Key)(x.private), (*x448.Key)(epk))
	x448.Shared(dh3, (*x448.Key)(spk), (*x448.Key)(epk))
	if initialMessage.Prekeys[1] != "" {
		dh4 := new(x448.Key)
		opk := x.keys.otp[initialMessage.Prekeys[1]]
		x448.Shared(dh4, (*x448.Key)(opk), (*x448.Key)(epk))
		shared = _KDF(appendDH(dh1[:], dh2[:], dh3[:], dh4[:]))
	} else {
		shared = _KDF(appendDH(dh1[:], dh2[:], dh3[:], nil))
	}
	if !decrypted(shared, x.associatedData(peer_identity, false), message, initialMessage.N) {
		return nil
	}
	return shared
}

func (x X3dh) Sign(msg []byte) []byte               { return x.eddsa.Sign(msg) }
func (x X3dh) Verify(key, message, sig []byte) bool { return xeddsa.Verify(key, message, sig) }
