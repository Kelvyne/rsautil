// Package rsautil contain utility function to decrypt with a RSA public key
// This is not tested code
package rsautil

import (
	"crypto/rsa"
	"crypto/subtle"
	"math/big"
)

// PublicKeyDecrypt uses a RSA public key k to decrypt b
func PublicKeyDecrypt(k *rsa.PublicKey, b []byte) ([]byte, error) {
	valid, em, i, err := decryptPKCS1v15(k, b)
	if valid == 0 {
		return nil, rsa.ErrDecryption
	}
	return em[i:], err
}

func decryptPKCS1v15(pub *rsa.PublicKey, ciphertext []byte) (valid int, em []byte, index int, err error) {
	k := (pub.N.BitLen() + 7) / 8
	if k < 11 {
		err = rsa.ErrDecryption
		return
	}

	c := new(big.Int).SetBytes(ciphertext)
	m := encrypt(new(big.Int), pub, c)

	em = leftPad(m.Bytes(), k)
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 1)

	lookingForIndex := 1

	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	validPS := subtle.ConstantTimeLessOrEq(2+8, index)

	valid = firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)
	return valid, em, index, nil
}

func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}
