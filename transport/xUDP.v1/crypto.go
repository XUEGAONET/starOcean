package xUDP_v1

import (
	"crypto/aes"
	"crypto/cipher"
)

type AESCipher struct {
	block cipher.Block
}

func NewAESCipher(token []byte) (*AESCipher, error) {
	block, err := aes.NewCipher(token)
	if err != nil {
		return nil, err
	}

	return &AESCipher{
		block: block,
	}, nil
}

func (c *AESCipher) Encrypt(plain []byte, enc []byte) {
	c.block.Encrypt(enc, plain)
}

func (c *AESCipher) Decrypt(plain []byte, enc []byte) {
	c.block.Decrypt(plain, enc)
}
