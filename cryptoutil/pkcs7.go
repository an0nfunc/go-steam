package cryptoutil

import (
	"crypto/aes"
	"fmt"
)

// Returns a new byte array padded with PKCS7 and prepended
// with empty space of the AES block size (16 bytes) for the IV.
func padPKCS7WithIV(src []byte) []byte {
	missing := aes.BlockSize - (len(src) % aes.BlockSize)
	newSize := len(src) + aes.BlockSize + missing
	dest := make([]byte, newSize, newSize)
	copy(dest[aes.BlockSize:], src)

	padding := byte(missing)
	for i := newSize - missing; i < newSize; i++ {
		dest[i] = padding
	}
	return dest
}

func unPadPKCS7(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("unpad not possible")
	}

	padLen := src[len(src)-1]
	if len(src) < len(src)-int(padLen) {
		return nil, fmt.Errorf("unpad not possible")
	} else {
		return src[:len(src)-int(padLen)], nil
	}
}
