package cryptoutil

import (
	"crypto/aes"
	"testing"
)

func TestPKCS7Pad(t *testing.T) {
	in := []byte("123456789012345678901234567890")
	out := padPKCS7WithIV(in)
	if len(out) != 32+aes.BlockSize {
		t.Fatalf("Invalid output size, expected 48 and got %v", len(out))
	}
	if out[47] != 2 {
		t.Fatalf("Invalid last output byte, expected 2 and got %v", out[47])
	}
}

func TestPKCS7Unpad(t *testing.T) {
	in := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 4, 4, 4, 4}
	out, err := unPadPKCS7(in)
	if err != nil {
		t.Fatalf("Error unpadding valid PKCS7: %v", err)
	}
	if len(out) != 12 {
		t.Fatalf("Invalid output size, expected 12 and got %v", len(out))
	}
	if out[7] != 8 {
		t.Fatalf("Invalid last output byte, expected 8 and got %v", out[7])
	}

	in = []byte{1, 2, 255}
	out, err = unPadPKCS7(in)
	if err == nil {
		t.Fatalf("Error should be filled: %v", err)
	}

	in = []byte{}
	out, err = unPadPKCS7(in)
	if err == nil {
		t.Fatalf("Error should be filled: %v", err)
	}
}
