package dhpals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"math/big"
	"testing"

	"github.com/dnkolegov/dhpals/dhgroup"
)

func Derypting(key, iv, msg []byte) ([]byte, error) {
	sessionKey := sha1.New().Sum(key)[:aes.BlockSize]
	block, _ := aes.NewCipher(sessionKey)
	cbc := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(msg))
	cbc.CryptBlocks(decrypted, msg)
	paddedsymb := int(decrypted[len(decrypted)-1])
	err := CheckPadding(paddedsymb, decrypted)
	if err != nil {
		return nil, err
	}
	decrypted = decrypted[:(len(decrypted) - paddedsymb)]
	return decrypted, nil
}

func CheckPadding(paddedsymb int, decrypted []byte) error {
	if paddedsymb <= 0 || paddedsymb > aes.BlockSize {
		paderror := fmt.Errorf("Padding was wrong: symb is: %d", paddedsymb)
		return paderror
	}
	for i := 1; i <= paddedsymb; i++ {
		if int(decrypted[len(decrypted)-i]) != paddedsymb {
			paderror := fmt.Errorf("Padding was wrong: symbols are different %d", paddedsymb)
			return paderror
		}
	}
	return nil
}

func Encrypting(key, iv, msg []byte) []byte {
	paddingl := aes.BlockSize - len(msg)%aes.BlockSize
	padding := bytes.Repeat([]byte{byte(paddingl)}, paddingl)
	paddedmsg := append(msg, padding...)
	sessionKey := sha1.New().Sum(key)[:aes.BlockSize]
	block, _ := aes.NewCipher(sessionKey)
	ciphertext := make([]byte, len(paddedmsg))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, paddedmsg)
	return ciphertext
}

func TestMitm(t *testing.T) {

	for _, v := range []dhgroup.ID{dhgroup.ModP512v57, dhgroup.ModP512v58, dhgroup.ModP768, dhgroup.ModP1536, dhgroup.ModP2048} {
		scheme, _ := dhgroup.GroupForGroupID(v)

		p := scheme.DHParams().P

		alice, _ := scheme.GenerateKey(rand.Reader)
		bob, _ := scheme.GenerateKey(rand.Reader)
		mallory, _ := scheme.GenerateKey(rand.Reader)
		mallory.Public = p

		skAtoM, _ := scheme.DH(alice.Private, mallory.Public)
		skBtoM, _ := scheme.DH(bob.Private, mallory.Public)

		if Big0.Cmp(skAtoM) != 0 && Big0.Cmp(skBtoM) != 0 {
			t.Errorf("%s: keys are wrong for %s. There are values: %s and %s", t.Name(), scheme.DHName(), skAtoM, skBtoM)
		}

		msg, _ := rand.Int(rand.Reader, p)
		plaintext := msg.Bytes()
		ivr, _ := rand.Int(rand.Reader, p)
		iv := ivr.Bytes()[:16]
		ciphertext := Encrypting(Big0.Bytes(), iv, plaintext)
		decrypted, err := Derypting(Big0.Bytes(), iv, ciphertext)
		if err != nil {
			fmt.Println(err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("AES went wrong for %s in %s", t.Name(), scheme.DHName())
		}
	}

}

func TestMitmG(t *testing.T) {
	for _, v := range []dhgroup.ID{dhgroup.ModP512v57, dhgroup.ModP512v58, dhgroup.ModP768, dhgroup.ModP1536, dhgroup.ModP2048} {
		scheme, _ := dhgroup.GroupForGroupID(v)

		p := scheme.DHParams().P

		msg, _ := rand.Int(rand.Reader, p)
		plaintext := msg.Bytes()
		ivr, _ := rand.Int(rand.Reader, p)
		iv := ivr.Bytes()[:16]

		pSub := new(big.Int).Sub(p, Big1)
		genericValue := []*big.Int{Big1, p, pSub}
		for _, value := range genericValue {

			scheme.DHParams().G = value

			alice, _ := scheme.GenerateKey(rand.Reader)
			bob, _ := scheme.GenerateKey(rand.Reader)
			mallory, _ := scheme.GenerateKey(rand.Reader)

			skAtoM, _ := scheme.DH(alice.Private, mallory.Public)
			skBtoM, _ := scheme.DH(bob.Private, mallory.Public)

			if value == Big1 {
				if Big1.Cmp(skAtoM) != 0 && Big1.Cmp(skBtoM) != 0 {
					t.Errorf("%s: keys are wrong for %s. There are values: %s and %s with g:%s", t.Name(), scheme.DHName(), skAtoM, skBtoM, value)
				}

				ciphertext := Encrypting(skAtoM.Bytes(), iv, plaintext)
				decrypted, _ := Derypting(Big1.Bytes(), iv, ciphertext)

				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("AES went wrong for %s in %s", t.Name(), scheme.DHName())
				}
			} else if value == p {
				if Big0.Cmp(skAtoM) != 0 && Big0.Cmp(skBtoM) != 0 {
					t.Errorf("%s: keys are wrong for %s. There are values: %s and %s with g:%s", t.Name(), scheme.DHName(), skAtoM, skBtoM, value)
				}

				ciphertext := Encrypting(skAtoM.Bytes(), iv, plaintext)
				decrypted, _ := Derypting(Big0.Bytes(), iv, ciphertext)

				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("AES went wrong for %s in %s", t.Name(), scheme.DHName())
				}
			} else {
				ciphertext := Encrypting(skAtoM.Bytes(), iv, plaintext)
				decrypted, err := Derypting(Big1.Bytes(), iv, ciphertext)
				if err != nil {
					decrypted, _ = Derypting(pSub.Bytes(), iv, ciphertext)
				}
				if !bytes.Equal(decrypted, plaintext) {
					if len(decrypted) == len(plaintext)+aes.BlockSize-1 {
						decrypted, _ = Derypting(pSub.Bytes(), iv, ciphertext)
						if !bytes.Equal(decrypted, plaintext) {
							t.Errorf("AES went wrong for %s in %s with Alice's %s when p is %s", t.Name(), scheme.DHName(), skAtoM, p)
						}
					} else {
						t.Errorf("AES went wrong for %s in %s with Alice's %s when p is %s", t.Name(), scheme.DHName(), skAtoM, p)
					}
				}

				ciphertext = Encrypting(skBtoM.Bytes(), iv, plaintext)
				decrypted, err = Derypting(Big1.Bytes(), iv, ciphertext)
				if err != nil {
					decrypted, _ = Derypting(pSub.Bytes(), iv, ciphertext)
				}
				if !bytes.Equal(decrypted, plaintext) {
					if len(decrypted) == len(plaintext)+aes.BlockSize-1 {
						decrypted, _ = Derypting(pSub.Bytes(), iv, ciphertext)
						if !bytes.Equal(decrypted, plaintext) {
							t.Errorf("AES went wrong for %s in %s with Bob's %s when p is %s", t.Name(), scheme.DHName(), skBtoM, p)
						}
					} else {
						t.Errorf("AES went wrong for %s in %s with Bob's %s when p is %s", t.Name(), scheme.DHName(), skBtoM, p)
					}
				}
			}
		}
	}
}
