package crypto

import (
	c "github.com/emailtovamos/crypto/cryptoclient"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestBytesToPublicKey(t *testing.T) {
	_, publicKey1 := c.GenerateKeyPair(2048)
	publicKeyBytes := c.PublicKeyToBytes(publicKey1)
	publicKey2 := BytesToPublicKey(publicKeyBytes)

	isEqual := reflect.DeepEqual(publicKey1, publicKey2)
	assert.True(t, isEqual, "public key conversion comparison")
}

func TestBytesToPrivateKey(t *testing.T) {
	privateKey1, _ := c.GenerateKeyPair(2048)
	privateKeyBytes := c.PrivateKeyToBytes(privateKey1)
	privateKey2 := BytesToPrivateKey(privateKeyBytes)

	isEqual := reflect.DeepEqual(privateKey1, privateKey2)
	assert.True(t, isEqual, "private key conversion comparison")

	privateKey11, _ := c.GenerateKeyPair(2048)
	privateKeyBytes11 := c.PrivateKeyToBytes(privateKey11)
	privateKey22 := BytesToPrivateKey(privateKeyBytes11)

	isEqual2 := reflect.DeepEqual(privateKey1, privateKey22)
	assert.False(t, isEqual2, "private key conversion comparison")

}
