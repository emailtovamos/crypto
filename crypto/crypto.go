package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	pb "github.com/emailtovamos/crypto"
	"github.com/rs/zerolog/log"
	"io"
	"math"
	"os"
	"strconv"
)

type MaxNumber struct {
}

var max_Number = math.MinInt32

func (m *MaxNumber) FindMaxNumber(stream pb.MaxNumber_FindMaxNumberServer) error {

	for {
		in, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		cipherTextBytes := in.CipherText
		privateKeyBytes := in.PrivateKey
		publicKeyBytes := in.PublicKey
		signatureBytes := in.Signature

		// convert to proper units for keys
		privateKey := BytesToPrivateKey(privateKeyBytes)
		publicKey := BytesToPublicKey(publicKeyBytes)
		// Get plainText in bytes
		plainText := getPlainTextWithPrivateKey(cipherTextBytes, privateKey)
		// verify signature
		err = verifySignatureWithPublicKey(fmt.Sprintf("%s", plainText), signatureBytes, publicKey)
		if err != nil {
			log.Error().Err(err).Msg("Signature not verified")
			return err
		}
		log.Info().Msg("signature verified")

		byteToInt, _ := strconv.Atoi(string(plainText))

		// Get the number
		number := int32(byteToInt)
		// Do the algorithm to check
		numberToReturn := maxNumber(number)
		log.Info().Msgf("number %v numberToReturn %v  plainText %v \n", number, numberToReturn, plainText)

		// stream send back
		if numberToReturn != number {
			// don't return anything, continue
		} else {
			response := &pb.FindMaxNumberResponse{
				MaxNumber: numberToReturn,
			}
			if err := stream.Send(response); err != nil {
				return err
			}
		}

	}
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		log.Info().Msg("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			log.Error().Err(err).Msg("")
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		log.Error().Err(err).Msg("")
	}
	return key
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		log.Info().Msg("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			log.Error().Err(err).Msg("")
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		log.Error().Err(err).Msg("")
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		log.Error().Err(err).Msg("not ok")
	}
	return key
}

func verifySignatureWithPublicKey(message string, signature []byte, key *rsa.PublicKey) error {
	newhash := crypto.SHA256
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	pssh := newhash.New()
	pssh.Write([]byte(message))
	hashed := pssh.Sum(nil)
	err := rsa.VerifyPSS(
		key,
		newhash,
		hashed,
		signature,
		&opts)
	if err != nil {
		fmt.Println("Who are U? Verify Signature failed")
		return err
	} else {
		fmt.Println("Verify Signature successful")
		return nil
	}
}

// decrypt to plain text
func getPlainTextWithPrivateKey(ciphertext []byte, key *rsa.PrivateKey) []byte {
	hash := sha256.New()
	label := []byte("")
	plainText, err := rsa.DecryptOAEP(
		hash,
		rand.Reader,
		key,
		ciphertext,
		label)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return plainText
}

func maxNumber(number int32) int32 {
	if number > int32(max_Number) {
		max_Number = int(number)
		return number
	}
	return int32(max_Number)
}
