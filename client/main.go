package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	pb "github.com/emailtovamos/crypto"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"io"
	"os"
	"strconv"
	"time"
)

var (
	serverAddr = flag.String("server_addr", "127.0.0.1:10000", "The server address in the format of host:port")
)

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*serverAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatal().Msgf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := pb.NewMaxNumberClient(conn)

	// Run maxnumber
	runMaxNumber(client)
}

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Error().Err(err).Msg("")
	}
	return privkey, &privkey.PublicKey
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Error().Err(err).Msg("")
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

//signer
func getSignatureWithPrivKey(message string, key *rsa.PrivateKey) []byte {
	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := message
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write([]byte(PSSmessage))
	hashed := pssh.Sum(nil)
	signature, err := rsa.SignPSS(
		rand.Reader,
		key,
		newhash,
		hashed,
		&opts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return signature
}

//encrypter
func getCypherTextWithPubKey(msg string, key *rsa.PublicKey) []byte {
	message := []byte(msg)
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		key,
		message,
		label)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return ciphertext
}

func runMaxNumber(client pb.MaxNumberClient) {
	numbers := []int32{1, 5, 3, 6, 2, 20}
	privateKey, publicKey := GenerateKeyPair(2048)
	privateKeyBytes := PrivateKeyToBytes(privateKey)
	publicKeyBytes := PublicKeyToBytes(publicKey)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.FindMaxNumber(ctx)
	if err != nil {
		log.Fatal().Msgf("%v.RouteChat(_) = _, %v", client, err)
	}
	waitc := make(chan struct{})
	go func() {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				// read done.
				close(waitc)
				return
			}
			if err != nil {
				log.Fatal().Msgf("Failed to receive a note : %v", err)
			}
			log.Info().Msgf("Got response: %d", in.MaxNumber)
		}
	}()
	for _, number := range numbers {
		// Convert number to string
		numberString := strconv.Itoa(int(number))
		// Create Signature & cipherText
		signature := getSignatureWithPrivKey(numberString, privateKey)
		cipherText := getCypherTextWithPubKey(numberString, publicKey)
		// Create message to send
		request := &pb.FindMaxNumberRequest{
			PublicKey:  publicKeyBytes,
			PrivateKey: privateKeyBytes,
			Signature:  signature,
			CipherText: cipherText,
		}
		if err := stream.Send(request); err != nil {
			log.Fatal().Msgf("Failed to send a note: %v", err)
		}
	}
	stream.CloseSend()
	<-waitc
}
