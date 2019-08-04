package main

import (
	"flag"
	pb "github.com/emailtovamos/crypto"
	"github.com/emailtovamos/crypto/cryptoclient"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
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
	cryptoclient.RunMaxNumber(client)
}
