package main

import (
	"flag"
	"fmt"
	pb "github.com/emailtovamos/crypto"
	crypto "github.com/emailtovamos/crypto/crypto"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"net"
)

var (
	port = flag.Int("port", 10000, "The server port")
)

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatal().Msgf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	srv := &crypto.MaxNumber{}
	pb.RegisterMaxNumberServer(grpcServer, srv)
	log.Info().Int("addr", *port).Msg("starting gRPC server")
	if err = grpcServer.Serve(lis); err != nil {
		log.Fatal().Msgf("Failed to serve at address %v \n", *port)
	} else {
		log.Info().Msgf("Server listening at address %v \n", *port)
	}
}
