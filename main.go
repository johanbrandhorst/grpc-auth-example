package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/johanbrandhorst/grpc-auth-example/auth"
	"github.com/johanbrandhorst/grpc-auth-example/insecure"
	pbExample "github.com/johanbrandhorst/grpc-auth-example/proto"
	"github.com/johanbrandhorst/grpc-auth-example/server"
)

var (
	gRPCPort = flag.Int("grpc-port", 10000, "The gRPC server port")
	username = flag.String("username", "testuser", "The username to authenticate with")
	password = flag.String("password", "testpassword", "The password to authenticate with")
	token    = flag.String("token", "testtoken", "The token to authenticate with")
)

var log grpclog.LoggerV2

func init() {
	log = grpclog.NewLoggerV2(os.Stdout, ioutil.Discard, ioutil.Discard)
	grpclog.SetLoggerV2(log)
}

func main() {
	flag.Parse()
	addr := fmt.Sprintf("localhost:%d", *gRPCPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalln("Failed to listen:", err)
	}

	auther := auth.Authenticator{
		Username: *username,
		Password: *password,
		Token:    *token,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{insecure.Cert},
		ClientCAs:    insecure.CertPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}

	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.StreamInterceptor(grpc_auth.StreamServerInterceptor(auther.Authenticate)),
		grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(auther.Authenticate)),
	)

	pbExample.RegisterUserServiceServer(s, server.New())

	// Serve gRPC Server
	log.Info("Serving gRPC on https://", addr)
	log.Fatal(s.Serve(lis))
}
