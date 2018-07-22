package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"flag"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/johanbrandhorst/grpc-auth-example/insecure"
	pbExample "github.com/johanbrandhorst/grpc-auth-example/proto"
)

var (
	addr     = flag.String("addr", "localhost", "The address of the server to connect to")
	port     = flag.String("port", "10000", "The port to connect to")
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
	runWithTLSAuth(*addr, *port, *username)
	runWithTokenAuth(*addr, *port, *token)
	runWithBasicAuth(*addr, *port, *username, *password)
	log.Infoln("Success!")
}

func makeTLSCert(username string) (*tls.Certificate, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   username,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, insecure.Cert.Leaf, pk.Public(), insecure.Cert.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{cert},
		PrivateKey:  pk,
	}, nil
}

func runWithTLSAuth(addr, port, username string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tlsCert, err := makeTLSCert(username)
	if err != nil {
		log.Fatalln("Failed to create client cert:", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		RootCAs:      insecure.CertPool,
	}

	conn, err := grpc.DialContext(ctx, net.JoinHostPort(addr, port),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		log.Fatalln("Failed to dial server:", err)
	}
	defer conn.Close()
	c := pbExample.NewUserServiceClient(conn)
	run(ctx, c)
}

type tokenAuth struct {
	token string
}

func (t tokenAuth) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (tokenAuth) RequireTransportSecurity() bool {
	return true
}

func runWithTokenAuth(addr, port, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := grpc.DialContext(ctx, net.JoinHostPort(addr, port),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(insecure.CertPool, "")),
		grpc.WithPerRPCCredentials(tokenAuth{
			token: token,
		}),
	)
	if err != nil {
		log.Fatalln("Failed to dial server:", err)
	}
	defer conn.Close()
	c := pbExample.NewUserServiceClient(conn)
	run(ctx, c)
}

type basicAuth struct {
	username string
	password string
}

func (b basicAuth) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	auth := b.username + ":" + b.password
	enc := base64.StdEncoding.EncodeToString([]byte(auth))
	return map[string]string{
		"authorization": "Basic " + enc,
	}, nil
}

func (basicAuth) RequireTransportSecurity() bool {
	return true
}

func runWithBasicAuth(addr, port, username, password string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	conn, err := grpc.DialContext(ctx, net.JoinHostPort(addr, port),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(insecure.CertPool, "")),
		grpc.WithPerRPCCredentials(basicAuth{
			username: username,
			password: password,
		}),
	)
	if err != nil {
		log.Fatalln("Failed to dial server:", err)
	}
	defer conn.Close()
	c := pbExample.NewUserServiceClient(conn)
	run(ctx, c)
}

func run(ctx context.Context, c pbExample.UserServiceClient) {
	user := pbExample.User{Id: 1, Role: pbExample.Role_ADMIN}
	_, err := c.AddUser(ctx, &user)
	if err != nil {
		log.Fatalln("Failed to add user:", err)
	}

	srv, err := c.ListUsers(ctx, new(empty.Empty))
	if err != nil {
		log.Fatalln("Failed to list users:", err)
	}
	for {
		rcv, err := srv.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalln("Failed to receive:", err)
		}
		log.Infoln("Read user:", rcv)
		_, err = c.DeleteUser(ctx, &pbExample.DeleteUserRequest{
			Id: rcv.GetId(),
		})
		if err != nil {
			log.Fatalln("Failed to delete user:", err)
		}
	}
}
