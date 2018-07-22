# grpc-auth-example

Examples of client authentication with gRPC. Both server-side and
client-side implementations are shown. All authentication is
performed in a server-side interceptor implemented in the
[`auth` package](./auth/).

## TLS Client Certificate Authentication

The first type of authentication uses TLS Certificate subjects
to validate that the correct client is connecting. This, of course,
relies on the issue certificate authority only issuing certificates
with the correct subject to the correct service, but that is outside
the scope of this repository.

On the client side, we create a certificate with the appropriate subject:

```go
pk, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
    return nil, err
}

template := &x509.Certificate{
    SerialNumber: serialNumber,
    Subject: pkix.Name{
        Organization: []string{"Acme Co"},
        CommonName:   username, // Will be checked by the server
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

tlsCert := tls.Certificate{
    Certificate: [][]byte{cert},
    PrivateKey:  pk,
}
```

We then use the certificate for transport security when dialing:

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{tlsCert},
    RootCAs:      insecure.CertPool,
}

conn, err := grpc.DialContext(ctx, net.JoinHostPort(addr, port),
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
)
```

On the server side, we use the [`grpc/peer`](https://godoc.org/google.golang.org/grpc/peer)
package to find the subject of the client side certificate:

```go
p, ok := peer.FromContext(ctx)
if !ok {
    return status.Error(codes.Unauthenticated, "no peer found")
}

tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
if !ok {
    return status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
}

if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
    return status.Error(codes.Unauthenticated, "could not verify peer certificate")
}

// Check subject common name against configured username
if tlsAuth.State.VerifiedChains[0][0].Subject.CommonName != a.Username {
    return status.Error(codes.Unauthenticated, "invalid subject common name")
}

return nil
```

This of course requires the server to verify incoming client certs,
so remember to configure the appropriate `tls.Config.ClientAuth` value.
In this example, we use `tls.VerifyClientCertIfGiven` to allow clients both
with and without certificates.

## Token based authentication

Secondly we've got token based authentication, which sends the authentication
details in the request headers. On the client side this means implementing
[`grpc/credentials.PerRPCCredentials`](https://godoc.org/google.golang.org/grpc/credentials#PerRPCCredentials):

```go
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
```

We then use the `tokenAuth` struct when dialling:

```go
conn, err := grpc.DialContext(ctx, net.JoinHostPort(addr, port),
    grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(insecure.CertPool, "")),
    grpc.WithPerRPCCredentials(tokenAuth{
        token: token,
    }),
)
```

On the server side, we simply check the header for the token value, but, of course,
if you were using a real token you might want to parse it and perform some validation as well.

```go
const prefix = "Bearer "
if !strings.HasPrefix(auth, prefix) {
	return ctx, status.Error(codes.Unauthenticated, `missing "Bearer " prefix in "Authorization" header`)
}

if strings.TrimPrefix(auth, prefix) != a.Token {
	return ctx, status.Error(codes.Unauthenticated, "invalid token")
}
```

## HTTP Basic authentication

Much like the token based authentication, this uses `PerRPCCredentials`, with the only
difference being the contents of the header:

```go
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
```

And dialling:

```go
conn, err := grpc.DialContext(ctx, net.JoinHostPort(addr, port),
	grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(insecure.CertPool, "")),
	grpc.WithPerRPCCredentials(basicAuth{
		username: username,
		password: password,
	}),
)
```

The server has to parse the the header:

```go
const prefix = "Basic "
if !strings.HasPrefix(auth, prefix) {
    return ctx, status.Error(codes.Unauthenticated, `missing "Basic " prefix in "Authorization" header`)
}

c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
if err != nil {
    return ctx, status.Error(codes.Unauthenticated, `invalid base64 in header`)
}

cs := string(c)
s := strings.IndexByte(cs, ':')
if s < 0 {
    return ctx, status.Error(codes.Unauthenticated, `invalid basic auth format`)
}

user, password := cs[:s], cs[s+1:]
if user != a.Username || password != a.Password {
    return ctx, status.Error(codes.Unauthenticated, "invalid user or password")
}
```
