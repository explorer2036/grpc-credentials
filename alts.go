package credentials

import (
	"context"
	"credentials/alts"
	"credentials/alts/handshaker"
	"net"
	"time"

	"google.golang.org/grpc/credentials"
)

const (
	// defaultTimeout specifies the server handshake timeout.
	defaultTimeout = 30 * time.Second
)

// ClientOptions contains the client-side options of an ALTS channel. These
// options will be passed to the underlying ALTS handshaker
type ClientOptions struct {
}

// DefaultClientOptions creates a new ClientOptions object with the default
// values.
func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{}
}

// ServerOptions contains the server-side options of an ALTS channel. These
// options will be passed to the underlying ALTS handshaker.
type ServerOptions struct {
}

// DefaultServerOptions creates a new ServerOptions object with the default
// values.
func DefaultServerOptions() *ServerOptions {
	return &ServerOptions{}
}

// altsTC is the credentials required for authenticating a connection using ALTS.
// It implements credentials.TransportCredentials interface.
type altsTC struct {
	info *credentials.ProtocolInfo
	side alts.Side
}

// NewClientCreds constructs a client-side ALTS TransportCredentials object.
func NewClientCreds(opts *ClientOptions) credentials.TransportCredentials {
	return newALTS(alts.ClientSide)
}

// NewServerCreds constructs a server-side ALTS TransportCredentials object.
func NewServerCreds(opts *ServerOptions) credentials.TransportCredentials {
	return newALTS(alts.ServerSide)
}

func newALTS(side alts.Side) credentials.TransportCredentials {
	return &altsTC{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: "alts",
			SecurityVersion:  "0.1",
		},
		side: side,
	}
}

// ClientHandshake implements the client side handshake protocol.
func (g *altsTC) ClientHandshake(ctx context.Context, addr string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	opts := handshaker.DefaultClientHandshakerOptions()
	chs, err := handshaker.NewClientHandshaker(ctx, rawConn, opts)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			chs.Close()
		}
	}()

	secureConn, authInfo, err := chs.ClientHandshake(ctx)
	if err != nil {
		return nil, nil, err
	}

	return secureConn, authInfo, nil
}

// ServerHandshake implements the server side ALTS handshaker.
func (g *altsTC) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	opts := handshaker.DefaultServerHandshakerOptions()
	shs, err := handshaker.NewServerHandshaker(ctx, rawConn, opts)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			shs.Close()
		}
	}()

	secureConn, authInfo, err := shs.ServerHandshake(ctx)
	if err != nil {
		return nil, nil, err
	}

	return secureConn, authInfo, nil
}

func (g *altsTC) Info() credentials.ProtocolInfo {
	return *g.info
}

func (g *altsTC) Clone() credentials.TransportCredentials {
	info := *g.info
	return &altsTC{
		info: &info,
		side: g.side,
	}
}

func (g *altsTC) OverrideServerName(serverNameOverride string) error {
	g.info.ServerName = serverNameOverride
	return nil
}
