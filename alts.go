package credentials

import (
	"context"
	"credentials/alts/internal"
	"net"

	"google.golang.org/grpc/credentials"
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
	side internal.Side
}

// NewClientCreds constructs a client-side ALTS TransportCredentials object.
func NewClientCreds(opts *ClientOptions) credentials.TransportCredentials {
	return newALTS(internal.ClientSide)
}

// NewServerCreds constructs a server-side ALTS TransportCredentials object.
func NewServerCreds(opts *ServerOptions) credentials.TransportCredentials {
	return newALTS(internal.ServerSide)
}

func newALTS(side internal.Side) credentials.TransportCredentials {
	return &altsTC{
		info: &credentials.ProtocolInfo{
			SecurityProtocol: "alts",
			SecurityVersion:  "0.1",
		},
		side: side,
	}
}

// ClientHandshake implements the client side handshake protocol.
func (g *altsTC) ClientHandshake(ctx context.Context, addr string, rawConn net.Conn) (_ net.Conn, _ credentials.AuthInfo, err error) {
	return
}

// ServerHandshake implements the server side ALTS handshaker.
func (g *altsTC) ServerHandshake(rawConn net.Conn) (_ net.Conn, _ credentials.AuthInfo, err error) {
	return
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
