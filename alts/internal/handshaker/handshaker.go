package handshaker

import (
	"context"
	"credentials/alts/internal"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc/credentials"
)

const (
	// The maximum byte size of receive frames
	frameLimit = 64 * 1024 // 64 KB
	// maxPendingHandshakes represents the maximum number of concurrent
	// handshakes.
	maxPendingHandshakes = 100
)

var (
	// control number of concurrent created (but not closed) handshakers.
	mu                   sync.Mutex
	concurrentHandshakes = int64(0)
	// errDropped occurs when maxPendingHandshakes is reached.
	errDropped = errors.New("maximum number of concurrent ALTS handshakes is reached")
)

func acquire() bool {
	mu.Lock()
	// If we need n to be configurable, we can pass it as an argument.
	n := int64(1)
	success := maxPendingHandshakes-concurrentHandshakes >= n
	if success {
		concurrentHandshakes += n
	}
	mu.Unlock()
	return success
}

func release() {
	mu.Lock()
	// If we need n to be configurable, we can pass it as an argument.
	n := int64(1)
	concurrentHandshakes -= n
	if concurrentHandshakes < 0 {
		mu.Unlock()
		panic("bad release")
	}
	mu.Unlock()
}

// ClientHandshakerOptions contains the client handshaker options that can
// provided by the caller.
type ClientHandshakerOptions struct {
}

// ServerHandshakerOptions contains the server handshaker options that can
// provided by the caller.
type ServerHandshakerOptions struct {
}

// DefaultClientHandshakerOptions returns the default client handshaker options.
func DefaultClientHandshakerOptions() *ClientHandshakerOptions {
	return &ClientHandshakerOptions{}
}

// DefaultServerHandshakerOptions returns the default client handshaker options.
func DefaultServerHandshakerOptions() *ServerHandshakerOptions {
	return &ServerHandshakerOptions{}
}

// altsHandshaker is used to complete a ALTS handshaking between client and server.
type altsHandshaker struct {
	// the connection to the peer.
	conn net.Conn
	// client handshake options.
	clientOpts *ClientHandshakerOptions
	// server handshake options.
	serverOpts *ServerHandshakerOptions
	// defines the side doing the handshake, client or server.
	side internal.Side
}

// NewClientHandshaker creates a ALTS handshaker
func NewClientHandshaker(ctx context.Context, conn net.Conn, opts *ClientHandshakerOptions) (internal.Handshaker, error) {
	return &altsHandshaker{
		conn:       conn,
		clientOpts: opts,
		side:       internal.ClientSide,
	}, nil
}

// NewServerHandshaker creates a ALTS handshaker
func NewServerHandshaker(ctx context.Context, conn net.Conn, opts *ServerHandshakerOptions) (internal.Handshaker, error) {
	return &altsHandshaker{
		conn:       conn,
		serverOpts: opts,
		side:       internal.ServerSide,
	}, nil
}

// ClientHandshake starts and completes a client ALTS handshaking. Once
// done, ClientHandshake returns a secure connection.
func (s *altsHandshaker) ClientHandshake(ctx context.Context) (net.Conn, credentials.AuthInfo, error) {
	if !acquire() {
		return nil, nil, errDropped
	}
	defer release()

	if s.side != internal.ClientSide {
		return nil, nil, errors.New("only handshakers created using NewClientHandshaker can perform a client handshaker")
	}

	return nil, nil, nil
}

// ServerHandshake starts and completes a server ALTS handshaking for GCP. Once
// done, ServerHandshake returns a secure connection.
func (s *altsHandshaker) ServerHandshake(ctx context.Context) (net.Conn, credentials.AuthInfo, error) {
	if !acquire() {
		return nil, nil, errDropped
	}
	defer release()

	if s.side != internal.ServerSide {
		return nil, nil, errors.New("only handshakers created using NewServerHandshaker can perform a server handshaker")
	}
	return nil, nil, nil
}

// Close terminates the Handshaker. It should be called when the caller obtains
// the secure connection.
func (s *altsHandshaker) Close() {
}
