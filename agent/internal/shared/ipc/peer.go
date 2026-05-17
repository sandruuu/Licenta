package ipc

import (
	"context"
	"net"
	"strings"
)

type PeerIdentity struct {
	UserSID           string
	Verified          bool
	VerificationError string
}

type peerIdentityContextKey struct{}

func ContextWithPeerIdentity(ctx context.Context, identity PeerIdentity) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	identity.UserSID = strings.TrimSpace(identity.UserSID)
	identity.VerificationError = strings.TrimSpace(identity.VerificationError)
	if identity.UserSID == "" {
		identity.Verified = false
	}
	return context.WithValue(ctx, peerIdentityContextKey{}, identity)
}

func PeerIdentityFromContext(ctx context.Context) (PeerIdentity, bool) {
	if ctx == nil {
		return PeerIdentity{}, false
	}
	identity, ok := ctx.Value(peerIdentityContextKey{}).(PeerIdentity)
	return identity, ok
}

func contextWithPeerIdentity(ctx context.Context, connection net.Conn) context.Context {
	identity, ok := peerIdentityForConnection(connection)
	if !ok {
		return ctx
	}
	return ContextWithPeerIdentity(ctx, identity)
}
