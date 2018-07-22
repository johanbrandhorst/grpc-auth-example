package server

import (
	"context"
	"sync"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/johanbrandhorst/grpc-auth-example/auth"
	pbExample "github.com/johanbrandhorst/grpc-auth-example/proto"
)

type Backend struct {
	mu    *sync.RWMutex
	users []*pbExample.User
}

var _ pbExample.UserServiceServer = (*Backend)(nil)

func New() *Backend {
	return &Backend{
		mu: &sync.RWMutex{},
	}
}

func (b *Backend) AddUser(ctx context.Context, user *pbExample.User) (*empty.Empty, error) {
	_, ok := auth.GetUserMetadata(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no user authentication found")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Check user ID doesn't already exist
	for _, u := range b.users {
		if u.GetId() == user.GetId() {
			return nil, status.Error(codes.FailedPrecondition, "user already exists")
		}
	}

	if user.GetCreateDate() == nil {
		user.CreateDate = ptypes.TimestampNow()
	}

	b.users = append(b.users, user)

	return new(empty.Empty), nil
}

func (b *Backend) ListUsers(_ *empty.Empty, srv pbExample.UserService_ListUsersServer) error {
	_, ok := auth.GetUserMetadata(srv.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no user authentication found")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, user := range b.users {
		err := srv.Send(user)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *Backend) DeleteUser(ctx context.Context, req *pbExample.DeleteUserRequest) (*empty.Empty, error) {
	_, ok := auth.GetUserMetadata(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no user authentication found")
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	for i, u := range b.users {
		if u.GetId() == req.GetId() {
			copy(b.users[i:], b.users[i+1:])
			b.users[len(b.users)-1] = nil
			b.users = b.users[:len(b.users)-1]
			return new(empty.Empty), nil
		}
	}

	return nil, status.Error(codes.NotFound, "user not found")
}
