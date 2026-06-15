// Package notificationsapi implements the NotificationsService gRPC server.
//
// Every handler resolves the caller's identity from the request context and
// scopes all store operations to that user's ID, so one user can never read or
// mutate another user's notifications.
package notificationsapi

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	notificationsv1 "github.com/zwarder/waf/gobackend/gen/notifications/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/store"
)

// Store is the persistence surface notificationsapi needs. Implemented by *store.Store.
type Store interface {
	CreateNotification(ctx context.Context, n *store.Notification) (*store.Notification, error)
	ListNotifications(ctx context.Context, userID int64, filter string, limit int, beforeID int64) ([]store.Notification, error)
	CountUnread(ctx context.Context, userID int64) (int64, error)
	MarkNotificationsRead(ctx context.Context, userID int64, ids []int64) error
	MarkAllNotificationsRead(ctx context.Context, userID int64) error
	SetNotificationStar(ctx context.Context, userID, id int64, starred bool) (*store.Notification, error)
	SoftDeleteNotifications(ctx context.Context, userID int64, ids []int64) error
}

// Service implements notificationsv1.NotificationsServiceServer.
type Service struct {
	notificationsv1.UnimplementedNotificationsServiceServer
	store Store
	log   *slog.Logger
}

// New constructs a Service.
func New(st Store, log *slog.Logger) *Service {
	return &Service{store: st, log: log}
}

// AuthLevels declares that every method requires a verified (logged-in) caller.
func (s *Service) AuthLevels() map[string]auth.Level {
	return map[string]auth.Level{
		notificationsv1.NotificationsService_ListNotifications_FullMethodName:   auth.LevelVerified,
		notificationsv1.NotificationsService_GetUnreadCount_FullMethodName:      auth.LevelVerified,
		notificationsv1.NotificationsService_MarkRead_FullMethodName:            auth.LevelVerified,
		notificationsv1.NotificationsService_MarkAllRead_FullMethodName:         auth.LevelVerified,
		notificationsv1.NotificationsService_ToggleStar_FullMethodName:          auth.LevelVerified,
		notificationsv1.NotificationsService_DeleteNotifications_FullMethodName: auth.LevelVerified,
	}
}

// identity extracts the authenticated caller from the context.
func identity(ctx context.Context) (*auth.Identity, error) {
	id, ok := auth.IdentityFromContext(ctx)
	if !ok || id == nil {
		return nil, status.Error(codes.Unauthenticated, "not authenticated")
	}
	return id, nil
}

// toProto converts a store.Notification to the proto wire type.
func toProto(n store.Notification) *notificationsv1.Notification {
	dataJSON := string(n.Data)
	if dataJSON == "" {
		dataJSON = "{}"
	}

	p := &notificationsv1.Notification{
		Id:        n.ID,
		Type:      n.Type,
		Title:     n.Title,
		Body:      n.Body,
		DataJson:  dataJSON,
		Read:      n.ReadAt != nil,
		Starred:   n.Starred,
		CreatedAt: n.CreatedAt.UTC().Format(time.RFC3339),
	}
	if n.TenantID != nil {
		p.TenantId = *n.TenantID
		p.HasTenantId = true
	}
	return p
}

// ListNotifications returns the caller's notifications, optionally filtered and
// cursor-paginated by before_id.
func (s *Service) ListNotifications(ctx context.Context, req *notificationsv1.ListNotificationsRequest) (*notificationsv1.ListNotificationsResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}

	rows, err := s.store.ListNotifications(ctx, id.UserID, req.GetFilter(), int(req.GetLimit()), req.GetBeforeId())
	if err != nil {
		s.log.Error("ListNotifications store error", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	out := make([]*notificationsv1.Notification, 0, len(rows))
	for _, n := range rows {
		out = append(out, toProto(n))
	}

	var nextBeforeID int64
	limit := int(req.GetLimit())
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if len(rows) == limit {
		nextBeforeID = rows[len(rows)-1].ID
	}

	return &notificationsv1.ListNotificationsResponse{
		Notifications: out,
		NextBeforeId:  nextBeforeID,
	}, nil
}

// GetUnreadCount returns the number of unread notifications for the caller.
func (s *Service) GetUnreadCount(ctx context.Context, _ *notificationsv1.GetUnreadCountRequest) (*notificationsv1.UnreadCountResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}

	count, err := s.store.CountUnread(ctx, id.UserID)
	if err != nil {
		s.log.Error("GetUnreadCount store error", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &notificationsv1.UnreadCountResponse{Count: count}, nil
}

// MarkRead marks specific notifications as read for the caller.
func (s *Service) MarkRead(ctx context.Context, req *notificationsv1.MarkReadRequest) (*emptypb.Empty, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.store.MarkNotificationsRead(ctx, id.UserID, req.GetIds()); err != nil {
		s.log.Error("MarkRead store error", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &emptypb.Empty{}, nil
}

// MarkAllRead marks every unread notification for the caller as read.
func (s *Service) MarkAllRead(ctx context.Context, _ *notificationsv1.MarkAllReadRequest) (*emptypb.Empty, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.store.MarkAllNotificationsRead(ctx, id.UserID); err != nil {
		s.log.Error("MarkAllRead store error", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &emptypb.Empty{}, nil
}

// ToggleStar sets or clears the starred flag on a single notification owned by
// the caller. Returns NotFound when the row does not exist, is deleted, or
// belongs to a different user.
func (s *Service) ToggleStar(ctx context.Context, req *notificationsv1.ToggleStarRequest) (*notificationsv1.Notification, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}

	updated, err := s.store.SetNotificationStar(ctx, id.UserID, req.GetId(), req.GetStarred())
	if err != nil {
		var nf *store.NotFoundError
		if errors.As(err, &nf) {
			return nil, status.Error(codes.NotFound, "notification not found")
		}
		s.log.Error("ToggleStar store error", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return toProto(*updated), nil
}

// DeleteNotifications soft-deletes specific notifications for the caller.
// Rows not owned by the caller are silently skipped.
func (s *Service) DeleteNotifications(ctx context.Context, req *notificationsv1.DeleteNotificationsRequest) (*emptypb.Empty, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.store.SoftDeleteNotifications(ctx, id.UserID, req.GetIds()); err != nil {
		s.log.Error("DeleteNotifications store error", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &emptypb.Empty{}, nil
}
