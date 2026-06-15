package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// Notification mirrors a row of the notifications table.
type Notification struct {
	ID        int64
	UserID    int64
	TenantID  *int64
	Type      string
	Title     string
	Body      string
	Data      []byte // raw JSONB
	ReadAt    *time.Time
	Starred   bool
	DeletedAt *time.Time
	CreatedAt time.Time
}

const notificationColumns = `
	id, user_id, tenant_id, type, title, body, data,
	read_at, starred, deleted_at, created_at`

func scanNotification(row pgx.Row, n *Notification) error {
	return row.Scan(
		&n.ID, &n.UserID, &n.TenantID, &n.Type, &n.Title, &n.Body, &n.Data,
		&n.ReadAt, &n.Starred, &n.DeletedAt, &n.CreatedAt,
	)
}

// CreateNotification inserts a new notification row and returns the full row
// with database-assigned id and created_at populated.
func (s *Store) CreateNotification(ctx context.Context, n *Notification) (*Notification, error) {
	if n.Data == nil {
		n.Data = []byte("{}")
	}
	const q = `
		INSERT INTO notifications (user_id, tenant_id, type, title, body, data)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING ` + notificationColumns
	out := &Notification{}
	err := scanNotification(
		s.pool.QueryRow(ctx, q, n.UserID, n.TenantID, n.Type, n.Title, n.Body, n.Data),
		out,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateNotification: %w", err)
	}
	return out, nil
}

// ListNotifications returns notifications for userID in descending ID order.
// filter: "" (all), "unread", or "starred".
// beforeID: if >0, only rows with id < beforeID (cursor pagination).
// limit: clamped to [1,50]; values <=0 or >100 become 50.
func (s *Store) ListNotifications(ctx context.Context, userID int64, filter string, limit int, beforeID int64) ([]Notification, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	q := `SELECT ` + notificationColumns + `
		FROM notifications
		WHERE user_id=$1 AND deleted_at IS NULL`
	args := []any{userID}

	switch filter {
	case "unread":
		q += ` AND read_at IS NULL`
	case "starred":
		q += ` AND starred`
	}

	if beforeID > 0 {
		args = append(args, beforeID)
		q += fmt.Sprintf(` AND id < $%d`, len(args))
	}

	args = append(args, limit)
	q += fmt.Sprintf(` ORDER BY id DESC LIMIT $%d`, len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("ListNotifications: %w", err)
	}
	defer rows.Close()

	out := []Notification{}
	for rows.Next() {
		var n Notification
		if err := scanNotification(rows, &n); err != nil {
			return nil, fmt.Errorf("ListNotifications scan: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListNotifications rows: %w", err)
	}
	return out, nil
}

// CountUnread returns the number of unread, non-deleted notifications for userID.
func (s *Store) CountUnread(ctx context.Context, userID int64) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM notifications
		 WHERE user_id=$1 AND deleted_at IS NULL AND read_at IS NULL`,
		userID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("CountUnread: %w", err)
	}
	return count, nil
}

// MarkNotificationsRead marks the given notification IDs as read for userID.
// Rows already read or not owned by userID are silently skipped.
func (s *Store) MarkNotificationsRead(ctx context.Context, userID int64, ids []int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE notifications
		 SET read_at = now()
		 WHERE user_id=$1 AND id = ANY($2::bigint[]) AND read_at IS NULL`,
		userID, ids,
	)
	if err != nil {
		return fmt.Errorf("MarkNotificationsRead: %w", err)
	}
	return nil
}

// MarkAllNotificationsRead marks every unread, non-deleted notification for
// userID as read.
func (s *Store) MarkAllNotificationsRead(ctx context.Context, userID int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE notifications
		 SET read_at = now()
		 WHERE user_id=$1 AND deleted_at IS NULL AND read_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("MarkAllNotificationsRead: %w", err)
	}
	return nil
}

// SetNotificationStar toggles the starred flag on a single notification owned
// by userID. Returns &NotFoundError{Entity:"notification"} when the row does
// not exist, is deleted, or belongs to a different user.
func (s *Store) SetNotificationStar(ctx context.Context, userID, id int64, starred bool) (*Notification, error) {
	const q = `
		UPDATE notifications
		SET starred=$3
		WHERE user_id=$1 AND id=$2 AND deleted_at IS NULL
		RETURNING ` + notificationColumns
	out := &Notification{}
	err := scanNotification(
		s.pool.QueryRow(ctx, q, userID, id, starred),
		out,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &NotFoundError{Entity: "notification"}
	}
	if err != nil {
		return nil, fmt.Errorf("SetNotificationStar: %w", err)
	}
	return out, nil
}

// HasRecentCertNotification reports whether a cert.expiring notification for
// the given connection was created since `since`. This is used as a dedup
// guard so the daily cert-expiry checker does not re-notify within the dedup
// window. It checks across all recipients (the fan-out creates one row per
// tenant member).
func (s *Store) HasRecentCertNotification(ctx context.Context, connID int64, since time.Time) (bool, error) {
	const q = `SELECT EXISTS(
		SELECT 1 FROM notifications
		WHERE type = 'cert.expiring'
		  AND data->>'connection_id' = $1
		  AND created_at > $2
	)`
	var exists bool
	err := s.pool.QueryRow(ctx, q, strconv.FormatInt(connID, 10), since).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("HasRecentCertNotification: %w", err)
	}
	return exists, nil
}

// SoftDeleteNotifications marks the given notification IDs as deleted for
// userID. Rows already deleted or not owned by userID are silently skipped.
func (s *Store) SoftDeleteNotifications(ctx context.Context, userID int64, ids []int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE notifications
		 SET deleted_at = now()
		 WHERE user_id=$1 AND id = ANY($2::bigint[]) AND deleted_at IS NULL`,
		userID, ids,
	)
	if err != nil {
		return fmt.Errorf("SoftDeleteNotifications: %w", err)
	}
	return nil
}
