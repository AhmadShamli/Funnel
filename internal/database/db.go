package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AhmadShamli/Funnel/internal/models"
	_ "modernc.org/sqlite"
)

// DB wraps the SQLite database connection.
type DB struct {
	*sql.DB
}

// Open opens or creates the SQLite database at the specified path and runs migrations.
func Open(dbPath string) (*DB, error) {
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory '%s': %w", dir, err)
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// SQLite handles concurrent reads well in WAL mode, but writes must be serialized
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	database := &DB{DB: db}
	if err := database.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	return database, nil
}

// Migrate executes initial schema and index creation.
func (db *DB) Migrate(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, SchemaSQL); err != nil {
		return err
	}
	// Ensure custom_text column exists on port_groups for existing databases
	_, _ = db.ExecContext(ctx, "ALTER TABLE port_groups ADD COLUMN custom_text TEXT NOT NULL DEFAULT ''")
	return nil
}

// Helper parsing functions for SQLite string datetimes
const timeLayout = time.RFC3339

func formatTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(timeLayout, s)
}

func parseNullTime(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil
	}
	return &t
}

func formatNullTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: formatTime(*t), Valid: true}
}

// --- Admin Users ---

func (db *DB) CountAdminUsers(ctx context.Context) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admin_users").Scan(&count)
	return count, err
}

func (db *DB) CreateAdminUser(ctx context.Context, u *models.AdminUser) error {
	now := time.Now().UTC()
	u.CreatedAt = now

	res, err := db.ExecContext(ctx, `
		INSERT INTO admin_users (
			username, password_hash, role, is_active, allow_extend, max_extensions,
			valid_from, valid_until, must_change_password, failed_login_count, locked_until, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Username, u.PasswordHash, u.Role, u.IsActive, u.AllowExtend, u.MaxExtensions,
		formatNullTime(u.ValidFrom), formatNullTime(u.ValidUntil), u.MustChangePassword,
		u.FailedLoginCount, formatNullTime(u.LockedUntil), formatTime(u.CreatedAt),
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	u.ID = id
	return nil
}

func (db *DB) GetAdminUserByUsername(ctx context.Context, username string) (*models.AdminUser, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, role, is_active, allow_extend, max_extensions,
		       valid_from, valid_until, must_change_password, failed_login_count, locked_until, created_at
		FROM admin_users WHERE username = ?`, username)

	var u models.AdminUser
	var validFrom, validUntil, lockedUntil sql.NullString
	var createdAt string
	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.IsActive, &u.AllowExtend, &u.MaxExtensions,
		&validFrom, &validUntil, &u.MustChangePassword, &u.FailedLoginCount, &lockedUntil, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	u.ValidFrom = parseNullTime(validFrom)
	u.ValidUntil = parseNullTime(validUntil)
	u.LockedUntil = parseNullTime(lockedUntil)
	u.CreatedAt, _ = parseTime(createdAt)
	return &u, nil
}

func (db *DB) GetAdminUserByID(ctx context.Context, id int64) (*models.AdminUser, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, role, is_active, allow_extend, max_extensions,
		       valid_from, valid_until, must_change_password, failed_login_count, locked_until, created_at
		FROM admin_users WHERE id = ?`, id)

	var u models.AdminUser
	var validFrom, validUntil, lockedUntil sql.NullString
	var createdAt string
	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.IsActive, &u.AllowExtend, &u.MaxExtensions,
		&validFrom, &validUntil, &u.MustChangePassword, &u.FailedLoginCount, &lockedUntil, &createdAt,
	)
	if err != nil {
		return nil, err
	}
	u.ValidFrom = parseNullTime(validFrom)
	u.ValidUntil = parseNullTime(validUntil)
	u.LockedUntil = parseNullTime(lockedUntil)
	u.CreatedAt, _ = parseTime(createdAt)
	return &u, nil
}

func (db *DB) ListAdminUsers(ctx context.Context) ([]models.AdminUser, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, username, password_hash, role, is_active, allow_extend, max_extensions,
		       valid_from, valid_until, must_change_password, failed_login_count, locked_until, created_at
		FROM admin_users ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.AdminUser
	for rows.Next() {
		var u models.AdminUser
		var validFrom, validUntil, lockedUntil sql.NullString
		var createdAt string
		if err := rows.Scan(
			&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.IsActive, &u.AllowExtend, &u.MaxExtensions,
			&validFrom, &validUntil, &u.MustChangePassword, &u.FailedLoginCount, &lockedUntil, &createdAt,
		); err != nil {
			return nil, err
		}
		u.ValidFrom = parseNullTime(validFrom)
		u.ValidUntil = parseNullTime(validUntil)
		u.LockedUntil = parseNullTime(lockedUntil)
		u.CreatedAt, _ = parseTime(createdAt)
		users = append(users, u)
	}
	return users, rows.Err()
}

func (db *DB) UpdateAdminUser(ctx context.Context, u *models.AdminUser) error {
	_, err := db.ExecContext(ctx, `
		UPDATE admin_users SET
			role = ?, is_active = ?, allow_extend = ?, max_extensions = ?,
			valid_from = ?, valid_until = ?, must_change_password = ?
		WHERE id = ?`,
		u.Role, u.IsActive, u.AllowExtend, u.MaxExtensions,
		formatNullTime(u.ValidFrom), formatNullTime(u.ValidUntil), u.MustChangePassword,
		u.ID,
	)
	return err
}

func (db *DB) UpdateAdminPassword(ctx context.Context, id int64, passwordHash string) error {
	_, err := db.ExecContext(ctx, "UPDATE admin_users SET password_hash = ?, must_change_password = 0 WHERE id = ?", passwordHash, id)
	return err
}

func (db *DB) IncrementAdminFailedLogin(ctx context.Context, id int64, lockUntil *time.Time) error {
	_, err := db.ExecContext(ctx, `
		UPDATE admin_users SET
			failed_login_count = failed_login_count + 1,
			locked_until = ?
		WHERE id = ?`,
		formatNullTime(lockUntil), id,
	)
	return err
}

func (db *DB) ResetAdminFailedLogin(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, "UPDATE admin_users SET failed_login_count = 0, locked_until = NULL WHERE id = ?", id)
	return err
}

func (db *DB) LockAdminUser(ctx context.Context, id int64, lockUntil time.Time) error {
	_, err := db.ExecContext(ctx, "UPDATE admin_users SET locked_until = ? WHERE id = ?", formatTime(lockUntil), id)
	return err
}

func (db *DB) UnlockAdminUser(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, "UPDATE admin_users SET failed_login_count = 0, locked_until = NULL WHERE id = ?", id)
	return err
}

// --- Admin Sessions ---

func (db *DB) CreateAdminSession(ctx context.Context, s *models.AdminSession) error {
	now := time.Now().UTC()
	s.CreatedAt = now
	s.LastActivityAt = now

	res, err := db.ExecContext(ctx, `
		INSERT INTO admin_sessions (admin_user_id, session_token_hash, user_agent, client_ip, created_at, last_activity_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		s.AdminUserID, s.SessionTokenHash, s.UserAgent, s.ClientIP,
		formatTime(s.CreatedAt), formatTime(s.LastActivityAt), formatTime(s.ExpiresAt),
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	s.ID = id
	return nil
}

func (db *DB) GetAdminSessionByTokenHash(ctx context.Context, tokenHash string) (*models.AdminSession, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, admin_user_id, session_token_hash, user_agent, client_ip, created_at, last_activity_at, expires_at
		FROM admin_sessions WHERE session_token_hash = ?`, tokenHash)

	var s models.AdminSession
	var createdAt, lastActivity, expiresAt string
	if err := row.Scan(&s.ID, &s.AdminUserID, &s.SessionTokenHash, &s.UserAgent, &s.ClientIP, &createdAt, &lastActivity, &expiresAt); err != nil {
		return nil, err
	}
	s.CreatedAt, _ = parseTime(createdAt)
	s.LastActivityAt, _ = parseTime(lastActivity)
	s.ExpiresAt, _ = parseTime(expiresAt)
	return &s, nil
}

func (db *DB) TouchAdminSession(ctx context.Context, id int64, now time.Time) error {
	_, err := db.ExecContext(ctx, "UPDATE admin_sessions SET last_activity_at = ? WHERE id = ?", formatTime(now), id)
	return err
}

func (db *DB) DeleteAdminSession(ctx context.Context, tokenHash string) error {
	_, err := db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE session_token_hash = ?", tokenHash)
	return err
}

func (db *DB) PruneExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE expires_at <= ?", formatTime(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Port Groups & Ports ---

func (db *DB) CreatePortGroup(ctx context.Context, pg *models.PortGroup) error {
	res, err := db.ExecContext(ctx, `
		INSERT INTO port_groups (
			name, description, custom_text, availability_mode, allow_extend, max_extensions,
			grant_duration_seconds, max_duration_seconds, valid_from, valid_until,
			network_match_mode, is_active
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		pg.Name, pg.Description, pg.CustomText, pg.AvailabilityMode, pg.AllowExtend, pg.MaxExtensions,
		pg.GrantDurationSeconds, pg.MaxDurationSeconds, formatNullTime(pg.ValidFrom),
		formatNullTime(pg.ValidUntil), pg.NetworkMatchMode, pg.IsActive,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	pg.ID = id

	// Insert ports
	for _, port := range pg.Ports {
		_, err := db.ExecContext(ctx, "INSERT OR IGNORE INTO port_group_ports (port_group_id, protocol, port) VALUES (?, ?, ?)",
			pg.ID, port.Protocol, port.Port)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) GetPortGroupByID(ctx context.Context, id int64) (*models.PortGroup, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, name, description, custom_text, availability_mode, allow_extend, max_extensions,
		       grant_duration_seconds, max_duration_seconds, valid_from, valid_until,
		       network_match_mode, is_active
		FROM port_groups WHERE id = ?`, id)

	var pg models.PortGroup
	var validFrom, validUntil sql.NullString
	if err := row.Scan(
		&pg.ID, &pg.Name, &pg.Description, &pg.CustomText, &pg.AvailabilityMode, &pg.AllowExtend, &pg.MaxExtensions,
		&pg.GrantDurationSeconds, &pg.MaxDurationSeconds, &validFrom, &validUntil,
		&pg.NetworkMatchMode, &pg.IsActive,
	); err != nil {
		return nil, err
	}
	pg.ValidFrom = parseNullTime(validFrom)
	pg.ValidUntil = parseNullTime(validUntil)

	ports, err := db.GetPortGroupPorts(ctx, pg.ID)
	if err != nil {
		return nil, err
	}
	pg.Ports = ports
	return &pg, nil
}

func (db *DB) ListPortGroups(ctx context.Context) ([]models.PortGroup, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, description, custom_text, availability_mode, allow_extend, max_extensions,
		       grant_duration_seconds, max_duration_seconds, valid_from, valid_until,
		       network_match_mode, is_active
		FROM port_groups ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []models.PortGroup
	for rows.Next() {
		var pg models.PortGroup
		var validFrom, validUntil sql.NullString
		if err := rows.Scan(
			&pg.ID, &pg.Name, &pg.Description, &pg.CustomText, &pg.AvailabilityMode, &pg.AllowExtend, &pg.MaxExtensions,
			&pg.GrantDurationSeconds, &pg.MaxDurationSeconds, &validFrom, &validUntil,
			&pg.NetworkMatchMode, &pg.IsActive,
		); err != nil {
			return nil, err
		}
		pg.ValidFrom = parseNullTime(validFrom)
		pg.ValidUntil = parseNullTime(validUntil)
		groups = append(groups, pg)
	}

	for i := range groups {
		ports, err := db.GetPortGroupPorts(ctx, groups[i].ID)
		if err != nil {
			return nil, err
		}
		groups[i].Ports = ports
	}

	return groups, rows.Err()
}

func (db *DB) UpdatePortGroup(ctx context.Context, pg *models.PortGroup) error {
	_, err := db.ExecContext(ctx, `
		UPDATE port_groups SET
			name = ?, description = ?, custom_text = ?, availability_mode = ?, allow_extend = ?,
			max_extensions = ?, grant_duration_seconds = ?, max_duration_seconds = ?,
			valid_from = ?, valid_until = ?, network_match_mode = ?, is_active = ?
		WHERE id = ?`,
		pg.Name, pg.Description, pg.CustomText, pg.AvailabilityMode, pg.AllowExtend,
		pg.MaxExtensions, pg.GrantDurationSeconds, pg.MaxDurationSeconds,
		formatNullTime(pg.ValidFrom), formatNullTime(pg.ValidUntil),
		pg.NetworkMatchMode, pg.IsActive, pg.ID,
	)
	if err != nil {
		return err
	}

	// Update ports
	_, err = db.ExecContext(ctx, "DELETE FROM port_group_ports WHERE port_group_id = ?", pg.ID)
	if err != nil {
		return err
	}
	for _, port := range pg.Ports {
		_, err = db.ExecContext(ctx, "INSERT OR IGNORE INTO port_group_ports (port_group_id, protocol, port) VALUES (?, ?, ?)",
			pg.ID, port.Protocol, port.Port)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) DeletePortGroup(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, "DELETE FROM port_groups WHERE id = ?", id)
	return err
}

func (db *DB) GetPortGroupPorts(ctx context.Context, portGroupID int64) ([]models.PortRule, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, port_group_id, protocol, port FROM port_group_ports WHERE port_group_id = ? ORDER BY port ASC", portGroupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []models.PortRule
	for rows.Next() {
		var p models.PortRule
		if err := rows.Scan(&p.ID, &p.PortGroupID, &p.Protocol, &p.Port); err != nil {
			return nil, err
		}
		ports = append(ports, p)
	}
	return ports, rows.Err()
}

// --- Access Keys ---

func (db *DB) CreateAccessKey(ctx context.Context, k *models.AccessKey) error {
	res, err := db.ExecContext(ctx, `
		INSERT INTO access_keys (
			name, password_hash, is_active, allow_extend, max_extensions,
			max_concurrent_ips, max_total_uses, use_count, max_duration_seconds,
			valid_from, valid_until, last_used_at, created_by_admin_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.Name, k.PasswordHash, k.IsActive, k.AllowExtend, k.MaxExtensions,
		k.MaxConcurrentIPs, k.MaxTotalUses, k.UseCount, k.MaxDurationSeconds,
		formatNullTime(k.ValidFrom), formatNullTime(k.ValidUntil), formatNullTime(k.LastUsedAt),
		k.CreatedByAdminID,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	k.ID = id

	// Map port groups
	for _, pgID := range k.PortGroupIDs {
		_, err := db.ExecContext(ctx, "INSERT OR IGNORE INTO access_key_port_groups (access_key_id, port_group_id) VALUES (?, ?)", k.ID, pgID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) GetAccessKeyByID(ctx context.Context, id int64) (*models.AccessKey, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, name, password_hash, is_active, allow_extend, max_extensions,
		       max_concurrent_ips, max_total_uses, use_count, max_duration_seconds,
		       valid_from, valid_until, last_used_at, created_by_admin_id
		FROM access_keys WHERE id = ?`, id)

	var k models.AccessKey
	var validFrom, validUntil, lastUsedAt sql.NullString
	if err := row.Scan(
		&k.ID, &k.Name, &k.PasswordHash, &k.IsActive, &k.AllowExtend, &k.MaxExtensions,
		&k.MaxConcurrentIPs, &k.MaxTotalUses, &k.UseCount, &k.MaxDurationSeconds,
		&validFrom, &validUntil, &lastUsedAt, &k.CreatedByAdminID,
	); err != nil {
		return nil, err
	}
	k.ValidFrom = parseNullTime(validFrom)
	k.ValidUntil = parseNullTime(validUntil)
	k.LastUsedAt = parseNullTime(lastUsedAt)

	pgs, err := db.GetAccessKeyPortGroups(ctx, k.ID)
	if err != nil {
		return nil, err
	}
	k.PortGroups = pgs
	for _, pg := range pgs {
		k.PortGroupIDs = append(k.PortGroupIDs, pg.ID)
	}

	return &k, nil
}

func (db *DB) GetAccessKeyByPasswordHash(ctx context.Context, passwordHash string) (*models.AccessKey, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, name, password_hash, is_active, allow_extend, max_extensions,
		       max_concurrent_ips, max_total_uses, use_count, max_duration_seconds,
		       valid_from, valid_until, last_used_at, created_by_admin_id
		FROM access_keys WHERE password_hash = ? AND is_active = 1`, passwordHash)

	var k models.AccessKey
	var validFrom, validUntil, lastUsedAt sql.NullString
	if err := row.Scan(
		&k.ID, &k.Name, &k.PasswordHash, &k.IsActive, &k.AllowExtend, &k.MaxExtensions,
		&k.MaxConcurrentIPs, &k.MaxTotalUses, &k.UseCount, &k.MaxDurationSeconds,
		&validFrom, &validUntil, &lastUsedAt, &k.CreatedByAdminID,
	); err != nil {
		return nil, err
	}
	k.ValidFrom = parseNullTime(validFrom)
	k.ValidUntil = parseNullTime(validUntil)
	k.LastUsedAt = parseNullTime(lastUsedAt)

	pgs, err := db.GetAccessKeyPortGroups(ctx, k.ID)
	if err != nil {
		return nil, err
	}
	k.PortGroups = pgs
	for _, pg := range pgs {
		k.PortGroupIDs = append(k.PortGroupIDs, pg.ID)
	}

	return &k, nil
}

func (db *DB) ListAccessKeys(ctx context.Context) ([]models.AccessKey, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, password_hash, is_active, allow_extend, max_extensions,
		       max_concurrent_ips, max_total_uses, use_count, max_duration_seconds,
		       valid_from, valid_until, last_used_at, created_by_admin_id
		FROM access_keys ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []models.AccessKey
	for rows.Next() {
		var k models.AccessKey
		var validFrom, validUntil, lastUsedAt sql.NullString
		if err := rows.Scan(
			&k.ID, &k.Name, &k.PasswordHash, &k.IsActive, &k.AllowExtend, &k.MaxExtensions,
			&k.MaxConcurrentIPs, &k.MaxTotalUses, &k.UseCount, &k.MaxDurationSeconds,
			&validFrom, &validUntil, &lastUsedAt, &k.CreatedByAdminID,
		); err != nil {
			return nil, err
		}
		k.ValidFrom = parseNullTime(validFrom)
		k.ValidUntil = parseNullTime(validUntil)
		k.LastUsedAt = parseNullTime(lastUsedAt)
		keys = append(keys, k)
	}

	for i := range keys {
		pgs, err := db.GetAccessKeyPortGroups(ctx, keys[i].ID)
		if err != nil {
			return nil, err
		}
		keys[i].PortGroups = pgs
		for _, pg := range pgs {
			keys[i].PortGroupIDs = append(keys[i].PortGroupIDs, pg.ID)
		}
	}

	return keys, rows.Err()
}

func (db *DB) UpdateAccessKey(ctx context.Context, k *models.AccessKey) error {
	_, err := db.ExecContext(ctx, `
		UPDATE access_keys SET
			name = ?, is_active = ?, allow_extend = ?, max_extensions = ?,
			max_concurrent_ips = ?, max_total_uses = ?, max_duration_seconds = ?,
			valid_from = ?, valid_until = ?
		WHERE id = ?`,
		k.Name, k.IsActive, k.AllowExtend, k.MaxExtensions,
		k.MaxConcurrentIPs, k.MaxTotalUses, k.MaxDurationSeconds,
		formatNullTime(k.ValidFrom), formatNullTime(k.ValidUntil), k.ID,
	)
	if err != nil {
		return err
	}

	if k.PasswordHash != "" {
		if _, err := db.ExecContext(ctx, "UPDATE access_keys SET password_hash = ? WHERE id = ?", k.PasswordHash, k.ID); err != nil {
			return err
		}
	}

	// Update port group mappings
	if _, err := db.ExecContext(ctx, "DELETE FROM access_key_port_groups WHERE access_key_id = ?", k.ID); err != nil {
		return err
	}
	for _, pgID := range k.PortGroupIDs {
		if _, err := db.ExecContext(ctx, "INSERT OR IGNORE INTO access_key_port_groups (access_key_id, port_group_id) VALUES (?, ?)", k.ID, pgID); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) IncrementAccessKeyUse(ctx context.Context, id int64, now time.Time) error {
	_, err := db.ExecContext(ctx, "UPDATE access_keys SET use_count = use_count + 1, last_used_at = ? WHERE id = ?", formatTime(now), id)
	return err
}

func (db *DB) DeleteAccessKey(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, "DELETE FROM access_keys WHERE id = ?", id)
	return err
}

func (db *DB) GetAccessKeyPortGroups(ctx context.Context, accessKeyID int64) ([]models.PortGroup, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT pg.id, pg.name, pg.description, pg.custom_text, pg.availability_mode, pg.allow_extend, pg.max_extensions,
		       pg.grant_duration_seconds, pg.max_duration_seconds, pg.valid_from, pg.valid_until,
		       pg.network_match_mode, pg.is_active
		FROM port_groups pg
		JOIN access_key_port_groups akpg ON pg.id = akpg.port_group_id
		WHERE akpg.access_key_id = ? AND pg.is_active = 1`, accessKeyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []models.PortGroup
	for rows.Next() {
		var pg models.PortGroup
		var validFrom, validUntil sql.NullString
		if err := rows.Scan(
			&pg.ID, &pg.Name, &pg.Description, &pg.CustomText, &pg.AvailabilityMode, &pg.AllowExtend, &pg.MaxExtensions,
			&pg.GrantDurationSeconds, &pg.MaxDurationSeconds, &validFrom, &validUntil,
			&pg.NetworkMatchMode, &pg.IsActive,
		); err != nil {
			return nil, err
		}
		pg.ValidFrom = parseNullTime(validFrom)
		pg.ValidUntil = parseNullTime(validUntil)
		groups = append(groups, pg)
	}

	for i := range groups {
		ports, err := db.GetPortGroupPorts(ctx, groups[i].ID)
		if err != nil {
			return nil, err
		}
		groups[i].Ports = ports
	}

	return groups, rows.Err()
}

// --- Allowed Networks ---

func (db *DB) CreateAllowedNetwork(ctx context.Context, an *models.AllowedNetwork) error {
	res, err := db.ExecContext(ctx, `
		INSERT INTO allowed_networks (
			name, network_cidr, mode, scope, allow_extend, max_extensions,
			valid_from, valid_until, access_key_id, grant_duration_seconds, is_active
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		an.Name, an.NetworkCIDR, an.Mode, an.Scope, an.AllowExtend, an.MaxExtensions,
		formatNullTime(an.ValidFrom), formatNullTime(an.ValidUntil), an.AccessKeyID,
		an.GrantDurationSeconds, an.IsActive,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	an.ID = id

	for _, pgID := range an.PortGroupIDs {
		_, err := db.ExecContext(ctx, "INSERT OR IGNORE INTO allowed_network_port_groups (allowed_network_id, port_group_id) VALUES (?, ?)", an.ID, pgID)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) GetAllowedNetworkByID(ctx context.Context, id int64) (*models.AllowedNetwork, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, name, network_cidr, mode, scope, allow_extend, max_extensions,
		       valid_from, valid_until, access_key_id, grant_duration_seconds, is_active
		FROM allowed_networks WHERE id = ?`, id)

	var an models.AllowedNetwork
	var validFrom, validUntil sql.NullString
	if err := row.Scan(
		&an.ID, &an.Name, &an.NetworkCIDR, &an.Mode, &an.Scope, &an.AllowExtend, &an.MaxExtensions,
		&validFrom, &validUntil, &an.AccessKeyID, &an.GrantDurationSeconds, &an.IsActive,
	); err != nil {
		return nil, err
	}
	an.ValidFrom = parseNullTime(validFrom)
	an.ValidUntil = parseNullTime(validUntil)

	pgs, err := db.GetAllowedNetworkPortGroups(ctx, an.ID)
	if err != nil {
		return nil, err
	}
	an.PortGroups = pgs
	for _, pg := range pgs {
		an.PortGroupIDs = append(an.PortGroupIDs, pg.ID)
	}

	return &an, nil
}

func (db *DB) ListAllowedNetworks(ctx context.Context) ([]models.AllowedNetwork, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, name, network_cidr, mode, scope, allow_extend, max_extensions,
		       valid_from, valid_until, access_key_id, grant_duration_seconds, is_active
		FROM allowed_networks ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []models.AllowedNetwork
	for rows.Next() {
		var an models.AllowedNetwork
		var validFrom, validUntil sql.NullString
		if err := rows.Scan(
			&an.ID, &an.Name, &an.NetworkCIDR, &an.Mode, &an.Scope, &an.AllowExtend, &an.MaxExtensions,
			&validFrom, &validUntil, &an.AccessKeyID, &an.GrantDurationSeconds, &an.IsActive,
		); err != nil {
			return nil, err
		}
		an.ValidFrom = parseNullTime(validFrom)
		an.ValidUntil = parseNullTime(validUntil)
		networks = append(networks, an)
	}

	for i := range networks {
		pgs, err := db.GetAllowedNetworkPortGroups(ctx, networks[i].ID)
		if err != nil {
			return nil, err
		}
		networks[i].PortGroups = pgs
		for _, pg := range pgs {
			networks[i].PortGroupIDs = append(networks[i].PortGroupIDs, pg.ID)
		}
	}

	return networks, rows.Err()
}

func (db *DB) UpdateAllowedNetwork(ctx context.Context, an *models.AllowedNetwork) error {
	_, err := db.ExecContext(ctx, `
		UPDATE allowed_networks SET
			name = ?, network_cidr = ?, mode = ?, scope = ?, allow_extend = ?,
			max_extensions = ?, valid_from = ?, valid_until = ?, access_key_id = ?,
			grant_duration_seconds = ?, is_active = ?
		WHERE id = ?`,
		an.Name, an.NetworkCIDR, an.Mode, an.Scope, an.AllowExtend,
		an.MaxExtensions, formatNullTime(an.ValidFrom), formatNullTime(an.ValidUntil),
		an.AccessKeyID, an.GrantDurationSeconds, an.IsActive, an.ID,
	)
	if err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx, "DELETE FROM allowed_network_port_groups WHERE allowed_network_id = ?", an.ID); err != nil {
		return err
	}
	for _, pgID := range an.PortGroupIDs {
		if _, err := db.ExecContext(ctx, "INSERT OR IGNORE INTO allowed_network_port_groups (allowed_network_id, port_group_id) VALUES (?, ?)", an.ID, pgID); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) DeleteAllowedNetwork(ctx context.Context, id int64) error {
	_, err := db.ExecContext(ctx, "DELETE FROM allowed_networks WHERE id = ?", id)
	return err
}

func (db *DB) GetAllowedNetworkPortGroups(ctx context.Context, allowedNetworkID int64) ([]models.PortGroup, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT pg.id, pg.name, pg.description, pg.custom_text, pg.availability_mode, pg.allow_extend, pg.max_extensions,
		       pg.grant_duration_seconds, pg.max_duration_seconds, pg.valid_from, pg.valid_until,
		       pg.network_match_mode, pg.is_active
		FROM port_groups pg
		JOIN allowed_network_port_groups anpg ON pg.id = anpg.port_group_id
		WHERE anpg.allowed_network_id = ? AND pg.is_active = 1`, allowedNetworkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []models.PortGroup
	for rows.Next() {
		var pg models.PortGroup
		var validFrom, validUntil sql.NullString
		if err := rows.Scan(
			&pg.ID, &pg.Name, &pg.Description, &pg.CustomText, &pg.AvailabilityMode, &pg.AllowExtend, &pg.MaxExtensions,
			&pg.GrantDurationSeconds, &pg.MaxDurationSeconds, &validFrom, &validUntil,
			&pg.NetworkMatchMode, &pg.IsActive,
		); err != nil {
			return nil, err
		}
		pg.ValidFrom = parseNullTime(validFrom)
		pg.ValidUntil = parseNullTime(validUntil)
		groups = append(groups, pg)
	}

	for i := range groups {
		ports, err := db.GetPortGroupPorts(ctx, groups[i].ID)
		if err != nil {
			return nil, err
		}
		groups[i].Ports = ports
	}

	return groups, rows.Err()
}

// --- Access Grants ---

func (db *DB) CreateAccessGrant(ctx context.Context, g *models.AccessGrant) error {
	res, err := db.ExecContext(ctx, `
		INSERT INTO access_grants (
			access_key_id, allowed_network_id, grant_source, source_ip, ipv6_prefix_length,
			extension_count, status, visitor_token_hash, granted_at, expires_at, revoked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.AccessKeyID, g.AllowedNetworkID, g.GrantSource, g.SourceIP, g.IPv6PrefixLength,
		g.ExtensionCount, g.Status, g.VisitorTokenHash,
		formatTime(g.GrantedAt), formatTime(g.ExpiresAt), formatNullTime(g.RevokedAt),
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	g.ID = id

	for _, port := range g.Ports {
		_, err := db.ExecContext(ctx, "INSERT OR IGNORE INTO access_grant_ports (access_grant_id, protocol, port) VALUES (?, ?, ?)",
			g.ID, port.Protocol, port.Port)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) GetAccessGrantByID(ctx context.Context, id int64) (*models.AccessGrant, error) {
	row := db.QueryRowContext(ctx, `
		SELECT g.id, g.access_key_id, g.allowed_network_id, g.grant_source, g.source_ip, g.ipv6_prefix_length,
		       g.extension_count, g.status, g.visitor_token_hash, g.granted_at, g.expires_at, g.revoked_at,
		       COALESCE(k.name, '') as key_name, COALESCE(an.name, '') as network_name
		FROM access_grants g
		LEFT JOIN access_keys k ON g.access_key_id = k.id
		LEFT JOIN allowed_networks an ON g.allowed_network_id = an.id
		WHERE g.id = ?`, id)

	var g models.AccessGrant
	var grantedAt, expiresAt string
	var revokedAt sql.NullString
	if err := row.Scan(
		&g.ID, &g.AccessKeyID, &g.AllowedNetworkID, &g.GrantSource, &g.SourceIP, &g.IPv6PrefixLength,
		&g.ExtensionCount, &g.Status, &g.VisitorTokenHash, &grantedAt, &expiresAt, &revokedAt,
		&g.AccessKeyName, &g.AllowedNetworkName,
	); err != nil {
		return nil, err
	}
	g.GrantedAt, _ = parseTime(grantedAt)
	g.ExpiresAt, _ = parseTime(expiresAt)
	g.RevokedAt = parseNullTime(revokedAt)

	ports, err := db.GetAccessGrantPorts(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	g.Ports = ports
	return &g, nil
}

func (db *DB) GetAccessGrantByTokenHash(ctx context.Context, tokenHash string) (*models.AccessGrant, error) {
	row := db.QueryRowContext(ctx, `
		SELECT g.id, g.access_key_id, g.allowed_network_id, g.grant_source, g.source_ip, g.ipv6_prefix_length,
		       g.extension_count, g.status, g.visitor_token_hash, g.granted_at, g.expires_at, g.revoked_at,
		       COALESCE(k.name, '') as key_name, COALESCE(an.name, '') as network_name
		FROM access_grants g
		LEFT JOIN access_keys k ON g.access_key_id = k.id
		LEFT JOIN allowed_networks an ON g.allowed_network_id = an.id
		WHERE g.visitor_token_hash = ?`, tokenHash)

	var g models.AccessGrant
	var grantedAt, expiresAt string
	var revokedAt sql.NullString
	if err := row.Scan(
		&g.ID, &g.AccessKeyID, &g.AllowedNetworkID, &g.GrantSource, &g.SourceIP, &g.IPv6PrefixLength,
		&g.ExtensionCount, &g.Status, &g.VisitorTokenHash, &grantedAt, &expiresAt, &revokedAt,
		&g.AccessKeyName, &g.AllowedNetworkName,
	); err != nil {
		return nil, err
	}
	g.GrantedAt, _ = parseTime(grantedAt)
	g.ExpiresAt, _ = parseTime(expiresAt)
	g.RevokedAt = parseNullTime(revokedAt)

	ports, err := db.GetAccessGrantPorts(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	g.Ports = ports
	return &g, nil
}

func (db *DB) GetAccessGrantPorts(ctx context.Context, grantID int64) ([]models.PortRule, error) {
	rows, err := db.QueryContext(ctx, "SELECT id, protocol, port FROM access_grant_ports WHERE access_grant_id = ? ORDER BY port ASC", grantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ports []models.PortRule
	for rows.Next() {
		var p models.PortRule
		if err := rows.Scan(&p.ID, &p.Protocol, &p.Port); err != nil {
			return nil, err
		}
		ports = append(ports, p)
	}
	return ports, rows.Err()
}

func (db *DB) ListActiveGrantsByIP(ctx context.Context, ip string, now time.Time) ([]models.AccessGrant, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT g.id, g.access_key_id, g.allowed_network_id, g.grant_source, g.source_ip, g.ipv6_prefix_length,
		       g.extension_count, g.status, g.visitor_token_hash, g.granted_at, g.expires_at, g.revoked_at,
		       COALESCE(k.name, '') as key_name, COALESCE(an.name, '') as network_name
		FROM access_grants g
		LEFT JOIN access_keys k ON g.access_key_id = k.id
		LEFT JOIN allowed_networks an ON g.allowed_network_id = an.id
		WHERE g.source_ip = ? AND g.status = 'active' AND g.expires_at > ?
		ORDER BY g.id ASC`, ip, formatTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []models.AccessGrant
	for rows.Next() {
		var g models.AccessGrant
		var grantedAt, expiresAt string
		var revokedAt sql.NullString
		if err := rows.Scan(
			&g.ID, &g.AccessKeyID, &g.AllowedNetworkID, &g.GrantSource, &g.SourceIP, &g.IPv6PrefixLength,
			&g.ExtensionCount, &g.Status, &g.VisitorTokenHash, &grantedAt, &expiresAt, &revokedAt,
			&g.AccessKeyName, &g.AllowedNetworkName,
		); err != nil {
			return nil, err
		}
		g.GrantedAt, _ = parseTime(grantedAt)
		g.ExpiresAt, _ = parseTime(expiresAt)
		g.RevokedAt = parseNullTime(revokedAt)
		grants = append(grants, g)
	}

	for i := range grants {
		ports, err := db.GetAccessGrantPorts(ctx, grants[i].ID)
		if err != nil {
			return nil, err
		}
		grants[i].Ports = ports
	}

	return grants, rows.Err()
}

func (db *DB) ListActiveGrantsAll(ctx context.Context, now time.Time) ([]models.AccessGrant, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT g.id, g.access_key_id, g.allowed_network_id, g.grant_source, g.source_ip, g.ipv6_prefix_length,
		       g.extension_count, g.status, g.visitor_token_hash, g.granted_at, g.expires_at, g.revoked_at,
		       COALESCE(k.name, '') as key_name, COALESCE(an.name, '') as network_name
		FROM access_grants g
		LEFT JOIN access_keys k ON g.access_key_id = k.id
		LEFT JOIN allowed_networks an ON g.allowed_network_id = an.id
		WHERE g.status = 'active' AND g.expires_at > ?
		ORDER BY g.id ASC`, formatTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []models.AccessGrant
	for rows.Next() {
		var g models.AccessGrant
		var grantedAt, expiresAt string
		var revokedAt sql.NullString
		if err := rows.Scan(
			&g.ID, &g.AccessKeyID, &g.AllowedNetworkID, &g.GrantSource, &g.SourceIP, &g.IPv6PrefixLength,
			&g.ExtensionCount, &g.Status, &g.VisitorTokenHash, &grantedAt, &expiresAt, &revokedAt,
			&g.AccessKeyName, &g.AllowedNetworkName,
		); err != nil {
			return nil, err
		}
		g.GrantedAt, _ = parseTime(grantedAt)
		g.ExpiresAt, _ = parseTime(expiresAt)
		g.RevokedAt = parseNullTime(revokedAt)
		grants = append(grants, g)
	}

	for i := range grants {
		ports, err := db.GetAccessGrantPorts(ctx, grants[i].ID)
		if err != nil {
			return nil, err
		}
		grants[i].Ports = ports
	}

	return grants, rows.Err()
}

func (db *DB) ListGrants(ctx context.Context, status string, limit, offset int) ([]models.AccessGrant, error) {
	query := `
		SELECT g.id, g.access_key_id, g.allowed_network_id, g.grant_source, g.source_ip, g.ipv6_prefix_length,
		       g.extension_count, g.status, g.visitor_token_hash, g.granted_at, g.expires_at, g.revoked_at,
		       COALESCE(k.name, '') as key_name, COALESCE(an.name, '') as network_name
		FROM access_grants g
		LEFT JOIN access_keys k ON g.access_key_id = k.id
		LEFT JOIN allowed_networks an ON g.allowed_network_id = an.id`

	var args []interface{}
	if status != "" {
		query += " WHERE g.status = ?"
		args = append(args, status)
	}
	query += " ORDER BY g.id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []models.AccessGrant
	for rows.Next() {
		var g models.AccessGrant
		var grantedAt, expiresAt string
		var revokedAt sql.NullString
		if err := rows.Scan(
			&g.ID, &g.AccessKeyID, &g.AllowedNetworkID, &g.GrantSource, &g.SourceIP, &g.IPv6PrefixLength,
			&g.ExtensionCount, &g.Status, &g.VisitorTokenHash, &grantedAt, &expiresAt, &revokedAt,
			&g.AccessKeyName, &g.AllowedNetworkName,
		); err != nil {
			return nil, err
		}
		g.GrantedAt, _ = parseTime(grantedAt)
		g.ExpiresAt, _ = parseTime(expiresAt)
		g.RevokedAt = parseNullTime(revokedAt)
		grants = append(grants, g)
	}

	for i := range grants {
		ports, err := db.GetAccessGrantPorts(ctx, grants[i].ID)
		if err != nil {
			return nil, err
		}
		grants[i].Ports = ports
	}

	return grants, rows.Err()
}

func (db *DB) CountActiveGrantsByAccessKeyID(ctx context.Context, accessKeyID int64, now time.Time) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT source_ip)
		FROM access_grants
		WHERE access_key_id = ? AND status = 'active' AND expires_at > ?`,
		accessKeyID, formatTime(now),
	).Scan(&count)
	return count, err
}

func (db *DB) RevokeGrant(ctx context.Context, id int64, now time.Time) error {
	_, err := db.ExecContext(ctx, "UPDATE access_grants SET status = 'revoked', revoked_at = ? WHERE id = ?", formatTime(now), id)
	return err
}

func (db *DB) ExtendGrant(ctx context.Context, id int64, newExpiresAt time.Time) error {
	_, err := db.ExecContext(ctx, `
		UPDATE access_grants SET
			extension_count = extension_count + 1,
			expires_at = ?
		WHERE id = ?`, formatTime(newExpiresAt), id)
	return err
}

func (db *DB) ExpireOldGrants(ctx context.Context, now time.Time) ([]models.AccessGrant, error) {
	// First select the grants that need expiring
	rows, err := db.QueryContext(ctx, `
		SELECT id, source_ip FROM access_grants WHERE status = 'active' AND expires_at <= ?`, formatTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var expiredGrants []models.AccessGrant
	for rows.Next() {
		var g models.AccessGrant
		if err := rows.Scan(&g.ID, &g.SourceIP); err != nil {
			return nil, err
		}
		expiredGrants = append(expiredGrants, g)
	}

	if len(expiredGrants) > 0 {
		_, err = db.ExecContext(ctx, "UPDATE access_grants SET status = 'expired' WHERE status = 'active' AND expires_at <= ?", formatTime(now))
		if err != nil {
			return nil, err
		}
		for i := range expiredGrants {
			ports, _ := db.GetAccessGrantPorts(ctx, expiredGrants[i].ID)
			expiredGrants[i].Ports = ports
		}
	}

	return expiredGrants, nil
}

// --- Audit Events ---

func (db *DB) RecordAuditEvent(ctx context.Context, e *models.AuditEvent) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}

	res, err := db.ExecContext(ctx, `
		INSERT INTO audit_events (event_type, actor_type, actor_identifier, target_ip, details_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		e.EventType, e.ActorType, e.ActorIdentifier, e.TargetIP, e.DetailsJSON, formatTime(e.CreatedAt),
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	e.ID = id
	return nil
}

func (db *DB) ListAuditEvents(ctx context.Context, eventType string, limit, offset int) ([]models.AuditEvent, error) {
	query := "SELECT id, event_type, actor_type, actor_identifier, target_ip, details_json, created_at FROM audit_events"
	var args []interface{}
	if eventType != "" {
		query += " WHERE event_type = ?"
		args = append(args, eventType)
	}
	query += " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.AuditEvent
	for rows.Next() {
		var e models.AuditEvent
		var createdAt string
		if err := rows.Scan(&e.ID, &e.EventType, &e.ActorType, &e.ActorIdentifier, &e.TargetIP, &e.DetailsJSON, &createdAt); err != nil {
			return nil, err
		}
		e.CreatedAt, _ = parseTime(createdAt)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (db *DB) PruneAuditEvents(ctx context.Context, olderThan time.Time) (int64, error) {
	res, err := db.ExecContext(ctx, "DELETE FROM audit_events WHERE created_at < ?", formatTime(olderThan))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
