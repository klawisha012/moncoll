package store

import "context"

// ListConnections returns all rows from the connections table.
// The crowdsec sync uses every row (enabled or not for the registry write; it
// filters on Enabled itself when building the domain→conn map, just like the
// Python _load_connections / _build_domain_to_conn_map pair).
//
// Columns: id, tenant_id, name, domain, enabled, status.
func (s *Store) ListConnections(ctx context.Context) ([]Connection, error) {
	const q = `SELECT id, tenant_id, name, domain, enabled, status
	           FROM connections
	           ORDER BY id`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Domain, &c.Enabled, &c.Status); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
