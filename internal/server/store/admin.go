package store

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"

	"github.com/aquarat/agent-quartermaster/internal/api"
)

func (q *Q) Hosts(ctx context.Context) ([]api.HostInfo, error) {
	rows, err := q.q.QueryContext(ctx, `SELECT e.id, h.name, e.class, e.peer_address, h.created_at, e.cert_pem, h.revoked_at,
		(SELECT MAX(created_at) FROM requests WHERE host_id = h.id)
		FROM hosts h JOIN enrollments e ON e.id = h.enrollment_id ORDER BY h.name, h.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []api.HostInfo{}
	for rows.Next() {
		var h api.HostInfo
		var created int64
		var certPEM string
		var revoked, last sql.NullInt64
		if err := rows.Scan(&h.ID, &h.Name, &h.Class, &h.Address, &created, &certPEM, &revoked, &last); err != nil {
			return nil, err
		}
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return nil, fmt.Errorf("missing certificate for enrollment %s", h.ID)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		h.NotBefore, h.NotAfter = cert.NotBefore, cert.NotAfter
		h.EnrolledAt, h.RevokedAt, h.LastRequestAt = fromMS(created), fromNullMS(revoked), fromNullMS(last)
		out = append(out, h)
	}
	return out, rows.Err()
}
