package fakecf

import (
	"database/sql"
	"net/http"
	"strings"
	"time"

	_ "modernc.org/sqlite" // the fake D1 runs real SQLite in memory
)

type d1db struct {
	named   Named
	db      *sql.DB
	created time.Time
}

func openD1() (*sql.DB, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	// One connection forever: an in-memory database lives as long as its connection.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
	return db, db.Ping()
}

func (f *Fake) d1Obj(d *d1db) map[string]any {
	return map[string]any{"uuid": d.named.ID, "name": d.named.Name, "version": "production", "created_at": ts(d.created),
		"num_tables": 0, "file_size": 12288, "running_in_region": "WEUR", "read_replication": map[string]any{"mode": "disabled"}}
}

// lookupD1 finds a database by uuid or (as wrangler does for name-only bindings) by name.
func (f *Fake) lookupD1(key string) *d1db {
	if d := f.d1[key]; d != nil {
		return d
	}
	for _, d := range f.d1 {
		if d.named.Name == key {
			return d
		}
	}
	return nil
}

func (f *Fake) d1Routes() {
	f.handle("GET /accounts/{acct}/d1/database", func(c *call) {
		name := c.r.URL.Query().Get("name")
		items := []any{}
		for _, d := range f.d1 {
			if name != "" && d.named.Name != name {
				continue
			}
			items = append(items, f.d1Obj(d))
		}
		c.paged(items, 1000)
	})
	f.handle("GET /accounts/{acct}/d1/database/{db}", func(c *call) {
		d := f.lookupD1(c.pv("db"))
		if d == nil {
			c.err(http.StatusNotFound, 7404, "The database "+sanitizePath(c.pv("db"))+" could not be found")
			return
		}
		c.ok(f.d1Obj(d))
	})
	exec := func(raw bool) handler {
		return func(c *call) {
			d := f.d1[c.pv("db")]
			if d == nil {
				c.err(http.StatusNotFound, 7404, "The database could not be found")
				return
			}
			var in struct {
				SQL    string `json:"sql"`
				Params []any  `json:"params"`
			}
			if !c.body(&in) {
				return
			}
			stmts := splitSQL(in.SQL)
			if len(stmts) == 0 {
				c.err(http.StatusBadRequest, 7500, "No SQL statements")
				return
			}
			out := []any{}
			for i, st := range stmts {
				var params []any
				if i == len(stmts)-1 {
					params = in.Params
				}
				res, err := runStmt(d.db, st, params, raw)
				if err != nil {
					c.err(http.StatusBadRequest, 7500, sanitizePath(err.Error())+": SQLITE_ERROR")
					return
				}
				out = append(out, res)
			}
			c.ok(out)
		}
	}
	f.handle("POST /accounts/{acct}/d1/database/{db}/query", exec(false))
	f.handle("POST /accounts/{acct}/d1/database/{db}/raw", exec(true))
}

func runStmt(db *sql.DB, stmt string, params []any, raw bool) (map[string]any, error) {
	start := time.Now()
	meta := map[string]any{"served_by": "fakecf", "served_by_region": "WEUR", "changed_db": false, "changes": 0,
		"last_row_id": 0, "rows_read": 0, "rows_written": 0, "size_after": 12288}
	rows, err := db.Query(stmt, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var objs []any
	var arrs [][]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		if raw {
			arrs = append(arrs, vals)
			continue
		}
		o := map[string]any{}
		for i, col := range cols {
			o[col] = vals[i]
		}
		objs = append(objs, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	meta["rows_read"] = len(objs) + len(arrs)
	up := strings.ToUpper(strings.TrimSpace(stmt))
	if !strings.HasPrefix(up, "SELECT") && !strings.HasPrefix(up, "PRAGMA") && !strings.HasPrefix(up, "WITH") && !strings.HasPrefix(up, "EXPLAIN") {
		meta["changed_db"] = true
	}
	meta["duration"] = float64(time.Since(start).Microseconds()) / 1000
	res := map[string]any{"success": true, "meta": meta}
	if raw {
		if arrs == nil {
			arrs = [][]any{}
		}
		res["results"] = map[string]any{"columns": cols, "rows": arrs}
	} else {
		if objs == nil {
			objs = []any{}
		}
		res["results"] = objs
	}
	return res, nil
}

// splitSQL splits a script into statements on ";" outside quotes and comments (enough for
// migrations; no CREATE TRIGGER bodies).
func splitSQL(s string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'' || ch == '"' || ch == '`':
			j := i + 1
			for j < len(s) {
				if s[j] == ch {
					if j+1 < len(s) && s[j+1] == ch {
						j += 2
						continue
					}
					break
				}
				j++
			}
			cur.WriteString(s[i:min(j+1, len(s))])
			i = j
		case ch == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			cur.WriteByte('\n')
		case ch == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				i = len(s)
			} else {
				i += end + 3
			}
			cur.WriteByte(' ')
		case ch == ';':
			flush()
		default:
			cur.WriteByte(ch)
		}
	}
	flush()
	return out
}
