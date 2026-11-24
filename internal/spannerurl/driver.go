package spannerurl

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"sync"

	spannerdriver "github.com/googleapis/go-sql-spanner"
)

// Open opens a database/sql pool on a driver connection string (DSN) with
// go-sql-spanner's driver, its connections wrapped so that a NULL of a
// bytea column reads as NULL. The driver gives it as a nil []byte, which
// database/sql reads as a value: an empty string, or a sql.NullString with
// Valid set, where Postgres's driver gives NULL. Its connections are reached
// through Conn.
func Open(dsn string) (*sql.DB, error) {
	d, err := spDriver(dsn)
	if err != nil {
		return nil, err
	}
	c, err := d.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(nullBytesConnector{c}), nil
}

// DriverName is Open's driver as database/sql registers it, for code that
// opens a pool by name (sql.Open(DriverName, dsn)).
const DriverName = "spanner-patchlog"

func init() { sql.Register(DriverName, nullBytesDriver{}) }

type nullBytesDriver struct{}

func (nullBytesDriver) Open(dsn string) (driver.Conn, error) {
	c, err := nullBytesDriver{}.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return c.Connect(context.Background())
}

func (nullBytesDriver) OpenConnector(dsn string) (driver.Connector, error) {
	d, err := spDriver(dsn)
	if err != nil {
		return nil, err
	}
	c, err := d.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return nullBytesConnector{c}, nil
}

// spDriver returns go-sql-spanner's registered driver, whose connectors
// are cached by connection string, so that pools on one database share a
// client. database/sql gives it out only from a pool opened on a valid
// connection string (dsn's), which makes no connection and is dropped.
func spDriver(dsn string) (driver.DriverContext, error) {
	spMu.Lock()
	defer spMu.Unlock()
	if spDrv == nil {
		db, err := sql.Open("spanner", dsn)
		if err != nil {
			return nil, err
		}
		spDrv = db.Driver().(driver.DriverContext)
	}
	return spDrv, nil
}

var (
	spMu  sync.Mutex
	spDrv driver.DriverContext
)

// Conn is the driver's connection under a connection of Open's (in
// sql.Conn.Raw), for what database/sql doesn't reach: mutations, DML
// batches, timestamps.
func Conn(dc any) (spannerdriver.SpannerConn, error) {
	sc, ok := dc.(spannerdriver.SpannerConn)
	if !ok {
		return nil, fmt.Errorf("not a Spanner connection: %T", dc)
	}
	return sc, nil
}

type nullBytesConnector struct{ driver.Connector }

// Close closes the driver's connector when the pool closes: its last user
// closes its client (sql.DB.Close).
func (c nullBytesConnector) Close() error {
	if cl, ok := c.Connector.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}

func (c nullBytesConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &nullBytesConn{SpannerConn: conn.(spannerdriver.SpannerConn), conn: conn}, nil
}

// nullBytesConn passes everything to the driver's connection, which
// implements every interface below, and wraps the rows it returns. It is a
// SpannerConn itself, the interface embedded with its unexported methods,
// so the driver's functions that take a *sql.Conn (RunTransaction's steps)
// find theirs.
type nullBytesConn struct {
	spannerdriver.SpannerConn
	conn driver.Conn
}

func (c *nullBytesConn) Prepare(q string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), q)
}

func (c *nullBytesConn) Close() error { return c.conn.Close() }

func (c *nullBytesConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *nullBytesConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

func (c *nullBytesConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	s, err := c.conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	return &nullBytesStmt{s}, nil
}

func (c *nullBytesConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	r, err := c.conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	return wrapRows(r, err)
}

func (c *nullBytesConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func (c *nullBytesConn) Ping(ctx context.Context) error { return c.conn.(driver.Pinger).Ping(ctx) }

func (c *nullBytesConn) ResetSession(ctx context.Context) error {
	return c.conn.(driver.SessionResetter).ResetSession(ctx)
}

func (c *nullBytesConn) IsValid() bool { return c.conn.(driver.Validator).IsValid() }

func (c *nullBytesConn) CheckNamedValue(v *driver.NamedValue) error {
	return c.conn.(driver.NamedValueChecker).CheckNamedValue(v)
}

type nullBytesStmt struct{ driver.Stmt }

func (s *nullBytesStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.Stmt.(driver.StmtExecContext).ExecContext(ctx, args)
}

func (s *nullBytesStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	r, err := s.Stmt.(driver.StmtQueryContext).QueryContext(ctx, args)
	return wrapRows(r, err)
}

func (s *nullBytesStmt) CheckNamedValue(v *driver.NamedValue) error {
	return s.Stmt.(driver.NamedValueChecker).CheckNamedValue(v)
}

func wrapRows(r driver.Rows, err error) (driver.Rows, error) {
	if err != nil {
		return nil, err
	}
	return &nullBytesRows{r}, nil
}

type nullBytesRows struct{ driver.Rows }

func (r *nullBytesRows) Next(dest []driver.Value) error {
	if err := r.Rows.Next(dest); err != nil {
		return err
	}
	for i, v := range dest {
		if b, ok := v.([]byte); ok && b == nil {
			dest[i] = nil
		}
	}
	return nil
}

func (r *nullBytesRows) HasNextResultSet() bool {
	m, ok := r.Rows.(driver.RowsNextResultSet)
	return ok && m.HasNextResultSet()
}

func (r *nullBytesRows) NextResultSet() error {
	if m, ok := r.Rows.(driver.RowsNextResultSet); ok {
		return m.NextResultSet()
	}
	return fmt.Errorf("no next result set")
}
