package core

// Compressed patch sets (Options.StoreCompression, SQLite only, off by
// default).
//
// Row format. With compression on, a patch set of revisions.patches may be
// stored as a BLOB
//
//	0x02 ‖ zstd frame of the canonical JSON
//
// (klauspost/compress, SpeedFastest, no dictionary, with the frame
// checksum). Canonical JSON never starts with a control byte, nor does an
// encrypted row (0x01, crypt.go), so the first byte tells the forms apart
// and reads handle any mix: rows from before compression was turned on or
// after it was turned off, values under StoreCompressMin, values that
// didn't shrink by an eighth, namespaces that don't compress. heads.doc and
// snapshots.doc stay canonical JSON: an import stores its bytes as
// whole-document genesis patch sets, which have no heads row (measured on
// the synthetic Demo Play bundle: 552 MB of patch sets, one 412-byte head,
// no snapshot), and compressing heads would make every uncached read of a
// small edited document pay for decompression.
//
// Policy. Only namespaces without an encryption level compress
// (compresses, the one place it is decided): the plaintext of an
// encrypted row stays canonical JSON (§E.1), sealed and e2e content is
// ciphertext already, and padded payloads are never compressed (§E.2.2).
// Turning encryption on for a namespace decompresses its rows before
// sealing them (encryptResource).
//
// Off the lock. Compression costs about as much CPU per byte as SQLite
// does to store the byte, so it pays only outside the serialised write:
// packPlan compresses a checked write's patch sets in the check phase of
// D.3, after its read transaction (checkOutside). A path without
// precomputed bytes (the whole gate in the lock, config batches, remote
// branches, restores, prunes) stores canonical JSON as before.
//
// Ids, limits and D.4's snapshot cadence are over the canonical bytes,
// computed before anything is stored; nothing hashes or serves the stored
// form.
//
// Format marker. Versions without this code read a 0x02 row as JSON and
// fail (500) on the resources that have one; nothing makes them refuse the
// database. So the first Open with compression on records it in a meta
// table (key store_compression, created then: a database that never had
// compression on is unchanged), and an Open with it off logs it.

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

// rowZstd marks a compressed stored value.
const rowZstd = 0x02

// Defaults and names of the option.
const (
	storeCompressionOff  = "off"
	storeCompressionZstd = "zstd"
	storeCompressMinDef  = 1 << 10
	metaStoreCompression = "store_compression"
)

// storeCodec is the engine's compression of stored values: an encoder when
// compression is on, and a decoder, made on first use, for compressed rows
// whatever the option.
type storeCodec struct {
	enc *zstd.Encoder // nil: compression off
	min int
	// mayHold: this database may hold compressed rows (compression is on,
	// or was once: the meta marker), which countSinceSnapshot looks for.
	mayHold bool
	// maxDecoded bounds a decoded value, so a corrupt row can't allocate
	// more: four times the largest value the deployment accepts, which
	// leaves room for a maximum lowered after values were stored.
	maxDecoded uint64
	decOnce    sync.Once
	dec        *zstd.Decoder
	decErr     error
	// onPack, if set, is called by packPlan before it compresses (tests).
	onPack func()
}

// checkStoreCompression checks the option before Open opens the database.
func checkStoreCompression(opt *Options) error {
	switch opt.StoreCompression {
	case "", storeCompressionOff:
		return nil
	case storeCompressionZstd:
		if isPostgresURL(opt.Path) {
			return errors.New("store compression is for SQLite only: Postgres compresses large values itself (TOAST)")
		}
		return nil
	}
	return fmt.Errorf("store compression %q: want %q or %q", opt.StoreCompression, storeCompressionOff, storeCompressionZstd)
}

// openStoreCodec sets up compression for an engine whose options and
// database are opened, and records or notes the format marker.
func (e *Engine) openStoreCodec() error {
	c := &e.comp
	c.maxDecoded = 4 * uint64(max(e.opt.Maximums.DocumentSize, e.opt.Maximums.PatchSetSize, e.opt.Limits.DocumentSize, e.opt.Limits.PatchSetSize))
	if e.pg {
		return nil
	}
	if e.opt.StoreCompression == storeCompressionZstd {
		c.min = e.opt.StoreCompressMin
		if c.min == 0 {
			c.min = storeCompressMinDef
		}
		enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(runtime.GOMAXPROCS(0)))
		if err != nil {
			return err
		}
		c.enc = enc
		since := time.Now().UTC().Format(time.RFC3339)
		if _, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
			return fmt.Errorf("recording store compression: %w", err)
		}
		r, err := e.db.Exec(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING`, metaStoreCompression, "zstd since "+since)
		if err != nil {
			return fmt.Errorf("recording store compression: %w", err)
		}
		if n, _ := r.RowsAffected(); n == 1 && e.opt.Path != ":memory:" {
			log.Printf("store compression on: patch sets of namespaces without encryption are stored compressed; versions of patchlog without -store-compression can no longer read this database")
		}
		c.mayHold = true
		return nil
	}
	var has bool
	if err := e.db.QueryRow(`SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta')`).Scan(&has); err != nil || !has {
		return err
	}
	var v string
	switch err := e.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaStoreCompression).Scan(&v); {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	c.mayHold = true
	log.Printf("store compression is off, but was on for this database (%s): its compressed patch sets stay compressed and readable", v)
	return nil
}

func (c *storeCodec) close() {
	if c.dec != nil {
		c.dec.Close() // DecodeAll, for good: Close again is a no-op
	}
}

// compresses reports whether the patch sets of a write into a namespace of
// encryption level level are stored compressed: only with compression on,
// and only without encryption. This is where the policy is decided.
func (e *Engine) compresses(level int) bool {
	return e.comp.enc != nil && level == levelNone
}

// pack returns the stored form of a canonical patch set, 0x02 ‖ zstd, or
// nil when it is stored as it is: under the threshold, or saving less than
// an eighth (unless the threshold is negative: tests).
func (c *storeCodec) pack(canon []byte) []byte {
	if len(canon) < c.min {
		return nil
	}
	out := make([]byte, 1, 1+len(canon)/2)
	out[0] = rowZstd
	out = c.enc.EncodeAll(canon, out)
	if c.min >= 0 && len(out) > len(canon)-len(canon)/8 {
		return nil
	}
	return out
}

// isPacked tells a compressed stored value from canonical JSON or an
// encrypted row.
func isPacked(b []byte) bool { return len(b) > 0 && b[0] == rowZstd }

func (c *storeCodec) decoder() (*zstd.Decoder, error) {
	c.decOnce.Do(func() {
		c.dec, c.decErr = zstd.NewReader(nil, zstd.WithDecoderConcurrency(runtime.GOMAXPROCS(0)), zstd.WithDecoderMaxMemory(c.maxDecoded))
	})
	return c.dec, c.decErr
}

// unpack returns the canonical JSON of a compressed stored value.
func (c *storeCodec) unpack(b []byte) ([]byte, error) {
	dec, err := c.decoder()
	if err != nil {
		return nil, err
	}
	var h zstd.Header
	if err := h.Decode(b[1:]); err != nil {
		return nil, err
	}
	// The frame's content size, which the encoder leaves out for values
	// under 256 bytes, only sizes the output; the decoder enforces the
	// bound.
	var out []byte
	if h.HasFCS && h.FrameContentSize <= c.maxDecoded {
		out = make([]byte, 0, h.FrameContentSize)
	}
	return dec.DecodeAll(b[1:], out)
}

// packedLen is the canonical length of a compressed stored value from its
// first bytes (prefix), or -1 when its frame doesn't record it.
func packedLen(prefix []byte) int64 {
	var h zstd.Header
	if !isPacked(prefix) || h.Decode(prefix[1:]) != nil || !h.HasFCS {
		return -1
	}
	return int64(h.FrameContentSize)
}

// packPlan compresses a checked write's patch sets in its check phase,
// outside the write lock (D.3); step 7 stores what it made (putPatches).
func (e *Engine) packPlan(p *writePlan) {
	if p == nil || !e.compresses(p.level) {
		return
	}
	if h := e.comp.onPack; h != nil {
		h()
	}
	for _, s := range p.st {
		for _, step := range s.steps {
			if !step.del && !step.sealed {
				step.packed = e.comp.pack(step.canon)
			}
		}
	}
}

// packedExtra is how many bytes res's compressed patch sets since its last
// snapshot add to their stored size once decompressed (countSinceSnapshot).
func (t *tx) packedExtra(res int64) int64 {
	if !t.e.comp.mayHold || t.e.pg {
		return 0
	}
	// Plaintext rows are TEXT, compressed and encrypted ones BLOBs.
	rows, err := t.Query(`SELECT seq, length(patches), substr(patches, 1, 19) FROM revisions
		WHERE res = ? AND kind = 0 AND typeof(patches) = 'blob' AND seq > (SELECT COALESCE(MAX(seq), 0) FROM snapshots WHERE res = ?)`, res, res)
	t.must(err)
	var extra int64
	var whole []int64
	for rows.Next() {
		var seq, stored int64
		var prefix []byte
		t.must(rows.Scan(&seq, &stored, &prefix))
		if !isPacked(prefix) {
			continue
		}
		if n := packedLen(prefix); n >= 0 {
			extra += n - stored
		} else {
			whole = append(whole, seq)
		}
	}
	t.must(rows.Err())
	rows.Close()
	for _, seq := range whole {
		var raw []byte
		t.must(t.QueryRow(`SELECT patches FROM revisions WHERE seq = ?`, seq).Scan(&raw))
		b, err := t.e.comp.unpack(raw)
		if err != nil {
			panic(fmt.Errorf("a compressed patch set of resource %d does not decompress: %w", res, err))
		}
		extra += int64(len(b) - len(raw))
	}
	return extra
}
