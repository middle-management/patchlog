package seal

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ---- E1 row encryption ----

// RowVersion is the first byte of a sealed row.
const RowVersion = 0x01

// SealRow encrypts one stored value with AES-256-GCM:
//
//	row = 0x01 ‖ nonce (12 random bytes) ‖ ciphertext ‖ tag (16)
//
// aad binds the row to its place, e.g. "revisions.patches\n{seq}" or
// "{res}\n{id}", so rows can't be swapped. It panics if key is not
// KeySize bytes (a programming error).
func SealRow(key, plaintext, aad []byte) []byte {
	aead, err := newGCM(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, 1+aead.NonceSize(), 1+aead.NonceSize()+len(plaintext)+aead.Overhead())
	out[0] = RowVersion
	rand.Read(out[1:])
	return aead.Seal(out, out[1:1+aead.NonceSize()], plaintext, aad)
}

// OpenRow decrypts a row produced by SealRow with the same aad.
func OpenRow(key, row, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	n := aead.NonceSize()
	if len(row) < 1+n+aead.Overhead() || row[0] != RowVersion {
		return nil, ErrFormat
	}
	pt, err := aead.Open(nil, row[1:1+n], row[1+n:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// ---- E1 streaming file encryption (archives, bundles, backups) ----
//
// File format, version 1:
//
//	header (40 bytes) = "PLSF" ‖ 0x01 (version) ‖ log2(chunk size) (0x10) ‖ 0x00 0x00 ‖ salt (32 random bytes)
//	chunks            = chunk_0 ‖ chunk_1 ‖ … ‖ chunk_n
//	chunk_i           = AES-256-GCM(K_f, nonce_i, plaintext_i, aad_i)   (ciphertext ‖ 16-byte tag)
//
//	K_f     = HKDF-SHA256(ikm = key, salt = salt, info = "patchlog-file-v1"), 32 bytes
//	nonce_i = 0x00000000 ‖ uint64_be(i)
//	aad_i   = header ‖ final_i ‖ caller aad        (final_i = 0x01 on the last chunk, else 0x00)
//
// Every chunk but the last carries exactly chunk-size (64 KiB) plaintext
// bytes; the last carries 0…chunk-size bytes and is always present, so an
// empty file is one empty final chunk. The counter in the nonce detects
// reordering, dropping or duplicating chunks; the final flag detects
// truncation at a chunk boundary and appended data; the header in the AAD
// detects header tampering. The per-file random salt gives each file its own
// key, so nonces never repeat across files encrypted under the same key.

const (
	fileMagic      = "PLSF"
	fileVersion    = 0x01
	fileHeaderSize = 40
	fileInfo       = "patchlog-file-v1"
	// FileChunkSize is the plaintext size of every non-final chunk.
	FileChunkSize = 1 << 16
	fileLog2Chunk = 16
	gcmTag        = 16
)

// ErrTruncated reports a file whose final chunk is missing.
var ErrTruncated = errors.New("seal: file truncated")

func fileKey(key, salt []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	k, err := hkdf.Key(sha256.New, key, salt, fileInfo, KeySize)
	if err != nil {
		return nil, err
	}
	return newGCM(k)
}

func chunkNonce(i uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], i)
	return n
}

func chunkAAD(header []byte, final bool, aad []byte) []byte {
	a := make([]byte, 0, len(header)+1+len(aad))
	a = append(a, header...)
	if final {
		a = append(a, 1)
	} else {
		a = append(a, 0)
	}
	return append(a, aad...)
}

// FileWriter encrypts a stream in the format above. Close MUST be called to
// write the final chunk; it does not close the underlying writer.
type FileWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	header []byte
	aad    []byte
	buf    []byte
	n      uint64
	err    error
	closed bool
}

// NewFileWriter writes the header to w and returns a writer that encrypts
// under key, binding aad (e.g. the archive's name) to every chunk.
func NewFileWriter(w io.Writer, key, aad []byte) (*FileWriter, error) {
	header := make([]byte, fileHeaderSize)
	copy(header, fileMagic)
	header[4] = fileVersion
	header[5] = fileLog2Chunk
	rand.Read(header[8:])
	aead, err := fileKey(key, header[8:])
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(header); err != nil {
		return nil, err
	}
	return &FileWriter{w: w, aead: aead, header: header, aad: bytes.Clone(aad), buf: make([]byte, 0, FileChunkSize)}, nil
}

func (fw *FileWriter) flush(final bool) error {
	ct := fw.aead.Seal(nil, chunkNonce(fw.n), fw.buf, chunkAAD(fw.header, final, fw.aad))
	fw.n++
	fw.buf = fw.buf[:0]
	_, err := fw.w.Write(ct)
	return err
}

// Write encrypts p. A full chunk is emitted only once more data follows it,
// so the last chunk can be marked final by Close.
func (fw *FileWriter) Write(p []byte) (int, error) {
	if fw.closed {
		return 0, errors.New("seal: write after close")
	}
	if fw.err != nil {
		return 0, fw.err
	}
	n := 0
	for len(p) > 0 {
		if len(fw.buf) == FileChunkSize {
			if fw.err = fw.flush(false); fw.err != nil {
				return n, fw.err
			}
		}
		k := copy(fw.buf[len(fw.buf):FileChunkSize], p)
		fw.buf = fw.buf[:len(fw.buf)+k]
		p = p[k:]
		n += k
	}
	return n, nil
}

// Close writes the final chunk.
func (fw *FileWriter) Close() error {
	if fw.closed {
		return fw.err
	}
	fw.closed = true
	if fw.err != nil {
		return fw.err
	}
	fw.err = fw.flush(true)
	return fw.err
}

// FileReader decrypts a stream written by FileWriter. Read returns io.EOF
// only after the authenticated final chunk; any tampering, reordering or
// truncation yields ErrDecrypt, ErrTruncated or ErrFormat instead.
type FileReader struct {
	r      io.Reader
	aead   cipher.AEAD
	header []byte
	aad    []byte
	chunk  int
	in     []byte // ciphertext buffer: chunk + tag + 1 lookahead byte
	have   int    // bytes of lookahead carried over into in
	pbuf   []byte // plaintext buffer, reused
	out    []byte // unread plaintext
	n      uint64
	done   bool
	err    error
}

// NewFileReader reads and checks the header of r and returns a decrypting
// reader for key and aad.
func NewFileReader(r io.Reader, key, aad []byte) (*FileReader, error) {
	header := make([]byte, fileHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("%w: file header", ErrFormat)
	}
	if string(header[:4]) != fileMagic || header[4] != fileVersion || header[6] != 0 || header[7] != 0 ||
		header[5] < 10 || header[5] > 24 {
		return nil, fmt.Errorf("%w: file header", ErrFormat)
	}
	aead, err := fileKey(key, header[8:])
	if err != nil {
		return nil, err
	}
	chunk := 1 << header[5]
	return &FileReader{r: r, aead: aead, header: header, aad: bytes.Clone(aad), chunk: chunk,
		in: make([]byte, chunk+gcmTag+1)}, nil
}

func (fr *FileReader) next() error {
	full := fr.chunk + gcmTag
	m, err := io.ReadFull(fr.r, fr.in[fr.have:full+1])
	m += fr.have
	fr.have = 0
	var final bool
	switch {
	case err == nil: // got a full chunk plus one lookahead byte: not final
		final = false
	case err == io.ErrUnexpectedEOF || err == io.EOF:
		final = true
	default:
		return err
	}
	size := m
	if !final {
		size = full
	}
	if size < gcmTag {
		return ErrTruncated
	}
	pt, oerr := fr.aead.Open(fr.pbuf[:0], chunkNonce(fr.n), fr.in[:size], chunkAAD(fr.header, final, fr.aad))
	if oerr != nil {
		if final && size == full {
			// A full chunk followed by EOF that only authenticates as
			// non-final: the stream was cut at a chunk boundary.
			if _, e2 := fr.aead.Open(nil, chunkNonce(fr.n), fr.in[:size], chunkAAD(fr.header, false, fr.aad)); e2 == nil {
				return ErrTruncated
			}
		}
		return ErrDecrypt
	}
	fr.n++
	fr.pbuf = pt
	fr.out = pt
	if final {
		fr.done = true
	} else {
		fr.in[0] = fr.in[full]
		fr.have = 1
	}
	return nil
}

// Read implements io.Reader.
func (fr *FileReader) Read(p []byte) (int, error) {
	for len(fr.out) == 0 {
		if fr.err != nil {
			return 0, fr.err
		}
		if fr.done {
			return 0, io.EOF
		}
		if err := fr.next(); err != nil {
			fr.err = err
			return 0, err
		}
	}
	n := copy(p, fr.out)
	fr.out = fr.out[n:]
	return n, nil
}
