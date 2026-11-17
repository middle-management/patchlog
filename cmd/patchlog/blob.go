package main

// patchlog blob put and get: blobs of a resource (§7.8), through
// client.UploadBlob and client.GetBlob. A blob uploaded stays pending,
// visible to nobody, until a write references it: put prints the
// reference to write, or with --at writes it into the document itself.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/middle-management/patchlog/internal/client"
	"github.com/middle-management/patchlog/internal/pointer"
	"github.com/middle-management/patchlog/internal/seal"
)

// blobCmd is patchlog blob.
type blobCmd struct {
	Put *blobPutCmd `arg:"subcommand:put" help:"upload a blob of a resource, and print or write its reference"`
	Get *blobGetCmd `arg:"subcommand:get" help:"download a blob of a resource, checked against its id"`
}

type blobPutCmd struct {
	toolArgs
	gestureArgs
	Type     string `arg:"--type" placeholder:"MEDIA-TYPE" help:"the blob's media type (default: from the file's extension, else sniffed from its bytes)"`
	Nonce    bool   `arg:"--nonce" help:"upload with a random nonce (Blob-Nonce), so the blob's id reveals nothing about its bytes (§3.7, §7.8)"`
	At       string `arg:"--at" placeholder:"POINTER" help:"also write the reference into the document at this JSON Pointer (add), so the blob isn't left pending"`
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
	File     string `arg:"positional,required" placeholder:"FILE|-" help:"the bytes to upload (- for stdin)"`
}

func (a *blobPutCmd) run(string) { runClient(a) }

func (a *blobPutCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	if a.At != "" {
		if _, err := pointer.Parse(a.At); err != nil {
			return fmt.Errorf("--at: %w", err)
		}
	}
	var data []byte
	if a.File == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(a.File)
	}
	if err != nil {
		return err
	}
	typ := a.Type
	if typ == "" {
		typ = mime.TypeByExtension(filepath.Ext(a.File))
	}
	if typ == "" {
		typ = http.DetectContentType(data)
	}
	nonce := ""
	if a.Nonce {
		nonce = seal.NewNonce()
	}
	c := a.writer()
	bid, err := c.UploadBlob(ctx, ns, name, typ, nonce, data)
	if err != nil {
		return err
	}
	ref := client.BlobRef(bid, typ, len(data), nonce)
	if a.At == "" {
		fmt.Fprintf(errw, "uploaded %s to %s, pending until a write references it\n", bid, a.Resource)
		return writeJSON(out, ref)
	}
	head, err := liveHead(ctx, c, ns, name)
	if err != nil {
		return err
	}
	g, opt := a.gesture()
	p := []any{map[string]any{"op": "add", "path": a.At, "value": ref}}
	w, err := c.AppendLatest(ctx, ns, name, head, client.Backoff{}, func(string) (any, error) { return p, nil }, opt)
	if err != nil {
		return fmt.Errorf("uploaded %s, but writing its reference: %w", bid, err)
	}
	if w.Gesture == "" {
		w.Gesture = g
	}
	return a.wrote(out, errw, fmt.Sprintf("uploaded %s to %s at %s", bid, a.Resource, a.At), w.ID, w.NSID, w.Gesture)
}

type blobGetCmd struct {
	toolArgs
	At       string `arg:"--at" placeholder:"POINTER" help:"the blob the document references at this JSON Pointer (its id and nonce)"`
	Rev      string `arg:"--rev" placeholder:"ID" help:"with --at, the revision to read the reference from (default: the head)"`
	Nonce    string `arg:"--nonce" help:"with BLOB, the reference's nonce, to check the bytes against the id"`
	Out      string `arg:"-o" placeholder:"FILE" help:"write the bytes to FILE (default: stdout, unless it is a terminal)"`
	Resource string `arg:"positional,required" placeholder:"NS/NAME"`
	Blob     string `arg:"positional" help:"the blob id (or give --at)"`
}

func (a *blobGetCmd) run(string) { runClient(a) }

func (a *blobGetCmd) exec(ctx context.Context, out, errw io.Writer) error {
	ns, name, err := resourceArg(a.Resource)
	if err != nil {
		return err
	}
	if (a.Blob == "") == (a.At == "") {
		return errors.New("give BLOB or --at, not both")
	}
	c := a.client()
	bid, nonce := a.Blob, a.Nonce
	if a.At != "" {
		if bid, nonce, err = blobAt(ctx, c, ns, name, a.Rev, a.At); err != nil {
			return err
		}
	}
	if a.Out == "" && out == io.Writer(os.Stdout) && isTerminal(os.Stdout) {
		return errors.New("stdout is a terminal: give -o FILE, or redirect it")
	}
	b, err := c.GetBlob(ctx, ns, name, bid, nonce)
	if err != nil && nonce == "" && strings.Contains(err.Error(), "doesn't match its id") {
		return fmt.Errorf("%w: a blob uploaded with a nonce is checked with it (--nonce, or --at reads it from the reference)", err)
	}
	if err != nil {
		return err
	}
	if a.Out != "" {
		if err := os.WriteFile(a.Out, b.Data, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(errw, "wrote %d bytes of %s (%s) to %s\n", len(b.Data), bid, b.Type, a.Out)
		return nil
	}
	_, err = out.Write(b.Data)
	return err
}

// blobAt reads the blob reference at ptr of ns/name's document (at rev,
// else the head) and returns its id and nonce.
func blobAt(ctx context.Context, c *client.Client, ns, name, rev, ptr string) (bid, nonce string, err error) {
	p, err := pointer.Parse(ptr)
	if err != nil {
		return "", "", fmt.Errorf("--at: %w", err)
	}
	if rev == "" {
		if rev, err = liveHead(ctx, c, ns, name); err != nil {
			return "", "", err
		}
	}
	d, err := c.Doc(ctx, ns, name, rev)
	if err != nil {
		return "", "", err
	}
	v, ok := pointer.Get(d.Value, p)
	ref, _ := v.(map[string]any)
	bid, _ = ref["$blob"].(string)
	if !ok || bid == "" {
		return "", "", fmt.Errorf("%s/%s has no blob reference at %s", ns, name, ptr)
	}
	nonce, _ = ref["nonce"].(string)
	return bid, nonce, nil
}

// isTerminal reports whether f is a terminal (a character device).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
