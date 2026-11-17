package main

// patchlog blob put and get: blobs of a resource (§7.8), through
// client.UploadBlob and client.GetBlob. A blob uploaded stays pending,
// visible to nobody, until a write references it: put prints the
// reference to write, or with --at writes it into the document itself.
//
// In encrypted namespaces (encrypted.go) a blob is read through its
// reference in the document (--at, client.GetBlobRef): a sealed
// namespace's are sealed for delivery, opened with the namespace's keys,
// and uploaded with a nonce (§E.2.2); an e2e namespace's are encrypted by
// the client under a key of their own that the reference carries
// (E2E.UploadBlob, §E.3.1), so a reference written elsewhere than with
// --at must go into the document with patch --identity.

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
	encArgs
	gestureArgs
	Type     string `arg:"--type" placeholder:"MEDIA-TYPE" help:"the blob's media type (default: from the file's extension, else sniffed from its bytes)"`
	Nonce    bool   `arg:"--nonce" help:"upload with a random nonce (Blob-Nonce), so the blob's id reveals nothing about its bytes (§3.7, §7.8); always in a sealed namespace, never in an e2e one, whose blobs are encrypted under a fresh key"`
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
	v, err := a.view(ctx, a.writer(), ns, name)
	if err != nil {
		return err
	}
	var ref map[string]any
	var bid string
	if v.e2e() {
		if a.Nonce {
			return errors.New("--nonce: an e2e namespace's blobs are encrypted under a fresh key, so their id reveals nothing, and are uploaded without one (§E.3.1)")
		}
		if ref, err = v.x.UploadBlob(ctx, ns, name, typ, data); err != nil {
			return v.explain(err)
		}
		bid, _ = ref["$blob"].(string)
	} else {
		nonce := ""
		if a.Nonce || v.sealed() {
			nonce = seal.NewNonce()
		}
		if bid, err = v.c.UploadBlob(ctx, ns, name, typ, nonce, data); err != nil {
			return err
		}
		ref = client.BlobRef(bid, typ, len(data), nonce)
	}
	if a.At == "" {
		fmt.Fprintf(errw, "uploaded %s to %s, pending until a write references it\n", bid, a.Resource)
		return writeJSON(out, ref)
	}
	g, opt := a.gesture()
	p := []any{map[string]any{"op": "add", "path": a.At, "value": ref}}
	w, err := v.append(ctx, "", p, opt)
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
	encArgs
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
	v, err := a.view(ctx, a.client(), ns, name)
	if err != nil {
		return err
	}
	if (v.e2e() || v.sealed()) && a.At == "" {
		return fmt.Errorf("namespace %s is %s: its blobs are read through their reference in the document, which an encrypted blob is checked and opened with; give --at POINTER", ns, v.level)
	}
	if a.Out == "" && out == io.Writer(os.Stdout) && isTerminal(os.Stdout) {
		return errors.New("stdout is a terminal: give -o FILE, or redirect it")
	}
	bid, nonce := a.Blob, a.Nonce
	var b *client.Blob
	if a.At != "" {
		ref, err := v.refAt(ctx, a.Rev, a.At)
		if err != nil {
			return err
		}
		bid, _ = ref["$blob"].(string)
		if b, err = v.c.GetBlobRef(ctx, ns, name, ref); err != nil {
			return v.explain(err)
		}
	} else {
		b, err = v.c.GetBlob(ctx, ns, name, bid, nonce)
		if err != nil && nonce == "" && strings.Contains(err.Error(), "doesn't match its id") {
			return fmt.Errorf("%w: a blob uploaded with a nonce is checked with it (--nonce, or --at reads it from the reference)", err)
		}
		if err != nil {
			return err
		}
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

// isTerminal reports whether f is a terminal (a character device).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
