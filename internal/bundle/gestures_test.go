package bundle_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/middle-management/patchlog/internal/bundle"
	"github.com/middle-management/patchlog/internal/client"
)

// §G.4.1 (v0.39): with "authors": true, history lines carry gesture and
// undoes, and an import writes them with the revisions; without authors
// they are left out, and a line that carries them anyway is refused.
func TestBundleGestures(t *testing.T) {
	src := newDeployment(t, stagingOrigin)
	dst := newDeployment(t, cmsOrigin)
	must(src.c.CreateNamespace(ctx, "m", map[string]any{"read": "public"}))
	g1, g2 := client.NewGesture(), client.NewGesture()
	w0 := must(src.c.CreateDoc(ctx, "m", "a", map[string]any{"n": 0.0}, client.WithGesture(g1)))
	w1 := must(src.c.Append(ctx, "m", "a", w0.ID, []any{op("replace", "/n", 1.0)}, client.WithGesture(g2), client.WithUndoes(g1)))

	var with, without bytes.Buffer
	_, _, err := bundle.Export(ctx, src.c, &with, bundle.ExportOptions{Select: []string{"m/a"}, Authors: true})
	noErr(t, err)
	_, _, err = bundle.Export(ctx, src.c, &without, bundle.ExportOptions{Select: []string{"m/a"}})
	noErr(t, err)
	if !bytes.Contains(with.Bytes(), []byte(`"gesture":"`+g2+`"`)) || !bytes.Contains(with.Bytes(), []byte(`"undoes":"`+g1+`"`)) {
		t.Fatalf("bundle with authors: %s", with.Bytes())
	}
	if bytes.Contains(without.Bytes(), []byte(`"gesture"`)) {
		t.Fatalf("bundle without authors: %s", without.Bytes())
	}

	importB(t, dst, with.Bytes(), bundle.ImportOptions{})
	lg := must(dst.c.Log(ctx, "m", "a", w1.ID, ""))
	if len(lg) != 2 || lg[0].ID != w0.ID || lg[0].Gesture != g1 || lg[1].Gesture != g2 || lg[1].Undoes != g1 {
		t.Fatalf("imported log %+v", lg)
	}
	importB(t, dst, without.Bytes(), bundle.ImportOptions{NSMap: map[string]string{"m": "m2"}})
	if lg := must(dst.c.Log(ctx, "m2", "a", w1.ID, "")); lg[1].Gesture != "" {
		t.Fatalf("imported without authors %+v", lg)
	}

	// A line carrying a gesture in a bundle without authors, or a gesture
	// that isn't one, is refused.
	lines := strings.Split(strings.TrimSpace(without.String()), "\n")
	lines[1] = strings.Replace(lines[1], `"id":`, `"gesture":"`+g1+`","id":`, 1)
	importErr(t, dst, []byte(strings.Join(lines, "\n")+"\n"), bundle.ImportOptions{NSMap: map[string]string{"m": "m3"}}, "without authors")
	bad := strings.Replace(with.String(), g2, "NOT-A-GESTURE", 1)
	importErr(t, dst, []byte(bad), bundle.ImportOptions{NSMap: map[string]string{"m": "m4"}}, "gesture id")
}
