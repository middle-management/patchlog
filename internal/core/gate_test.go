package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Every read of checkReads must be declared on *tx itself. The
// transaction embeds its gate, which embeds checkReads holding the
// transaction: a read missing on *tx would still compile, promoted from
// the interface, and call itself until the stack overflows.
func TestCheckReadsDeclaredOnTx(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	onTx := map[string]bool{}
	ifaces := map[string]*ast.InterfaceType{}
	for _, f := range pkgs["core"].Files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) != 1 {
					continue
				}
				if st, ok := d.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := st.X.(*ast.Ident); ok && id.Name == "tx" {
						onTx[d.Name.Name] = true
					}
				}
			case *ast.GenDecl:
				for _, sp := range d.Specs {
					if ts, ok := sp.(*ast.TypeSpec); ok {
						if it, ok := ts.Type.(*ast.InterfaceType); ok {
							ifaces[ts.Name.Name] = it
						}
					}
				}
			}
		}
	}
	// checkReads' methods, its embedded interfaces' included.
	var reads []string
	var collect func(name string)
	collect = func(name string) {
		it, ok := ifaces[name]
		if !ok {
			t.Fatalf("interface %s not found", name)
		}
		for _, m := range it.Methods.List {
			if len(m.Names) == 0 {
				collect(m.Type.(*ast.Ident).Name)
			}
			for _, n := range m.Names {
				reads = append(reads, n.Name)
			}
		}
	}
	collect("checkReads")
	for _, r := range reads {
		if !onTx[r] {
			t.Errorf("checkReads.%s is not declared on *tx: it would recurse through the gate", r)
		}
	}
}
