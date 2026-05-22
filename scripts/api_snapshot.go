//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
)

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(info os.FileInfo) bool { return !strings.HasSuffix(info.Name(), "_test.go") }, 0)
	if err != nil {
		panic(err)
	}
	var pkg *ast.Package
	for _, p := range pkgs {
		pkg = p
		break
	}
	if pkg == nil {
		panic("no package")
	}
	var out []string
	for _, f := range pkg.Files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && ast.IsExported(d.Name.Name) {
					out = append(out, "func "+d.Name.Name+strings.TrimPrefix(node(fset, d.Type), "func"))
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if !ast.IsExported(s.Name.Name) {
							continue
						}
						out = append(out, "type "+s.Name.Name+typeSummary(fset, s.Type))
					case *ast.ValueSpec:
						kind := strings.ToLower(d.Tok.String())
						for i, name := range s.Names {
							if ast.IsExported(name.Name) {
								out = append(out, kind+" "+name.Name+valueType(fset, s, i))
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(out)
	for _, line := range out {
		fmt.Println(line)
	}
}

func typeSummary(fset *token.FileSet, e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StructType:
		var fields []string
		for _, f := range t.Fields.List {
			for _, n := range f.Names {
				if ast.IsExported(n.Name) {
					fields = append(fields, n.Name+" "+node(fset, f.Type))
				}
			}
		}
		return " struct { " + strings.Join(fields, "; ") + " }"
	case *ast.InterfaceType:
		var methods []string
		for _, f := range t.Methods.List {
			for _, n := range f.Names {
				if ast.IsExported(n.Name) {
					methods = append(methods, n.Name+node(fset, f.Type))
				}
			}
		}
		return " interface { " + strings.Join(methods, "; ") + " }"
	default:
		return " " + node(fset, e)
	}
}

func valueType(fset *token.FileSet, s *ast.ValueSpec, i int) string {
	if s.Type != nil {
		return " " + node(fset, s.Type)
	}
	if i < len(s.Values) {
		return " = " + node(fset, s.Values[i])
	}
	return ""
}

func node(fset *token.FileSet, n any) string {
	var b bytes.Buffer
	if err := format.Node(&b, fset, n); err != nil {
		panic(err)
	}
	return b.String()
}
