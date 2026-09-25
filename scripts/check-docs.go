//go:build ignore

// Command check-docs verifies package and exported declaration documentation.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	failed := false
	packages := map[string]bool{}
	fs := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && path != "." || d.Name() == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, e := parser.ParseFile(fs, path, nil, parser.ParseComments)
		if e != nil {
			return e
		}
		dir := filepath.Dir(path)
		packages[dir] = packages[dir] || file.Doc != nil
		report := func(name string, pos token.Pos) {
			fmt.Printf("%s: missing documentation for %s\n", fs.Position(pos), name)
			failed = true
		}
		for _, decl := range file.Decls {
			switch v := decl.(type) {
			case *ast.FuncDecl:
				if ast.IsExported(v.Name.Name) && v.Doc == nil {
					report(v.Name.Name, v.Pos())
				}
			case *ast.GenDecl:
				for _, spec := range v.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(s.Name.Name) && s.Doc == nil && v.Doc == nil {
							report(s.Name.Name, s.Pos())
						}
					case *ast.ValueSpec:
						for _, name := range s.Names {
							if ast.IsExported(name.Name) && s.Doc == nil && v.Doc == nil {
								report(name.Name, name.Pos())
							}
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for dir, ok := range packages {
		if !ok {
			fmt.Println(dir + ": missing package documentation")
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("Package and exported API documentation present")
}
