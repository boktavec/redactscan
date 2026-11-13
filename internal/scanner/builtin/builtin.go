// Package builtin holds the production scanners and the registry that runs
// them. It sits above internal/scanner (which never imports it) so the scanner
// package stays free of scanner-specific imports.
//
// Scanners here read only through the io.ReaderAt Run gives them, always via
// readFull, and never open files (an import-allowlist test enforces it).
package builtin

import "github.com/boktavec/redactscan/internal/scanner"

// Default returns the production registry.
func Default() (*scanner.Registry, error) {
	return scanner.NewRegistry(Hash{}, FileType{})
}
