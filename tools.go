//go:build tools

package tools

// Tool dependencies — not imported by production code but required
// for gomobile bind to work (gobind needs these packages importable
// from within the project's module).
import (
	_ "golang.org/x/mobile/bind"
	_ "golang.org/x/mobile/bind/objc"
)
