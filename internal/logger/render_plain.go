//go:build libcrust

package logger

import (
	"fmt"
	"io"
)

func renderColored(w io.Writer, timestamp, levelStr, prefix, msg string) {
	// libcrust build: no color dependencies, fall back to plain text.
	fmt.Fprintf(w, "%s [%s] [%s] %s\n", timestamp, levelStr, prefix, msg)
}
