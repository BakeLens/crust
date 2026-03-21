package proxyutil

import (
	"bytes"
	"testing"
)

func TestCompressDecompressGzip_Roundtrip(t *testing.T) {
	original := []byte(`{"content":[{"type":"text","text":"hello world"}]}`)

	compressed, err := CompressGzip(original)
	if err != nil {
		t.Fatalf("CompressGzip: %v", err)
	}
	if bytes.Equal(compressed, original) {
		t.Error("compressed data should differ from original")
	}

	decompressed, err := DecompressGzip(compressed)
	if err != nil {
		t.Fatalf("DecompressGzip: %v", err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Errorf("roundtrip failed: got %q, want %q", decompressed, original)
	}
}

func TestDecompressGzip_InvalidData(t *testing.T) {
	_, err := DecompressGzip([]byte("not gzip"))
	if err == nil {
		t.Error("expected error for invalid gzip data")
	}
}

func TestCompressGzip_Empty(t *testing.T) {
	compressed, err := CompressGzip(nil)
	if err != nil {
		t.Fatalf("CompressGzip(nil): %v", err)
	}
	decompressed, err := DecompressGzip(compressed)
	if err != nil {
		t.Fatalf("DecompressGzip: %v", err)
	}
	if len(decompressed) != 0 {
		t.Errorf("expected empty, got %d bytes", len(decompressed))
	}
}
