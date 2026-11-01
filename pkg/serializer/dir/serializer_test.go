// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dir

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

// writeModel creates a model directory with the given files (paths use /)
// under a temp dir and returns its path.
func writeModel(t *testing.T, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "model")
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// names returns the manifest entries' names in manifest order.
func names(m *Manifest) []string {
	out := make([]string, 0, len(m.Files))
	for _, f := range m.Files {
		out = append(out, f.GetName())
	}
	return out
}

// sampleFiles is a small model with files at several depths.
var sampleFiles = map[string]string{
	"file2.txt":   "test content 2\n",
	"file1.txt":   "test content 1\n",
	configJSON:    "config data\n",
	"sub/b.bin":   "b",
	"sub/a.bin":   "a",
	"sub/x/c.bin": "c",
}

func TestSerialize(t *testing.T) {
	root := writeModel(t, sampleFiles)

	manifest, err := New(options.Default()).Serialize(root)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	want := configJSON + ",file1.txt,file2.txt,sub/a.bin,sub/b.bin,sub/x/c.bin"
	if got := strings.Join(names(manifest), ","); got != want {
		t.Errorf("manifest order: got %v want %v", got, want)
	}
	if manifest.ModelName != "model" {
		t.Errorf("model name: got %q", manifest.ModelName)
	}
	for _, f := range manifest.Files {
		if len(f.GetDigest()["sha256"]) != 64 {
			t.Errorf("%s: bad sha256 digest %q", f.GetName(), f.GetDigest()["sha256"])
		}
	}

	rootDigest, err := ComputeRootDigest(manifest)
	if err != nil {
		t.Fatalf("ComputeRootDigest failed: %v", err)
	}
	if len(rootDigest) != 64 {
		t.Errorf("Expected 64 character hex string, got %d: %s", len(rootDigest), rootDigest)
	}

	// The same content in a differently named directory hashes the same.
	other := writeModel(t, sampleFiles)
	d1, err := ComputeDigest(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := ComputeDigest(other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 || d1 != "sha256:"+rootDigest {
		t.Errorf("digests differ: %s %s %s", d1, d2, rootDigest)
	}
}

func TestIgnorePaths(t *testing.T) {
	root := writeModel(t, map[string]string{
		"keep.txt":          "content1",
		"drop.txt":          "content2",
		"sub/nested/d.json": "d",
		"sub/e.bin":         "e",
	})

	for name, ignore := range map[string][]string{
		"absolute file":  {filepath.Join(root, "drop.txt")},
		"relative file":  {"drop.txt"},
		"trailing slash": {"drop.txt/"},
	} {
		t.Run(name, func(t *testing.T) {
			opts := options.Default()
			opts.IgnorePaths = ignore
			manifest, err := New(opts).Serialize(root)
			if err != nil {
				t.Fatalf("Serialize failed: %v", err)
			}
			want := "keep.txt,sub/e.bin,sub/nested/d.json"
			if got := strings.Join(names(manifest), ","); got != want {
				t.Errorf("got %s want %s", got, want)
			}
		})
	}

	// Ignoring a directory drops its whole subtree.
	opts := options.Default()
	opts.IgnorePaths = []string{filepath.Join(root, "sub", "nested")}
	manifest, err := New(opts).Serialize(root)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	for _, n := range names(manifest) {
		if strings.HasPrefix(n, "sub/nested/") {
			t.Errorf("found file in ignored directory: %s", n)
		}
	}

	// An ignore path outside the model is harmless.
	opts.IgnorePaths = []string{filepath.Join(t.TempDir(), "elsewhere")}
	manifest, err = New(opts).Serialize(root)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if len(manifest.Files) != 4 {
		t.Errorf("expected 4 files, got %v", names(manifest))
	}
}

func TestIgnoreGitPaths(t *testing.T) {
	root := writeModel(t, map[string]string{
		"file.txt":                 "content",
		".git/config":              "git config",
		gitHead:                    "ref: refs/heads/main",
		gitIgnore:                  "*.pyc",
		gitAttrs:                   "",
		".github/workflows/ci.yml": "name: CI",
		"sub/" + gitIgnore:         "kept",
	})

	// Default: git metadata at the root is excluded, nested is not.
	manifest, err := New(options.Default()).Serialize(root)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if got := strings.Join(names(manifest), ","); got != "file.txt,sub/.gitignore" {
		t.Errorf("unexpected files: %s", got)
	}

	opts := options.Default()
	opts.IgnoreGitPaths = false
	manifest, err = New(opts).Serialize(root)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if len(manifest.Files) != 7 {
		t.Errorf("expected 7 files, got %v", names(manifest))
	}
}

func TestComputeDigest(t *testing.T) {
	root := writeModel(t, map[string]string{"test.txt": "test"})

	digest, err := ComputeDigest(root, options.Default())
	if err != nil {
		t.Fatalf("ComputeDigest failed: %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		t.Errorf("expected sha256: plus 64 hex chars, got %q", digest)
	}

	// nil options mean the defaults.
	if d, err := ComputeDigest(root, nil); err != nil || d != digest {
		t.Errorf("nil options: got %s, %v", d, err)
	}

	if _, err := ComputeDigest(filepath.Join(root, "missing"), nil); err == nil {
		t.Error("expected an error for a missing path")
	}
}

// A model is rejected when nothing is left to hash (OMS section 6.1).
func TestEmptyModel(t *testing.T) {
	if _, err := New(nil).Serialize(t.TempDir()); !errors.Is(err, ErrEmptyModel) {
		t.Fatalf("expected ErrEmptyModel, got %v", err)
	}

	// A directory holding only excluded files is empty too.
	root := writeModel(t, map[string]string{gitIgnore: ".gitkeep\n"})
	if _, err := New(nil).Serialize(root); !errors.Is(err, ErrEmptyModel) {
		t.Fatalf("expected ErrEmptyModel, got %v", err)
	}
}

// A single-file model is recorded under its basename and hashes the same
// as a directory holding only that file.
func TestSingleFile(t *testing.T) {
	root := writeModel(t, map[string]string{modelBin: "single model"})
	file := filepath.Join(root, modelBin)

	fileManifest, err := New(nil).Serialize(file)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if got := names(fileManifest); len(got) != 1 || got[0] != modelBin {
		t.Fatalf("expected a single %s entry, got %v", modelBin, got)
	}
	if fileManifest.ModelName != modelBin {
		t.Errorf("expected model name %s, got %s", modelBin, fileManifest.ModelName)
	}

	fileDigest, err := ComputeDigest(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	dirDigest, err := ComputeDigest(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fileDigest != dirDigest {
		t.Errorf("single-file digest %s differs from directory digest %s", fileDigest, dirDigest)
	}
}

// A model path that is a symlink to a directory is followed as the root.
func TestSymlinkedRoot(t *testing.T) {
	root := writeModel(t, map[string]string{"a.bin": "a", "sub/b.bin": "b"})
	link := filepath.Join(t.TempDir(), "linked-model")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}

	want, err := ComputeDigest(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(nil).Serialize(link)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ComputeRootDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	if "sha256:"+got != want {
		t.Errorf("digest through symlink %s differs from %s", got, want)
	}
	if m.ModelName != "linked-model" {
		t.Errorf("model name should be the path given, got %s", m.ModelName)
	}
}

// The manifest records the exclusions the way a signer publishes them:
// relative to the root, defaults included, sorted, without duplicates.
func TestManifestRecordsSerialization(t *testing.T) {
	const cBin = "c.bin"
	root := writeModel(t, map[string]string{"a.bin": "a", "skip/b.bin": "b", cBin: "c"})

	opts := options.Default()
	opts.IgnorePaths = []string{filepath.Join(root, "skip"), cBin + "/", cBin}
	m, err := New(opts).Serialize(root)
	require.NoError(t, err)
	require.Equal(t, []string{".git", gitAttrs, ".github", gitIgnore, cBin, "skip"}, m.IgnorePaths)
	require.False(t, m.AllowSymlinks)

	opts = options.Default()
	opts.IgnoreGitPaths = false
	opts.AllowSymlinks = true
	opts.IgnorePaths = []string{filepath.Join(t.TempDir(), "elsewhere")}
	m, err = New(opts).Serialize(root)
	require.NoError(t, err)
	require.Empty(t, m.IgnorePaths)
	require.True(t, m.AllowSymlinks)
}
