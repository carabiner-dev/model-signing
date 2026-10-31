// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package dir implements a directory serializer and root digest
// computation for ML models, compatible with the Python
// model_signing library.

package dir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

// TestIntegration_ComplexDirectory tests serialization of a complex directory
// structure with subdirectories and git files.
func TestIntegration_ComplexDirectory(t *testing.T) {
	// Create complex directory structure
	tempDir, err := os.MkdirTemp("", "complex-model-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create nested structure
	testStructure := map[string]string{
		"model.bin":                "model weights",
		"config.json":              `{"version": "1.0"}`,
		"subdir/layer1.bin":        "layer 1 data",
		"subdir/layer2.bin":        "layer 2 data",
		"subdir/nested/data.json":  `{"nested": true}`,
		".git/config":              "git config",
		".git/HEAD":                "ref: refs/heads/main",
		".gitignore":               "*.pyc\n__pycache__/",
		".github/workflows/ci.yml": "name: CI",
	}

	for path, content := range testStructure {
		fullPath := filepath.Join(tempDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("Failed to create dir for %s: %v", path, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write %s: %v", path, err)
		}
	}

	// Test 1: With git ignore (default)
	t.Run("WithGitIgnore", func(t *testing.T) {
		opts := options.Default()
		serializer := New(opts)
		manifest, err := serializer.Serialize(tempDir)
		if err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}

		// Should only have non-git files
		expectedFiles := []string{
			"config.json",
			"model.bin",
			"subdir/layer1.bin",
			"subdir/layer2.bin",
			"subdir/nested/data.json",
		}

		if len(manifest.Files) != len(expectedFiles) {
			t.Errorf("Expected %d files, got %d", len(expectedFiles), len(manifest.Files))
			for i, f := range manifest.Files {
				t.Logf("  %d: %s", i, f.Name)
			}
		}

		// Verify files are in sorted order
		for i, expectedPath := range expectedFiles {
			if manifest.Files[i].Name != expectedPath {
				t.Errorf("File %d: expected %s, got %s", i, expectedPath, manifest.Files[i].Name)
			}
		}

		// Compute root digest
		rootDigest, err := ComputeRootDigest(manifest)
		if err != nil {
			t.Fatalf("ComputeRootDigest failed: %v", err)
		}

		if len(rootDigest) != 64 {
			t.Errorf("Expected 64-char hex digest, got %d chars", len(rootDigest))
		}
	})

	// Test 2: Without git ignore
	t.Run("WithoutGitIgnore", func(t *testing.T) {
		opts := options.Default()
		opts.IgnoreGitPaths = false

		serializer := New(opts)
		manifest, err := serializer.Serialize(tempDir)
		if err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}

		// Should have all files including git files
		if len(manifest.Files) != 9 {
			t.Errorf("Expected 9 files, got %d", len(manifest.Files))
			for i, f := range manifest.Files {
				t.Logf("  %d: %s", i, f.Name)
			}
		}
	})

	// Test 3: With custom ignore paths
	t.Run("WithCustomIgnore", func(t *testing.T) {
		opts := options.Default()
		opts.IgnorePaths = []string{
			filepath.Join(tempDir, "subdir", "nested"),
		}

		serializer := New(opts)
		manifest, err := serializer.Serialize(tempDir)
		if err != nil {
			t.Fatalf("Serialize failed: %v", err)
		}

		// Should not include files in subdir/nested/
		for _, file := range manifest.Files {
			if filepath.HasPrefix(file.Name, "subdir/nested/") {
				t.Errorf("Found file in ignored directory: %s", file.Name)
			}
		}
	})
}

// TestIntegration_EmptyDirectory checks that an empty model is rejected,
// as OMS v1.0 section 6.1 requires, instead of yielding the digest of an
// empty manifest.
func TestIntegration_EmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()

	serializer := New(options.Default())
	if _, err := serializer.Serialize(tempDir); !errors.Is(err, ErrEmptyModel) {
		t.Fatalf("expected ErrEmptyModel, got %v", err)
	}

	// A directory holding only excluded files is empty too.
	if err := os.WriteFile(filepath.Join(tempDir, ".gitignore"), []byte(".gitkeep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := serializer.Serialize(tempDir); !errors.Is(err, ErrEmptyModel) {
		t.Fatalf("expected ErrEmptyModel, got %v", err)
	}
}

// TestIntegration_SingleFile tests a model that is a single file: the
// manifest records it under its basename and the root digest is the same
// the file gets when it is the only entry of a directory model.
func TestIntegration_SingleFile(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "model.bin")
	if err := os.WriteFile(testFile, []byte("single model"), 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	serializer := New(options.Default())

	fileManifest, err := serializer.Serialize(testFile)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}
	if len(fileManifest.Files) != 1 || fileManifest.Files[0].Name != "model.bin" {
		t.Fatalf("expected a single model.bin entry, got %+v", fileManifest.Files)
	}
	if fileManifest.ModelName != "model.bin" {
		t.Errorf("expected model name model.bin, got %s", fileManifest.ModelName)
	}

	dirManifest, err := serializer.Serialize(tempDir)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	fileDigest, err := ComputeRootDigest(fileManifest)
	if err != nil {
		t.Fatal(err)
	}
	dirDigest, err := ComputeRootDigest(dirManifest)
	if err != nil {
		t.Fatal(err)
	}
	if fileDigest != dirDigest {
		t.Errorf("single-file digest %s differs from directory digest %s", fileDigest, dirDigest)
	}
}
