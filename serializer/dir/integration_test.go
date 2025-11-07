// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package dir implements a directory serializer and root digest
// computation for ML models, compatible with the Python
// model_signing library.

package dir

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/model-signing/serializer/options"
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

// TestIntegration_EmptyDirectory tests handling of an empty directory.
func TestIntegration_EmptyDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "empty-model-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	opts := options.Default()
	serializer := New(opts)
	manifest, err := serializer.Serialize(tempDir)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	if len(manifest.Files) != 0 {
		t.Errorf("Expected 0 files in empty directory, got %d", len(manifest.Files))
	}

	// Should still compute a valid root digest (of empty concatenation)
	rootDigest, err := ComputeRootDigest(manifest)
	if err != nil {
		t.Fatalf("ComputeRootDigest failed: %v", err)
	}

	// SHA256 of empty input
	expectedEmpty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if rootDigest != expectedEmpty {
		t.Errorf("Expected SHA256 of empty input, got %s", rootDigest)
	}
}

// TestIntegration_SingleFile tests handling of a model that is a single file.
func TestIntegration_SingleFile(t *testing.T) {
	tempFile, err := os.CreateTemp("", "model-*.bin")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.WriteString("model data"); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()

	// Note: Serializer expects a directory, but we test it with a file parent
	// to ensure proper handling
	tempDir := filepath.Dir(tempFile.Name())
	fileName := filepath.Base(tempFile.Name())

	opts := options.Default()
	opts.IgnoreGitPaths = false // Don't filter anything
	serializer := New(opts)

	manifest, err := serializer.Serialize(tempFile.Name())
	if err == nil {
		t.Logf("Serializing a single file path produced manifest with %d files", len(manifest.Files))
	}

	// Better approach: create a dir with just one file
	tempDir2, err := os.MkdirTemp("", "single-file-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir2)

	testFile := filepath.Join(tempDir2, "model.bin")
	if err := os.WriteFile(testFile, []byte("single model"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	manifest, err = serializer.Serialize(tempDir2)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	if len(manifest.Files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(manifest.Files))
	}

	if manifest.Files[0].Name != "model.bin" {
		t.Errorf("Expected model.bin, got %s", manifest.Files[0].Name)
	}

	_ = tempDir
	_ = fileName
}
