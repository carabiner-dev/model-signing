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

	"github.com/carabiner-dev/model-signing/internal/serializer/options"
)

func TestSerialize(t *testing.T) {
	// Create a temporary test directory
	tempDir, err := os.MkdirTemp("", "modeldigest-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	testFiles := map[string]string{
		"file1.txt":   "test content 1\n",
		"file2.txt":   "test content 2\n",
		"config.json": "config data\n",
	}

	for name, content := range testFiles {
		path := filepath.Join(tempDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
	}

	// Test with default options
	opts := options.Default()
	serializer := New(opts)
	manifest, err := serializer.Serialize(tempDir)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Check that all files were found
	if len(manifest.Files) != 3 {
		t.Errorf("Expected 3 files, got %d", len(manifest.Files))
	}

	// Verify files are sorted
	for i := 0; i < len(manifest.Files)-1; i++ {
		if manifest.Files[i].Name >= manifest.Files[i+1].Name {
			t.Errorf("Files not sorted: %s >= %s", manifest.Files[i].Name, manifest.Files[i+1].Name)
		}
	}

	// Compute root digest
	rootDigest, err := ComputeRootDigest(manifest)
	if err != nil {
		t.Fatalf("ComputeRootDigest failed: %v", err)
	}

	if rootDigest == "" {
		t.Error("Root digest is empty")
	}

	// Verify it's a valid hex string (64 chars for SHA256)
	if len(rootDigest) != 64 {
		t.Errorf("Expected 64 character hex string, got %d: %s", len(rootDigest), rootDigest)
	}
}

func TestIgnorePaths(t *testing.T) {
	// Create a temporary test directory
	tempDir, err := os.MkdirTemp("", "modeldigest-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files
	if err := os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("content1"), 0644); err != nil {
		t.Fatalf("Failed to create file1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "file2.txt"), []byte("content2"), 0644); err != nil {
		t.Fatalf("Failed to create file2: %v", err)
	}

	// Test ignoring one file
	opts := options.Default()
	opts.IgnorePaths = []string{filepath.Join(tempDir, "file2.txt")}

	serializer := New(opts)
	manifest, err := serializer.Serialize(tempDir)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	if len(manifest.Files) != 1 {
		t.Errorf("Expected 1 file after ignoring, got %d", len(manifest.Files))
	}

	if manifest.Files[0].Name != "file1.txt" {
		t.Errorf("Expected file1.txt, got %s", manifest.Files[0].Name)
	}
}

func TestIgnoreGitPaths(t *testing.T) {
	// Create a temporary test directory
	tempDir, err := os.MkdirTemp("", "modeldigest-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test files including git files
	if err := os.WriteFile(filepath.Join(tempDir, "file.txt"), []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	if err := os.Mkdir(filepath.Join(tempDir, ".git"), 0755); err != nil {
		t.Fatalf("Failed to create .git dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, ".git", "config"), []byte("git config"), 0644); err != nil {
		t.Fatalf("Failed to create .git/config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, ".gitignore"), []byte("*.pyc"), 0644); err != nil {
		t.Fatalf("Failed to create .gitignore: %v", err)
	}

	// Test with IgnoreGitPaths = true
	opts := options.Default()
	opts.IgnoreGitPaths = true

	serializer := New(opts)
	manifest, err := serializer.Serialize(tempDir)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Should only have file.txt, not .gitignore or .git/config
	if len(manifest.Files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(manifest.Files))
		for _, f := range manifest.Files {
			t.Logf("  Found file: %s", f.Name)
		}
	}

	if manifest.Files[0].Name != "file.txt" {
		t.Errorf("Expected file.txt, got %s", manifest.Files[0].Name)
	}

	// Test with IgnoreGitPaths = false
	opts.IgnoreGitPaths = false
	serializer = New(opts)
	manifest, err = serializer.Serialize(tempDir)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	// Should have all files
	if len(manifest.Files) != 3 {
		t.Errorf("Expected 3 files, got %d", len(manifest.Files))
		for _, f := range manifest.Files {
			t.Logf("  Found file: %s", f.Name)
		}
	}
}

func TestComputeDigest(t *testing.T) {
	// Create a temporary test directory
	tempDir, err := os.MkdirTemp("", "modeldigest-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test file
	if err := os.WriteFile(filepath.Join(tempDir, "test.txt"), []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test ComputeDigest convenience function
	digest, err := ComputeDigest(tempDir, options.Default())
	if err != nil {
		t.Fatalf("ComputeDigest failed: %v", err)
	}

	// Check format
	if len(digest) < 8 || digest[:7] != "sha256:" {
		t.Errorf("Expected sha256: prefix, got: %s", digest)
	}

	// Check hash length (sha256: + 64 hex chars = 71 total)
	if len(digest) != 71 {
		t.Errorf("Expected 71 characters (sha256: + 64 hex), got %d: %s", len(digest), digest)
	}
}
