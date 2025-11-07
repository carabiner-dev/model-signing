// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package dir implements a directory serializer and root digest
// computation for ML models, compatible with the Python
// model_signing library.

package dir

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/carabiner-dev/hasher"
	"github.com/carabiner-dev/model-signing/serializer/options"
	intoto "github.com/in-toto/attestation/go/v1"
)

// Manifest represents the serialized model with all file hashes.
type Manifest struct {
	ModelName string
	Files     []*intoto.ResourceDescriptor
}

// Serializer serializes a model directory and computes digests.
type Serializer struct {
	opts *options.Options
}

// New creates a new Serializer with the given options.
func New(opts *options.Options) *Serializer {
	if opts == nil {
		opts = options.Default()
	}
	return &Serializer{opts: opts}
}

// gitPaths returns the default git-related paths to ignore.
func gitPaths() []string {
	return []string{".git", ".gitignore", ".gitattributes", ".github"}
}

// shouldIgnore determines if a path should be ignored based on ignore rules.
func (s *Serializer) shouldIgnore(path string, modelPath string, ignorePaths []string) (bool, error) {
	// Get relative path from model root
	relPath, err := filepath.Rel(modelPath, path)
	if err != nil {
		return false, err
	}

	// Normalize path separators
	relPath = filepath.ToSlash(relPath)

	// Check each ignore pattern
	for _, ignore := range ignorePaths {
		ignore = filepath.ToSlash(ignore)

		// If ignore path is relative, match against relative path
		// If ignore path is absolute, resolve it to relative
		var checkPath string
		if filepath.IsAbs(ignore) {
			checkRelPath, err := filepath.Rel(modelPath, ignore)
			if err != nil || strings.HasPrefix(checkRelPath, "..") {
				// Ignore path is outside model directory
				continue
			}
			checkPath = filepath.ToSlash(checkRelPath)
		} else {
			checkPath = ignore
		}

		// Check if path is under the ignore path
		if relPath == checkPath || strings.HasPrefix(relPath, checkPath+"/") {
			return true, nil
		}
	}

	return false, nil
}

// Serialize traverses the model directory and creates a manifest with file hashes.
func (s *Serializer) Serialize(modelPath string) (*Manifest, error) {
	// Resolve absolute path
	absPath, err := filepath.Abs(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve model path: %w", err)
	}

	// Build complete ignore list
	ignorePaths := make([]string, len(s.opts.IgnorePaths))
	copy(ignorePaths, s.opts.IgnorePaths)

	if s.opts.IgnoreGitPaths {
		for _, gitPath := range gitPaths() {
			ignorePaths = append(ignorePaths, filepath.Join(absPath, gitPath))
		}
	}

	// Collect all files to hash
	var filesToHash []string

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if it's a symlink
		if info.Mode()&os.ModeSymlink != 0 {
			if !s.opts.AllowSymlinks {
				return fmt.Errorf("symlink not allowed: %s (use AllowSymlinks option)", path)
			}
		}

		// Skip directories
		if info.IsDir() {
			// Check if directory should be ignored
			ignore, err := s.shouldIgnore(path, absPath, ignorePaths)
			if err != nil {
				return err
			}
			if ignore {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file should be ignored
		ignore, err := s.shouldIgnore(path, absPath, ignorePaths)
		if err != nil {
			return err
		}
		if ignore {
			return nil
		}

		// Add regular files
		if info.Mode().IsRegular() {
			filesToHash = append(filesToHash, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	// Hash all files using the hasher library
	h := hasher.New()
	h.Options.Algorithms = []intoto.HashAlgorithm{intoto.AlgorithmSHA256}

	fileHashes, err := h.HashFiles(filesToHash)
	if err != nil {
		return nil, fmt.Errorf("failed to hash files: %w", err)
	}

	// Build manifest with relative paths
	var fileDescriptors []*intoto.ResourceDescriptor
	for _, filePath := range filesToHash {
		relPath, err := filepath.Rel(absPath, filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to get relative path: %w", err)
		}

		// Normalize to forward slashes (POSIX style) for compatibility
		relPath = filepath.ToSlash(relPath)

		hashSet := (*fileHashes)[filePath]
		hashValue := hashSet[intoto.AlgorithmSHA256]

		fileDescriptors = append(fileDescriptors, &intoto.ResourceDescriptor{
			Name: relPath,
			Digest: map[string]string{
				"sha256": hashValue,
			},
		})
	}

	// Sort by path for deterministic ordering
	sort.Slice(fileDescriptors, func(i, j int) bool {
		return fileDescriptors[i].Name < fileDescriptors[j].Name
	})

	modelName := filepath.Base(absPath)

	return &Manifest{
		ModelName: modelName,
		Files:     fileDescriptors,
	}, nil
}

// ComputeRootDigest computes the root digest from a manifest.
// This is the same digest that appears in signatures: SHA256(hash1 + hash2 + ... + hashN)
// where hashes are raw bytes concatenated in sorted order.
func ComputeRootDigest(manifest *Manifest) (string, error) {
	hasher := sha256.New()

	// Files are already sorted by path in the manifest
	for _, file := range manifest.Files {
		// Get the sha256 hash from the digest map
		hashValue, ok := file.Digest["sha256"]
		if !ok {
			return "", fmt.Errorf("sha256 digest not found for %s", file.Name)
		}

		// Decode hex hash to bytes
		hashBytes, err := hex.DecodeString(hashValue)
		if err != nil {
			return "", fmt.Errorf("failed to decode hash for %s: %w", file.Name, err)
		}

		// Write raw hash bytes to the hasher
		hasher.Write(hashBytes)
	}

	rootHash := hasher.Sum(nil)
	return hex.EncodeToString(rootHash), nil
}

// ComputeDigest is a convenience function that serializes a model directory
// and returns the root digest in algorithm:hash format.
func ComputeDigest(modelPath string, opts *options.Options) (string, error) {
	serializer := New(opts)
	manifest, err := serializer.Serialize(modelPath)
	if err != nil {
		return "", err
	}

	rootDigest, err := ComputeRootDigest(manifest)
	if err != nil {
		return "", err
	}

	return "sha256:" + rootDigest, nil
}
