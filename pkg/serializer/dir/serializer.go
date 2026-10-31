// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package dir implements the OpenSSF Model Signing (OMS) "files"
// serialization method: it enumerates the regular files of a model
// directory (or a single-file model), hashes each one and computes the
// root digest that OMS bundles record as the statement subject.
//
// The enumeration, exclusion and digest rules follow the OMS v1.0
// specification (sections 6.1, 6.2 and 6.5) and are checked against the
// conformance corpus published with it, so the digests produced here
// match the ones the sigstore model_signing reference implementation
// signs.
package dir

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/carabiner-dev/hasher"
	intoto "github.com/in-toto/attestation/go/v1"

	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

// ErrEmptyModel is returned when a model has no regular files left after
// applying the exclusions. OMS requires signers and verifiers to reject
// such models instead of producing the digest of an empty manifest.
var ErrEmptyModel = errors.New("model contains no regular files after applying exclusions")

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

// gitPaths returns the default git-related paths to ignore. OMS matches
// these as top-level entries of the model root only.
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
			checkPath = strings.TrimSuffix(ignore, "/")
		}

		// Check if path is under the ignore path
		if relPath == checkPath || strings.HasPrefix(relPath, checkPath+"/") {
			return true, nil
		}
	}

	return false, nil
}

// Serialize enumerates the model given by modelPath and creates a manifest
// with the digests of its files. The model may be a directory or a single
// file; for a single file the manifest records the file under its basename.
//
// Symbolic links are rejected unless AllowSymlinks is set, in which case a
// link to a regular file is hashed through its target and recorded under
// the link's own path. Links to directories are rejected either way since
// the files under them would silently fall out of the manifest.
func (s *Serializer) Serialize(modelPath string) (*Manifest, error) {
	// Resolve absolute path
	absPath, err := filepath.Abs(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve model path: %w", err)
	}

	rootInfo, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read model path: %w", err)
	}

	var filesToHash []string
	// walkRoot is the directory relative paths are computed from. It
	// differs from absPath only when the model path itself is a symlink.
	walkRoot := absPath
	if rootInfo.IsDir() {
		walkRoot, err = filepath.EvalSymlinks(absPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve model path: %w", err)
		}
		filesToHash, err = s.enumerate(absPath, walkRoot)
		if err != nil {
			return nil, err
		}
	} else {
		if !rootInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("model path %s is neither a directory nor a regular file", modelPath)
		}
		filesToHash = []string{absPath}
	}

	if len(filesToHash) == 0 {
		return nil, ErrEmptyModel
	}

	// Hash all files using the hasher library
	h := hasher.New()
	h.Options.Algorithms = []intoto.HashAlgorithm{intoto.AlgorithmSHA256}

	fileHashes, err := h.HashFiles(filesToHash)
	if err != nil {
		return nil, fmt.Errorf("failed to hash files: %w", err)
	}

	// Build manifest with relative paths
	fileDescriptors := make([]*intoto.ResourceDescriptor, 0, len(filesToHash))
	for _, filePath := range filesToHash {
		var relPath string
		if filePath == absPath {
			// Single-file model: OMS records the file under its basename.
			relPath = filepath.Base(absPath)
		} else {
			relPath, err = filepath.Rel(walkRoot, filePath)
			if err != nil {
				return nil, fmt.Errorf("failed to get relative path: %w", err)
			}
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

	// Sort by path for deterministic ordering. Go compares strings
	// bytewise, which for UTF-8 names is the code point order OMS calls for.
	sort.Slice(fileDescriptors, func(i, j int) bool {
		return fileDescriptors[i].Name < fileDescriptors[j].Name
	})

	modelName := filepath.Base(absPath)

	return &Manifest{
		ModelName: modelName,
		Files:     fileDescriptors,
	}, nil
}

// normalizeIgnorePath rewrites an absolute ignore path so it compares
// against the resolved walk root: the model path may be given through a
// symlink (eg macOS temp dirs under /var -> /private/var) while the walk
// runs on the resolved directory.
func normalizeIgnorePath(ignore, modelPath, walkRoot string) string {
	if !filepath.IsAbs(ignore) {
		return ignore
	}
	if resolved, err := filepath.EvalSymlinks(ignore); err == nil {
		return resolved
	}
	// The path does not exist (yet), map it under the resolved root.
	if rel, err := filepath.Rel(modelPath, ignore); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.Join(walkRoot, rel)
	}
	return ignore
}

// enumerate walks the resolved model root and returns the files to hash,
// applying the exclusion and symlink rules. modelPath is the root as the
// caller gave it, used to interpret absolute ignore paths.
func (s *Serializer) enumerate(modelPath, root string) ([]string, error) {
	// Build complete ignore list
	ignorePaths := make([]string, 0, len(s.opts.IgnorePaths)+4)
	for _, ignore := range s.opts.IgnorePaths {
		ignorePaths = append(ignorePaths, normalizeIgnorePath(ignore, modelPath, root))
	}

	if s.opts.IgnoreGitPaths {
		for _, gitPath := range gitPaths() {
			ignorePaths = append(ignorePaths, filepath.Join(root, gitPath))
		}
	}

	var filesToHash []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}

		ignore, err := s.shouldIgnore(path, root, ignorePaths)
		if err != nil {
			return err
		}

		// Symlinks: Walk never follows them, so decide here what to do.
		if info.Mode()&os.ModeSymlink != 0 {
			if !s.opts.AllowSymlinks {
				return fmt.Errorf("symlink not allowed: %s (use AllowSymlinks option)", path)
			}
			if ignore {
				return nil
			}
			target, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("failed to resolve symlink %s: %w", path, err)
			}
			if target.IsDir() {
				return fmt.Errorf("cannot use %s: it is a symlink to a directory, files under it would not be serialized", path)
			}
			if !target.Mode().IsRegular() {
				return fmt.Errorf("symlink %s does not point to a regular file", path)
			}
			filesToHash = append(filesToHash, path)
			return nil
		}

		if info.IsDir() {
			if ignore {
				return filepath.SkipDir
			}
			return nil
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
	return filesToHash, nil
}

// ComputeRootDigest computes the root digest from a manifest as defined
// in OMS v1.0 section 6.5.1: SHA256(hash1 + hash2 + ... + hashN) where the
// hashes are the raw digest bytes concatenated in manifest (path) order.
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
