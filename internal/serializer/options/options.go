// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

// Options configures the serialization behavior.
type Options struct {
	// IgnorePaths is a list of paths to ignore during serialization.
	// If a path is a directory, all children are ignored.
	IgnorePaths []string

	// IgnoreGitPaths controls whether git-related files are ignored.
	// When true (default), .git/, .gitignore, .gitattributes, and .github/ are ignored.
	IgnoreGitPaths bool

	// AllowSymlinks controls whether symbolic links are included.
	// If false (default) and a symlink is encountered, an error is returned.
	AllowSymlinks bool
}

// DefaultOptions returns the default options matching the Python implementation.
func Default() *Options {
	return &Options{
		IgnorePaths:    []string{},
		IgnoreGitPaths: true,
		AllowSymlinks:  false,
	}
}
