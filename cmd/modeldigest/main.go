// Copyright 2025 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	modeldigest "github.com/carabiner-dev/model-signing/internal/serializer/dir"
	"github.com/carabiner-dev/model-signing/internal/serializer/options"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ",")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var ignorePaths arrayFlags
	ignoreGitPaths := flag.Bool("ignore-git-paths", true, "Ignore git-related files")
	allowSymlinks := flag.Bool("allow-symlinks", false, "Allow following symlinks")

	flag.Var(&ignorePaths, "ignore-paths", "File paths to ignore (can be specified multiple times)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] MODEL_PATH\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	modelPath := flag.Arg(0)

	opts := &options.Options{
		IgnorePaths:    ignorePaths,
		IgnoreGitPaths: *ignoreGitPaths,
		AllowSymlinks:  *allowSymlinks,
	}

	digest, err := modeldigest.ComputeDigest(modelPath, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error computing digest: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(digest)
}
