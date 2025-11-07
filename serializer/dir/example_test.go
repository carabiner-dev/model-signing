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

package dir_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	modeldigest "github.com/carabiner-dev/model-signing/serializer/dir"
	"github.com/carabiner-dev/model-signing/serializer/options"
)

func ExampleComputeDigest() {
	// Create a temporary model directory for the example
	tempDir, err := os.MkdirTemp("", "example-model-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create some model files
	os.WriteFile(filepath.Join(tempDir, "model.bin"), []byte("model data"), 0644)
	os.WriteFile(filepath.Join(tempDir, "config.json"), []byte(`{"version": "1.0"}`), 0644)

	// Compute digest with default options
	digest, err := modeldigest.ComputeDigest(tempDir, options.Default())
	if err != nil {
		log.Fatal(err)
	}

	// The digest will be in the format sha256:hash
	fmt.Printf("Digest format: sha256:...\n")
	fmt.Printf("Digest length: %d characters\n", len(digest))

	// Output:
	// Digest format: sha256:...
	// Digest length: 71 characters
}

func ExampleSerializer_Serialize() {
	// Create a temporary model directory
	tempDir, err := os.MkdirTemp("", "example-model-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create model files
	os.WriteFile(filepath.Join(tempDir, "weights.bin"), []byte("weights"), 0644)
	os.WriteFile(filepath.Join(tempDir, "metadata.json"), []byte("{}"), 0644)

	// Create serializer
	serializer := modeldigest.New(options.Default())

	// Serialize the model
	manifest, err := serializer.Serialize(tempDir)
	if err != nil {
		log.Fatal(err)
	}

	// Print file information
	fmt.Printf("Model: %s\n", manifest.ModelName)
	fmt.Printf("Files: %d\n", len(manifest.Files))

	// Files are sorted by path
	for _, file := range manifest.Files {
		fmt.Printf("  %s: %s...\n", file.Name, file.Digest["sha256"][:8])
	}
}

func ExampleOptions_IgnorePaths() {
	tempDir, err := os.MkdirTemp("", "example-model-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create files including one we want to ignore
	os.WriteFile(filepath.Join(tempDir, "model.bin"), []byte("model"), 0644)
	os.WriteFile(filepath.Join(tempDir, "README.md"), []byte("readme"), 0644)

	// Create options to ignore README.md
	opts := options.Default()
	opts.IgnorePaths = []string{filepath.Join(tempDir, "README.md")}

	// Serialize with ignore
	serializer := modeldigest.New(opts)
	manifest, err := serializer.Serialize(tempDir)
	if err != nil {
		log.Fatal(err)
	}

	// Only model.bin should be included
	fmt.Printf("Files included: %d\n", len(manifest.Files))
	fmt.Printf("First file: %s\n", manifest.Files[0].Name)

	// Output:
	// Files included: 1
	// First file: model.bin
}
