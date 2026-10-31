// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dir_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/carabiner-dev/model-signing/pkg/serializer/dir"
	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

// The model is the "simple" fixture of the OMS conformance suite; the
// digest printed is the subject digest of the signed test vectors
// published with the spec.
func ExampleComputeDigest() {
	root, err := os.MkdirTemp("", "simple-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(root) //nolint:errcheck // best effort cleanup

	files := map[string]string{"signme-1": "signme-1\n", "signme-2": "signme-2", "ignore-me": ""}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			log.Print(err)
			return
		}
	}

	// Leave the signer's ignored file out, as it did.
	opts := options.Default()
	opts.IgnorePaths = []string{"ignore-me"}

	digest, err := dir.ComputeDigest(root, opts)
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Println(digest)

	manifest, err := dir.New(opts).Serialize(root)
	if err != nil {
		log.Print(err)
		return
	}
	for _, f := range manifest.Files {
		fmt.Printf("%s %s\n", f.GetName(), f.GetDigest()["sha256"])
	}

	// Output:
	// sha256:92745110b1ab4368471cbe31664e10174e954b113a3df333db860317b2c6dec4
	// signme-1 bc9a717db6064a32cbe9eae6fc40651dd6d36ef1757183f590eff2b1765d7ebc
	// signme-2 32dcb1f8e1ae52d5963e56a6ba06ab58b424c15ed2a6b70d2feca1d089370028
}
