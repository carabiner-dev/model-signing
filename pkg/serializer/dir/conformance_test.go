// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

// File names the conformance models share.
const (
	modelBin   = "model.bin"
	configJSON = "config.json"
	weightsBin = "weights.bin"
	gitHead    = ".git/HEAD"
	gitIgnore  = ".gitignore"
	gitAttrs   = ".gitattributes"
	signme1    = "signme-1"
	signme2    = "signme-2"
	ignoreMe   = "ignore-me"
)

// The models below are the fixtures of the OpenSSF Model Signing (OMS)
// conformance suite (conformance/config/models.yaml in
// github.com/ossf/model-signing-spec). The "simple" model is the one the
// signed bundles shipped in the spec's test-vectors/v1.0/valid directory
// were produced from, so its root digest is the one recorded in those
// bundles' statement subject. The other digests follow the spec's root
// digest algorithm (section 6.5.1) over the files the suite expects to be
// signed, and agree with the sigstore model_signing reference.
func TestOMSConformanceModels(t *testing.T) {
	type file struct {
		path    string
		content []byte
		ignored bool
	}
	fill := func(b byte, n int) []byte {
		out := make([]byte, n)
		for i := range out {
			out[i] = b
		}
		return out
	}
	seq := func(repeat int) []byte {
		out := make([]byte, 0, 256*repeat)
		for range repeat {
			for i := range 256 {
				out = append(out, byte(i))
			}
		}
		return out
	}

	for _, tc := range []struct {
		name   string
		files  []file
		expect string
	}{
		{
			// Matches subject[0].digest.sha256 of the valid test vectors.
			name: "simple",
			files: []file{
				{path: signme1, content: []byte("signme-1\n")},
				{path: signme2, content: []byte("signme-2")},
				{path: ignoreMe, ignored: true},
			},
			expect: "92745110b1ab4368471cbe31664e10174e954b113a3df333db860317b2c6dec4",
		},
		{
			name:   "single-file",
			files:  []file{{path: modelBin, content: fill(0xEF, 256)}},
			expect: "8ecc35b97d93618c7a945a4e945b8919a71138eec8c3381260c1d1cc9595ed0b",
		},
		{
			name: "multi-file",
			files: []file{
				{path: configJSON, content: []byte(`{"model": "test", "version": "1.0"}`)},
				{path: weightsBin, content: fill(0xAB, 1024)},
				{path: "subdir/adapter.bin", content: fill(0xCD, 512)},
			},
			expect: "f80be2143728d736125937042ab2e36657a156208e98982b99ba13b869c51310",
		},
		{
			name: "binary-content",
			files: []file{
				{path: "header.bin", content: []byte{0x00, 0x01, 0xff, 0xfe, 0x00, 0x00, 0x89, 0x50, 0x4e, 0x47}},
				{path: weightsBin, content: seq(4)},
			},
			expect: "4b32d770d69eb4076a18fc25d735e3e63e255f542baeef244aac381f73135fe5",
		},
		{
			name: "with-dotfiles",
			files: []file{
				{path: ".config", content: []byte("config data")},
				{path: ".env.example", content: []byte("env example")},
				{path: modelBin, content: []byte("model")},
			},
			expect: "31f4c970f4512286626f76d1b994c6168a257cf85eda853f23580e3c1870cb1f",
		},
		{
			name: "with-empty-file",
			files: []file{
				{path: "empty.bin"},
				{path: signme1, content: []byte("signme-1")},
			},
			expect: "3554923ee47a3be2ec029fe4eba3b9ccde3192433b6ecfff693f7803952dd9df",
		},
		{
			// .git, .gitignore, .gitattributes and .github at the root are
			// excluded without being listed as ignore paths.
			name: "with-git-dir",
			files: []file{
				{path: gitAttrs},
				{path: gitIgnore},
				{path: modelBin, content: []byte("model data")},
				{path: gitHead, content: []byte("git object")},
				{path: ".github/ci.yml", content: []byte("workflow")},
			},
			expect: "4ded26095c206dccabad3b97e41dd418c755866946b61bbeb765d7c93f2c9e4f",
		},
		{
			name: "hidden-subdir",
			files: []file{
				{path: modelBin, content: []byte("main model")},
				{path: ".cache/weights.bin", content: []byte("cached weights")},
				{path: ".local/share/data.bin", content: []byte("local data")},
			},
			expect: "bb4243c7f0726a09b88d8b96a9cf2c7f176c425dc5f8e4e83637103be5a10e06",
		},
		{
			// Default exclusions only apply at the top level.
			name: "with-nested-gitignore",
			files: []file{
				{path: modelBin, content: []byte("model content\n")},
				{path: "subdir/" + gitIgnore, content: []byte("nested gitignore\n")},
			},
			expect: "55ece539253dfaf534604fca3f12af263337557f4b5648f1fd5586ae905c8df1",
		},
		{
			name: "unicode-names",
			files: []file{
				{path: weightsBin, content: []byte("weights")},
				{path: "模型.bin", content: []byte("model data")}, //nolint:gosmopolitan // the fixture has a non-Latin name on purpose
			},
			expect: "70db9bd7de3e64e48b95fa943f63c18001e1d609ee8b1bb492ecd0398ca9e049",
		},
		{
			name: "special-chars",
			files: []file{
				{path: "file (copy).bin", content: []byte("file1")},
				{path: "normal.bin", content: []byte("file3")},
				{path: "path with spaces/model.bin", content: []byte("file2")},
			},
			expect: "926e19bfa7417f64da758090ae60fcd8c51c395abeb8660aba811b98a387fba1",
		},
		{
			name: "deeply-nested-with-git",
			files: []file{
				{path: "a/very/deep/directory/tree/weights.bin", content: []byte("deep weights")},
				{path: gitHead, content: []byte("git object")},
			},
			expect: "b61fc85907c641460b608f9033bc9273894efb7a0d5aae7147ff20e19585825b",
		},
		{
			// A nested .git is not excluded by default, the suite lists it.
			name: "multi-git-dirs",
			files: []file{
				{path: modelBin, content: []byte("main model")},
				{path: gitHead, content: []byte("git root")},
				{path: "submodule/model.bin", content: []byte("sub model")},
				{path: "submodule/.git/HEAD", content: []byte("git sub"), ignored: true},
			},
			expect: "6b5e34b794f08138bc4057e00825b142785f2a9ec638aa952d24cdeeb11e8d73",
		},
		{
			name: "with-assets-subdir",
			files: []file{
				{path: weightsBin, content: []byte("weights")},
				{path: configJSON, content: []byte(`{"version": "1.0"}`)},
				{path: "assets/vocab.txt", content: []byte("vocabulary data")},
				{path: "assets/tokenizer.bin", content: fill(0xAA, 128)},
			},
			expect: "c379689149e43172c08040a0b05368ef2fb0422fb4ce19dc3f5c4f2b6d191955",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), tc.name)
			opts := options.Default()
			for _, f := range tc.files {
				full := filepath.Join(root, filepath.FromSlash(f.path))
				if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, f.content, 0o600); err != nil {
					t.Fatal(err)
				}
				if f.ignored {
					// The conformance adapters get ignore paths as
					// absolute paths.
					opts.IgnorePaths = append(opts.IgnorePaths, full)
				}
			}

			digest, err := ComputeDigest(root, opts)
			if err != nil {
				t.Fatalf("ComputeDigest: %v", err)
			}
			if digest != "sha256:"+tc.expect {
				t.Errorf("root digest mismatch:\n got %s\nwant sha256:%s", digest, tc.expect)
			}

			// Relative ignore paths must give the same answer.
			rel := options.Default()
			for _, f := range tc.files {
				if f.ignored {
					rel.IgnorePaths = append(rel.IgnorePaths, f.path)
				}
			}
			relDigest, err := ComputeDigest(root, rel)
			if err != nil {
				t.Fatalf("ComputeDigest with relative ignores: %v", err)
			}
			if relDigest != digest {
				t.Errorf("relative ignore paths gave %s, absolute gave %s", relDigest, digest)
			}
		})
	}
}

// User ignore paths match exact relative paths only: ignoring "ignore-me"
// leaves "subdir/ignore-me" in the manifest (OMS section 6.2.1, the
// key-ignore-paths-exact-match conformance case).
func TestOMSIgnorePathsExactMatch(t *testing.T) {
	root := t.TempDir()
	for p, c := range map[string]string{
		ignoreMe:             "top-level ignore\n",
		signme1:              "signme content\n",
		"subdir/" + ignoreMe: "nested ignore\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	opts := options.Default()
	opts.IgnorePaths = []string{ignoreMe}
	m, err := New(opts).Serialize(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 2 || m.Files[0].GetName() != signme1 || m.Files[1].GetName() != "subdir/"+ignoreMe {
		t.Fatalf("unexpected manifest: %+v", m.Files)
	}
	digest, err := ComputeRootDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "402c6c4192984b634134681664f6dc142d9b2c31b278305e8b8cdc3df0454efb" {
		t.Errorf("unexpected root digest %s", digest)
	}
}

// Symlinks are rejected by default. When allowed, a link to a regular file
// is hashed through its target and recorded under the link's own name
// (OMS section 6.1.1); a link to a directory is always rejected.
func TestOMSSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, signme1), []byte("signme-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, signme2), []byte("signme-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(signme1, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	if _, err := ComputeDigest(root, options.Default()); err == nil {
		t.Fatal("expected an error for a model with a symlink")
	}

	opts := options.Default()
	opts.AllowSymlinks = true
	m, err := New(opts).Serialize(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 3 || m.Files[0].GetName() != "link" {
		t.Fatalf("expected the link in the manifest, got %+v", m.Files)
	}
	if m.Files[0].GetDigest()["sha256"] != m.Files[1].GetDigest()["sha256"] {
		t.Errorf("link digest %s differs from its target's %s", m.Files[0].GetDigest()["sha256"], m.Files[1].GetDigest()["sha256"])
	}
	digest, err := ComputeRootDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	// sha256 over the digests of signme-1 (as link), signme-1, signme-2.
	if digest != "1eae50c7504ed47f2ae7d230fd797f9ccf243f6569413bca7ddcf00b0ea52142" {
		t.Errorf("unexpected root digest %s", digest)
	}

	if err := os.Mkdir(filepath.Join(root, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(root, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := ComputeDigest(root, opts); err == nil {
		t.Fatal("expected an error for a symlink to a directory")
	}
}

// A model with nothing to hash is an error, never the digest of nothing.
func TestOMSEmptyModel(t *testing.T) {
	_, err := ComputeDigest(t.TempDir(), options.Default())
	if !errors.Is(err, ErrEmptyModel) {
		t.Fatalf("expected ErrEmptyModel, got %v", err)
	}
}
