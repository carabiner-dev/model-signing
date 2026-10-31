# OMS Model Signing in Go

[![Go Reference](https://pkg.go.dev/badge/github.com/carabiner-dev/model-signing.svg)](https://pkg.go.dev/github.com/carabiner-dev/model-signing)
[![Tests](https://github.com/carabiner-dev/model-signing/actions/workflows/go-build-and-test.yaml/badge.svg?branch=main)](https://github.com/carabiner-dev/model-signing/actions/workflows/go-build-and-test.yaml)
[![Lint](https://github.com/carabiner-dev/model-signing/actions/workflows/golangci-lint.yaml/badge.svg?branch=main)](https://github.com/carabiner-dev/model-signing/actions/workflows/golangci-lint.yaml)
[![License](https://img.shields.io/github/license/carabiner-dev/model-signing)](LICENSE)

Go tools and code to work with
[OpenSSF Model Signing (OMS)](https://github.com/ossf/model-signing-spec)
signatures, the format produced by
[sigstore/model-transparency](https://github.com/sigstore/model-transparency).

## Model digests

The `pkg/serializer/dir` package implements the OMS `files` serialization
method: it enumerates the regular files of a model directory (or a single
file model), hashes each one with SHA-256 and computes the root digest OMS
bundles record as their statement subject (spec section 6.5.1).

```go
import (
	"github.com/carabiner-dev/model-signing/pkg/serializer/dir"
	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

opts := options.Default()
opts.IgnorePaths = []string{"model.sig"}
digest, err := dir.ComputeDigest("./my-model", opts) // "sha256:..."
```

The enumeration follows the spec: `.git`, `.gitignore`, `.gitattributes` and
`.github` at the model root are always excluded, ignore paths match exact
relative paths, symlinks are rejected unless `AllowSymlinks` is set, and an
empty model is an error. The package is checked against the models of the
OMS conformance suite, including the one behind the signed test vectors
published with the spec.

## modeldigest CLI

While this project is intended to be used as a library, it ships with a 
simple CLI to compute and print the computed digest of a model:

```
go run ./cmd/modeldigest [-ignore-paths PATH]... [-allow-symlinks] MODEL_PATH
```

Prints the root digest of the model at `MODEL_PATH`.

## Contributing

This module is open source software by [Carabiner Systems](https://carabiner.dev),
released under the [Apache 2.0 license](LICENSE). Contributions are welcome:
file an issue to report a bug or discuss an idea, or open a pull request with
a fix. Changes that touch the digest computation should come with a test
against the OMS conformance models so the digests keep matching the ones
other implementations sign.
