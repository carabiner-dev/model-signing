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

## Signing models

The `pkg/oms` package turns a serialized model into the in-toto statement
OMS signs (the model's root digest as the subject, the file manifest and the
serialization settings as the predicate) and signs it into an OMS bundle
with a [policylabs/signer](https://github.com/policylabs/signer). The
signing method follows the signer: a key gives a `key` bundle, a key with a
certificate chain a `certificate` bundle, and the sigstore backend a
`sigstore` bundle.

```go
import (
	"github.com/policylabs/signer"
	soptions "github.com/policylabs/signer/options"

	"github.com/carabiner-dev/model-signing/pkg/oms"
	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

s := signer.NewSigner()
s.Options.Backend = soptions.BackendKey
s.Options.Keys = []key.PrivateKeyProvider{privateKey}

serOpts := options.Default()
serOpts.IgnorePaths = []string{"model.sig"}

bundle, err := oms.NewSigner(s, serOpts).Sign("./my-model")
if err != nil {
	return err
}
err = bundle.Write("./my-model/model.sig")
```

`oms.ReadBundle` and `oms.ParseBundle` read bundles back, report their
signing method and decode the statement and predicate.

## Verifying models

`oms.Verify` checks a bundle's signature with the trust material for its
method and then hashes the model the way the bundle records, comparing
every file with the signed manifest: listed files must exist with the
recorded digest and, unless `IgnoreUnsignedFiles` is set, no other file
may be present. `oms.VerifySignature` does the signature and statement
checks alone, `oms.VerifyModel` the manifest comparison alone.

```go
res, err := oms.Verify("./my-model", bundle, &oms.VerifyOptions{
	Keys:        publicKeys,              // key bundles
	Roots:       trustedCAs,              // certificate bundles
	Verifier:    sigstoreVerifier,        // sigstore bundles: identity and roots
	IgnorePaths: []string{"model.sig"},   // on top of the bundle's ignore paths
})
```

Key bundles are matched to the key by the hint the bundle carries;
certificate bundles need a chain leading to one of the roots with a leaf
valid at verification time and allowed to sign code; sigstore bundles go
through the policylabs signer's bundle verifier.

## oms CLI

The module ships a small CLI, `oms`, that exposes the same operations:

```
go install github.com/carabiner-dev/model-signing/cmd/oms@latest

# Print the OMS root digest of a model
oms digest ./my-model --ignore-path model.sig

# Sign a model with a key into ./my-model/model.sig
oms sign ./my-model --signing-key key.pem -o ./my-model/model.sig

# Sign with a key and its certificate chain
oms sign ./my-model --signing-key key.pem --signing-cert cert.pem --signing-cert-chain chain.pem

# Sign with sigstore (the default backend)
oms sign ./my-model

# Verify a model against a bundle
oms verify ./my-model --bundle ./my-model/model.sig --key pub.pem
oms verify ./my-model --bundle model.sig --certificate-chain ca.pem
oms verify ./my-model --bundle model.sig --sigstore-identity me@example.com --sigstore-issuer https://accounts.google.com
```

A bundle written inside the model is left out of the model's digest, as
the specification requires, and so is a bundle read from inside it. The
signing and verification flags come from
[policylabs/signer](https://github.com/policylabs/signer); run
`oms sign --help` and `oms verify --help` for the sigstore and SPIFFE
options.

## Contributing

This module is open source software by [Carabiner Systems](https://carabiner.dev),
released under the [Apache 2.0 license](LICENSE). Contributions are welcome:
file an issue to report a bug or discuss an idea, or open a pull request with
a fix. Changes that touch the digest computation should come with a test
against the OMS conformance models so the digests keep matching the ones
other implementations sign.
