// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Command conformance is the adapter the OpenSSF Model Signing conformance
// suite (github.com/ossf/model-signing-spec/conformance) drives to test
// this module. It implements the suite's protocol, two subcommands that
// exit zero on success:
//
//	conformance sign-model --method key|certificate|sigstore \
//	    --model-path DIR --output-bundle FILE \
//	    [--private-key PEM] [--signing-cert PEM] [--cert-chain PEM]... \
//	    [--ignore-paths PATH]... [--identity-token TOKEN] [--use-staging]
//
//	conformance verify-model --method key|certificate|sigstore \
//	    --model-path DIR --bundle FILE \
//	    [--public-key PEM] [--cert-chain PEM]... [--ignore-paths PATH]... \
//	    [--ignore-unsigned-files] [--identity SAN] [--identity-provider ISSUER] \
//	    [--use-staging]
package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/policylabs/signer"
	"github.com/policylabs/signer/key"
	soptions "github.com/policylabs/signer/options"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/carabiner-dev/model-signing/pkg/oms"
	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: conformance sign-model|verify-model [flags]")
	}
	switch args[0] {
	case "sign-model":
		return signModel(args[1:])
	case "verify-model":
		return verifyModel(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// multi collects a repeatable flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func signModel(args []string) error {
	fs := flag.NewFlagSet("sign-model", flag.ContinueOnError)
	var (
		method     = fs.String("method", "", "key, certificate or sigstore")
		modelPath  = fs.String("model-path", "", "model to sign")
		output     = fs.String("output-bundle", "", "bundle to write")
		privateKey = fs.String("private-key", "", "PEM private key")
		cert       = fs.String("signing-cert", "", "PEM certificate of the key")
		chain      multi
		ignore     multi
		token      = fs.String("identity-token", "", "OIDC token for sigstore")
		staging    = fs.Bool("use-staging", false, "use the sigstore staging instance")
	)
	fs.Var(&chain, "cert-chain", "PEM intermediates (repeatable)")
	fs.Var(&ignore, "ignore-paths", "paths to leave out (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *modelPath == "" || *output == "" {
		return errors.New("--model-path and --output-bundle are required")
	}

	s := signer.NewSigner()
	var signOpts []soptions.SignOptFn
	switch oms.Method(*method) {
	case oms.MethodKey, oms.MethodCertificate:
		if *privateKey == "" {
			return errors.New("--private-key is required")
		}
		k, err := readPrivateKey(*privateKey)
		if err != nil {
			return err
		}
		s.Options.Backend = soptions.BackendKey
		s.Options.Keys = []key.PrivateKeyProvider{k}
		if oms.Method(*method) == oms.MethodCertificate {
			if *cert == "" {
				return errors.New("--signing-cert is required")
			}
			leaf, err := readCertificates(*cert)
			if err != nil {
				return err
			}
			intermediates, err := readCertificates(chain...)
			if err != nil {
				return err
			}
			signOpts = append(signOpts, soptions.WithCertificateChain(leaf[0], intermediates...))
		}
	case oms.MethodSigstore:
		if *staging {
			return errors.New("the sigstore staging instance is not supported")
		}
		if *token != "" {
			return errors.New("signing with a pre-issued identity token is not supported")
		}
	case oms.MethodUnknown:
		return errors.New("--method is required")
	default:
		return fmt.Errorf("unknown method %q", *method)
	}

	serOpts := options.Default()
	serOpts.IgnorePaths = append(serOpts.IgnorePaths, ignore...)
	if inside, rel := pathInside(*output, *modelPath); inside {
		serOpts.IgnorePaths = append(serOpts.IgnorePaths, rel)
	}

	bundle, err := oms.NewSigner(s, serOpts).Sign(*modelPath, signOpts...)
	if err != nil {
		return err
	}
	return bundle.Write(*output)
}

func verifyModel(args []string) error {
	fs := flag.NewFlagSet("verify-model", flag.ContinueOnError)
	var (
		method     = fs.String("method", "", "key, certificate or sigstore")
		modelPath  = fs.String("model-path", "", "model to verify")
		bundlePath = fs.String("bundle", "", "bundle to verify against")
		publicKey  = fs.String("public-key", "", "PEM public key")
		chain      multi
		ignore     multi
		unsigned   = fs.Bool("ignore-unsigned-files", false, "tolerate unsigned files")
		identity   = fs.String("identity", "", "expected sigstore identity")
		issuer     = fs.String("identity-provider", "", "expected sigstore issuer")
		staging    = fs.Bool("use-staging", false, "use the sigstore staging instance")
	)
	fs.Var(&chain, "cert-chain", "PEM trusted CA certificates (repeatable)")
	fs.Var(&ignore, "ignore-paths", "paths to leave out (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *modelPath == "" || *bundlePath == "" {
		return errors.New("--model-path and --bundle are required")
	}

	vopts := &oms.VerifyOptions{
		Method:              oms.Method(*method),
		IgnoreUnsignedFiles: *unsigned,
		IgnorePaths:         ignore,
		Verifier:            signer.NewVerifier(),
	}
	switch vopts.Method {
	case oms.MethodKey:
		if *publicKey == "" {
			return errors.New("--public-key is required")
		}
		data, err := os.ReadFile(*publicKey)
		if err != nil {
			return fmt.Errorf("reading public key: %w", err)
		}
		k, err := key.NewParser().ParsePublicKeyProvider(data)
		if err != nil {
			return fmt.Errorf("parsing public key: %w", err)
		}
		vopts.Keys = []key.PublicKeyProvider{k}
	case oms.MethodCertificate:
		roots, err := readCertificates(chain...)
		if err != nil {
			return err
		}
		vopts.Roots = roots
	case oms.MethodSigstore:
		if *staging {
			return errors.New("the sigstore staging instance is not supported")
		}
		if err := soptions.WithExpectedIdentity(*issuer, *identity)(&vopts.Verifier.Options.Verification); err != nil {
			return err
		}
	case oms.MethodUnknown:
		return errors.New("--method is required")
	default:
		return fmt.Errorf("unknown method %q", *method)
	}
	if inside, rel := pathInside(*bundlePath, *modelPath); inside {
		vopts.IgnorePaths = append(vopts.IgnorePaths, rel)
	}

	bundle, err := oms.ReadBundle(*bundlePath)
	if err != nil {
		return err
	}
	_, err = oms.Verify(*modelPath, bundle, vopts)
	return err
}

func readPrivateKey(path string) (key.PrivateKeyProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	k, err := key.NewParser().ParsePrivateKeyProvider(data)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return k, nil
}

// readCertificates reads every certificate in the given PEM files.
func readCertificates(paths ...string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading certificates: %w", err)
		}
		parsed, err := cryptoutils.UnmarshalCertificatesFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", p, err)
		}
		if len(parsed) == 0 {
			return nil, fmt.Errorf("no certificates in %q", p)
		}
		certs = append(certs, parsed...)
	}
	return certs, nil
}

// pathInside reports whether path lies under root and, if so, its path
// relative to root with forward slashes.
func pathInside(path, root string) (inside bool, rel string) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, ""
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false, ""
	}
	rel, err = filepath.Rel(absRoot, absPath)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false, ""
	}
	return true, filepath.ToSlash(rel)
}
