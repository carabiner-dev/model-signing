// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oms

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/signer"
	"github.com/policylabs/signer/key"

	"github.com/carabiner-dev/model-signing/pkg/serializer/dir"
	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

// VerifyOptions holds the trust material and settings of a verification.
type VerifyOptions struct {
	// Method, when set, is the signing method the bundle must have been
	// produced with; a bundle of another method fails verification.
	Method Method

	// Keys are the public keys a key bundle may be signed with. The one
	// matching the bundle's key hint is used.
	Keys []key.PublicKeyProvider

	// Roots are the CA certificates a certificate bundle's chain must
	// lead to.
	Roots []*x509.Certificate

	// Verifier verifies signatures. For sigstore bundles it carries the
	// expected identity and the trust roots; when nil, a default signer
	// verifier is used.
	Verifier *signer.Verifier

	// IgnoreUnsignedFiles tolerates files in the model that the manifest
	// does not list (spec 8.5). Listed files are still checked.
	IgnoreUnsignedFiles bool

	// IgnorePaths are left out of the model on top of the paths the
	// bundle records, for example the bundle file itself when it lives
	// inside the model.
	IgnorePaths []string

	// Now is the time certificate validity is checked at; zero means
	// the current time.
	Now time.Time
}

// Result describes a successful verification.
type Result struct {
	Method    Method
	Statement *intoto.Statement
	Predicate *Predicate

	// Signer names who signed: the key hint, the certificate subject or
	// the sigstore identity.
	Signer string

	// Files is the number of files the manifest lists, all of which
	// matched the model when the model was verified.
	Files int
}

// Verify checks a bundle's signature and then the model against the
// bundle's manifest (spec 8). Any failure is returned as an error.
func Verify(modelPath string, b *Bundle, opts *VerifyOptions) (*Result, error) {
	if opts == nil {
		opts = &VerifyOptions{}
	}
	res, err := VerifySignature(b, opts)
	if err != nil {
		return nil, err
	}
	if err := VerifyModel(modelPath, res.Predicate, opts); err != nil {
		return nil, err
	}
	res.Files = len(res.Predicate.Resources)
	return res, nil
}

// VerifySignature checks the bundle's signature with the trust material
// for its signing method (spec 8.2) and validates the statement it
// carries (spec 8.3). The model is not read.
func VerifySignature(b *Bundle, opts *VerifyOptions) (*Result, error) {
	if b == nil || b.Bundle == nil {
		return nil, errors.New("no bundle to verify")
	}
	if opts == nil {
		opts = &VerifyOptions{}
	}
	verifier := opts.Verifier
	if verifier == nil {
		verifier = signer.NewVerifier()
	}

	var (
		who string
		err error
	)
	method := b.Method()
	if opts.Method != MethodUnknown && opts.Method != method {
		return nil, fmt.Errorf("bundle was signed with the %s method, not %s", method, opts.Method)
	}
	switch method {
	case MethodKey:
		who, err = verifyWithKey(b, verifier, opts.Keys)
	case MethodCertificate:
		who, err = verifyWithCertificate(b, verifier, opts.Roots, opts.Now)
	case MethodSigstore:
		who, err = verifyWithSigstore(b, verifier)
	case MethodUnknown:
		return nil, errors.New("bundle verification material matches no OMS signing method")
	}
	if err != nil {
		return nil, fmt.Errorf("verifying %s signature: %w", method, err)
	}

	st, err := b.Statement()
	if err != nil {
		return nil, err
	}
	predicate, err := PredicateOf(st)
	if err != nil {
		return nil, err
	}
	if err := checkSubjectDigest(st, predicate); err != nil {
		return nil, err
	}
	return &Result{Method: method, Statement: st, Predicate: predicate, Signer: who}, nil
}

// VerifyModel enumerates the model the way the predicate records and
// checks every file against the manifest (spec 8.4): listed files must
// exist with the recorded digest and, unless unsigned files are
// tolerated, no other file may be present.
func VerifyModel(modelPath string, p *Predicate, opts *VerifyOptions) error {
	if p == nil {
		return errors.New("no predicate to verify the model against")
	}
	if opts == nil {
		opts = &VerifyOptions{}
	}
	if p.Serialization.Method != MethodFiles {
		return fmt.Errorf("serialization method %q is not supported", p.Serialization.Method)
	}
	if p.Serialization.HashType != HashSHA256 {
		return fmt.Errorf("hash type %q is not supported", p.Serialization.HashType)
	}

	serOpts := options.Default()
	serOpts.IgnorePaths = append(append([]string{}, p.Serialization.IgnorePaths...), opts.IgnorePaths...)
	serOpts.AllowSymlinks = p.Serialization.AllowSymlinks
	manifest, err := dir.New(serOpts).Serialize(modelPath)
	if err != nil {
		return fmt.Errorf("reading model: %w", err)
	}

	expected := make(map[string]string, len(p.Resources))
	for _, r := range p.Resources {
		expected[r.Name] = r.Digest
	}
	seen := make(map[string]bool, len(expected))
	var problems []error
	for _, f := range manifest.Files {
		name := f.GetName()
		want, listed := expected[name]
		if !listed {
			if !opts.IgnoreUnsignedFiles {
				problems = append(problems, fmt.Errorf("%s: not in the signed manifest", name))
			}
			continue
		}
		seen[name] = true
		if got := f.GetDigest()[HashSHA256]; got != want {
			problems = append(problems, fmt.Errorf("%s: digest %s does not match the signed %s", name, got, want))
		}
	}
	for _, r := range p.Resources {
		if !seen[r.Name] {
			problems = append(problems, fmt.Errorf("%s: missing from the model", r.Name))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("model does not match the signed manifest: %w", errors.Join(problems...))
	}
	return nil
}

// checkSubjectDigest checks that the statement's subject is the root
// digest of the resources it lists (spec 6.5.1).
func checkSubjectDigest(st *intoto.Statement, p *Predicate) error {
	want, ok := st.GetSubject()[0].GetDigest()[HashSHA256]
	if !ok {
		return errors.New("statement subject has no sha256 digest")
	}
	h := sha256.New()
	for _, r := range p.Resources {
		raw, err := hex.DecodeString(r.Digest)
		if err != nil {
			return fmt.Errorf("resource %s has a malformed digest: %w", r.Name, err)
		}
		h.Write(raw)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("subject digest %s is not the root digest of the resources (%s)", want, got)
	}
	return nil
}

// verifyWithKey verifies a key bundle: the key matching the bundle's
// hint must verify the DSSE signature.
func verifyWithKey(b *Bundle, verifier *signer.Verifier, keys []key.PublicKeyProvider) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("a public key is required to verify a key bundle")
	}
	// Bundles before OMS v1.1.0 carried the key bytes instead of a
	// hint; the sigstore protobuf cannot even represent them, so they
	// are not supported. An empty hint means every key is tried.
	hint := b.GetVerificationMaterial().GetPublicKey().GetHint()
	matching := keys
	if hint != "" {
		matching = nil
		for _, k := range keys {
			pub, err := k.PublicKey()
			if err != nil {
				return "", fmt.Errorf("reading public key: %w", err)
			}
			h, err := PublicKeyHint(pub.Key)
			if err != nil {
				return "", err
			}
			if h == hint {
				matching = append(matching, k)
			}
		}
		if len(matching) == 0 {
			return "", fmt.Errorf("none of the %d keys matches the bundle's key hint %s", len(keys), hint)
		}
	}

	res, err := verifier.VerifyParsedDSSE(b.GetDsseEnvelope(), matching)
	if err != nil {
		return "", err
	}
	if res == nil || !res.Verified {
		return "", errors.New("signature does not verify with the given key")
	}
	return hint, nil
}

// verifyWithCertificate verifies a certificate bundle: the chain must
// lead to one of the roots, with the leaf valid at the given time and
// allowed to sign code, and the leaf's key must verify the signature.
func verifyWithCertificate(b *Bundle, verifier *signer.Verifier, roots []*x509.Certificate, now time.Time) (string, error) {
	if len(roots) == 0 {
		return "", errors.New("a trusted CA certificate is required to verify a certificate bundle")
	}
	certs := b.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	if len(certs) == 0 {
		return "", errors.New("bundle carries an empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(certs[0].GetRawBytes())
	if err != nil {
		return "", fmt.Errorf("parsing signing certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for i, c := range certs[1:] {
		cert, err := x509.ParseCertificate(c.GetRawBytes())
		if err != nil {
			return "", fmt.Errorf("parsing chain certificate %d: %w", i+1, err)
		}
		intermediates.AddCert(cert)
	}
	rootPool := x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	if now.IsZero() {
		now = time.Now()
	}
	// Go treats a leaf without the extension as valid for any usage;
	// a signing certificate must say it signs code.
	if !slices.ContainsFunc(leaf.ExtKeyUsage, func(u x509.ExtKeyUsage) bool {
		return u == x509.ExtKeyUsageCodeSigning || u == x509.ExtKeyUsageAny
	}) {
		return "", errors.New("signing certificate does not carry the code signing extended key usage")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return "", fmt.Errorf("validating certificate chain: %w", err)
	}

	der, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return "", fmt.Errorf("encoding certificate key: %w", err)
	}
	prov, err := key.NewParser().ParsePublicKeyProvider(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if err != nil {
		return "", fmt.Errorf("parsing certificate key: %w", err)
	}
	res, err := verifier.VerifyParsedDSSE(b.GetDsseEnvelope(), []key.PublicKeyProvider{prov})
	if err != nil {
		return "", err
	}
	if res == nil || !res.Verified {
		return "", errors.New("signature does not verify with the certificate's key")
	}
	return leaf.Subject.String(), nil
}

// verifyWithSigstore verifies a sigstore bundle through the signer's
// bundle verifier, which checks the Fulcio chain, the transparency log
// entry and the identity the verifier expects.
func verifyWithSigstore(b *Bundle, verifier *signer.Verifier) (string, error) {
	res, err := verifier.VerifyParsedBundle(b.Bundle)
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", errors.New("bundle verification returned no result")
	}
	if res.VerifiedIdentity != nil {
		return res.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName, nil
	}
	if res.Signature != nil && res.Signature.Certificate != nil {
		return res.Signature.Certificate.SubjectAlternativeName, nil
	}
	return "", nil
}

// PublicKeyHint identifies a public key the way OMS key bundles do: the
// hex SHA-256 of its PEM-encoded SubjectPublicKeyInfo.
func PublicKeyHint(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encoding public key: %w", err)
	}
	sum := sha256.Sum256(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return hex.EncodeToString(sum[:]), nil
}
