// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/policylabs/signer/key"
	soptions "github.com/policylabs/signer/options"
	"github.com/stretchr/testify/require"
)

// signSimple signs the conformance model with a fresh key and returns the
// model path, the bundle and the key.
func signSimple(t *testing.T) (string, *Bundle, *key.Private) {
	t.Helper()
	s, k := keySigner(t)
	root := writeSimpleModel(t)
	b, err := NewSigner(s, simpleOptions()).Sign(root)
	require.NoError(t, err)
	return root, b, k
}

func publicKeys(t *testing.T, keys ...*key.Private) []key.PublicKeyProvider {
	t.Helper()
	out := make([]key.PublicKeyProvider, 0, len(keys))
	for _, k := range keys {
		pub, err := k.PublicKey()
		require.NoError(t, err)
		out = append(out, pub)
	}
	return out
}

// A key bundle verifies with its key, picks that key out of several by
// the hint, and fails with the wrong key or no key.
func TestVerifyKeyBundle(t *testing.T) {
	t.Parallel()
	root, b, k := signSimple(t)
	_, other := keySigner(t)

	res, err := Verify(root, b, &VerifyOptions{Keys: publicKeys(t, k)})
	require.NoError(t, err)
	require.Equal(t, MethodKey, res.Method)
	require.Equal(t, 2, res.Files)
	require.Equal(t, keyHint(t, k), res.Signer)
	require.Equal(t, simpleRootDigest, res.Statement.GetSubject()[0].GetDigest()[HashSHA256])

	_, err = Verify(root, b, &VerifyOptions{Keys: publicKeys(t, other, k)})
	require.NoError(t, err)

	_, err = Verify(root, b, &VerifyOptions{Keys: publicKeys(t, other)})
	require.ErrorContains(t, err, "matches the bundle's key hint")

	_, err = Verify(root, b, &VerifyOptions{})
	require.ErrorContains(t, err, "public key is required")

	_, err = Verify(root, b, &VerifyOptions{Method: MethodCertificate, Keys: publicKeys(t, k)})
	require.ErrorContains(t, err, "signed with the key method, not certificate")
	_, err = Verify(root, b, &VerifyOptions{Method: MethodKey, Keys: publicKeys(t, k)})
	require.NoError(t, err)
}

// A tampered DSSE payload does not verify even with the right key.
func TestVerifyTamperedPayload(t *testing.T) {
	t.Parallel()
	root, b, k := signSimple(t)
	env := b.GetDsseEnvelope()
	payload := append([]byte{}, env.GetPayload()...)
	payload[len(payload)-2] ^= 0x01
	env.Payload = payload
	_, err := Verify(root, b, &VerifyOptions{Keys: publicKeys(t, k)})
	require.Error(t, err)
}

// The model is checked against the manifest: changed, added and missing
// files fail, and only added files can be tolerated.
func TestVerifyModelChanges(t *testing.T) {
	t.Parallel()
	root, b, k := signSimple(t)
	opts := &VerifyOptions{Keys: publicKeys(t, k)}

	require.NoError(t, os.WriteFile(filepath.Join(root, "extra.bin"), []byte("new"), 0o600))
	_, err := Verify(root, b, opts)
	require.ErrorContains(t, err, "extra.bin: not in the signed manifest")
	opts.IgnoreUnsignedFiles = true
	_, err = Verify(root, b, opts)
	require.NoError(t, err)
	opts.IgnoreUnsignedFiles = false
	opts.IgnorePaths = []string{"extra.bin"}
	_, err = Verify(root, b, opts)
	require.NoError(t, err)
	opts.IgnorePaths = nil
	require.NoError(t, os.Remove(filepath.Join(root, "extra.bin")))

	require.NoError(t, os.WriteFile(filepath.Join(root, signme2), []byte("changed"), 0o600))
	_, err = Verify(root, b, opts)
	require.ErrorContains(t, err, "signme-2: digest")
	require.NoError(t, os.WriteFile(filepath.Join(root, signme2), []byte("signme-2"), 0o600))

	require.NoError(t, os.Remove(filepath.Join(root, signme1)))
	_, err = Verify(root, b, opts)
	require.ErrorContains(t, err, "signme-1: missing from the model")

	// Signature checks alone do not touch the model.
	_, err = VerifySignature(b, opts)
	require.NoError(t, err)
}

// testPKI builds a root CA, an intermediate and a leaf for the key.
type testPKI struct {
	root, intermediate, leaf *x509.Certificate
	notAfter                 time.Time
}

func newTestPKI(t *testing.T, leafKey crypto.PublicKey, leafEKU []x509.ExtKeyUsage) testPKI {
	t.Helper()
	notAfter := time.Now().Add(24 * time.Hour)
	newCA := func(name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              notAfter,
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		if parent == nil {
			parent, parentKey = tmpl, priv
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &priv.PublicKey, parentKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert, priv
	}
	root, rootKey := newCA("root", nil, nil)
	intermediate, intKey := newCA("intermediate", root, rootKey)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  leafEKU,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, intermediate, leafKey, intKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return testPKI{root: root, intermediate: intermediate, leaf: leaf, notAfter: notAfter}
}

// A certificate bundle verifies against its root CA, fails against another
// root, outside the leaf's validity and without a trusted root.
func TestVerifyCertificateBundle(t *testing.T) {
	t.Parallel()
	s, k := keySigner(t)
	pub, err := k.PublicKey()
	require.NoError(t, err)
	pki := newTestPKI(t, pub.Key, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})
	root := writeSimpleModel(t)

	b, err := NewSigner(s, simpleOptions()).Sign(root, soptions.WithCertificateChain(pki.leaf, pki.intermediate, pki.root))
	require.NoError(t, err)
	require.Equal(t, MethodCertificate, b.Method())

	res, err := Verify(root, b, &VerifyOptions{Roots: []*x509.Certificate{pki.root}})
	require.NoError(t, err)
	require.Equal(t, MethodCertificate, res.Method)
	require.Equal(t, "CN=leaf", res.Signer)

	otherPKI := newTestPKI(t, pub.Key, nil)
	_, err = Verify(root, b, &VerifyOptions{Roots: []*x509.Certificate{otherPKI.root}})
	require.ErrorContains(t, err, "certificate chain")

	_, err = Verify(root, b, &VerifyOptions{Roots: []*x509.Certificate{pki.root}, Now: pki.notAfter.Add(time.Hour)})
	require.ErrorContains(t, err, "certificate chain")

	_, err = Verify(root, b, &VerifyOptions{})
	require.ErrorContains(t, err, "trusted CA certificate is required")

	// A leaf without the code signing usage is refused.
	noEKU := newTestPKI(t, pub.Key, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	b, err = NewSigner(s, simpleOptions()).Sign(root, soptions.WithCertificateChain(noEKU.leaf, noEKU.intermediate))
	require.NoError(t, err)
	_, err = Verify(root, b, &VerifyOptions{Roots: []*x509.Certificate{noEKU.root}})
	require.ErrorContains(t, err, "certificate chain")
}

// A bundle whose subject digest is not the root digest of its resources
// is rejected even when its signature verifies.
func TestVerifySubjectDigestConsistency(t *testing.T) {
	t.Parallel()
	st, err := ParseStatement([]byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"m","digest":{"sha256":"` + simpleRootDigest + `"}}],"predicateType":"` + PredicateType + `","predicate":{"serialization":{"method":"files","hash_type":"sha256","allow_symlinks":false,"ignore_paths":[]},"resources":[{"name":"a","algorithm":"sha256","digest":"` + signme1Digest + `"}]}}`))
	require.NoError(t, err)
	p, err := PredicateOf(st)
	require.NoError(t, err)
	require.ErrorContains(t, checkSubjectDigest(st, p), "root digest")
}
