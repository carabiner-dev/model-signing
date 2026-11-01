// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func writeModel(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "simple")
	require.NoError(t, os.MkdirAll(root, 0o750))
	for name, content := range map[string]string{"signme-1": "signme-1\n", "signme-2": "signme-2", "ignore-me": ""} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o600))
	}
	return root
}

func writePEM(t *testing.T, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600))
	return path
}

func newKey(t *testing.T) (priv *ecdsa.PrivateKey, privPath, pubPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return priv, writePEM(t, "key.pem", "PRIVATE KEY", privDER), writePEM(t, "pub.pem", "PUBLIC KEY", pubDER)
}

const flagMethod = "--method"

// sign and verify build the suite's command lines.
func sign(method, root, out string, extra ...string) error {
	return run(append([]string{"sign-model", flagMethod, method, "--model-path", root, "--output-bundle", out}, extra...))
}

func verify(method, root, bundle string, extra ...string) error {
	return run(append([]string{"verify-model", flagMethod, method, "--model-path", root, "--bundle", bundle}, extra...))
}

// The key round trip the suite runs: sign with --ignore-paths given as an
// absolute path, verify with the public key, and fail with the wrong key,
// the wrong method, an added file or a tampered one.
func TestKeyRoundTrip(t *testing.T) {
	t.Parallel()
	root := writeModel(t)
	_, privPath, pubPath := newKey(t)
	_, _, otherPub := newKey(t)
	out := filepath.Join(t.TempDir(), "model.sig")
	ignore := []string{"--ignore-paths", filepath.Join(root, "ignore-me")}

	require.NoError(t, sign("key", root, out, append(ignore, "--private-key", privPath)...))
	require.NoError(t, verify("key", root, out, append(ignore, "--public-key", pubPath)...))
	require.Error(t, verify("key", root, out, append(ignore, "--public-key", otherPub)...))
	require.Error(t, verify("certificate", root, out, "--cert-chain", pubPath))

	// The bundle records its ignore paths, so verification needs none.
	require.NoError(t, verify("key", root, out, "--public-key", pubPath))

	// A file added after signing fails, unless unsigned files are tolerated.
	require.NoError(t, os.WriteFile(filepath.Join(root, "extra.bin"), []byte("x"), 0o600))
	require.Error(t, verify("key", root, out, "--public-key", pubPath))
	require.NoError(t, verify("key", root, out, "--public-key", pubPath, "--ignore-unsigned-files"))

	require.NoError(t, os.WriteFile(filepath.Join(root, "signme-1"), []byte("tampered"), 0o600))
	require.Error(t, verify("key", root, out, "--public-key", pubPath, "--ignore-unsigned-files"))
}

// The certificate round trip: sign with the leaf and chain, verify with
// the root as trust anchor, and fail against another root.
func TestCertificateRoundTrip(t *testing.T) {
	t.Parallel()
	root := writeModel(t)
	priv, privPath, _ := newKey(t)

	newCA := func(name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert, caKey, der
	}
	ca, caKey, caDER := newCA("ca")
	_, _, otherDER := newCA("other")
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &priv.PublicKey, caKey)
	require.NoError(t, err)

	certPath := writePEM(t, "leaf.pem", "CERTIFICATE", leafDER)
	caPath := writePEM(t, "ca.pem", "CERTIFICATE", caDER)
	otherPath := writePEM(t, "other.pem", "CERTIFICATE", otherDER)
	out := filepath.Join(root, "model.sig")
	ignore := []string{"--ignore-paths", filepath.Join(root, "ignore-me")}

	require.NoError(t, sign("certificate", root, out, append(ignore, "--private-key", privPath, "--signing-cert", certPath, "--cert-chain", caPath)...))
	require.NoError(t, verify("certificate", root, out, append(ignore, "--cert-chain", caPath)...))
	require.Error(t, verify("certificate", root, out, append(ignore, "--cert-chain", otherPath)...))
}

func TestUsageErrors(t *testing.T) {
	t.Parallel()
	require.Error(t, run(nil))
	require.Error(t, run([]string{"nope"}))
	require.Error(t, run([]string{"sign-model", flagMethod, "key"}))
	require.Error(t, sign("sigstore", "x", "y", "--use-staging"))
	require.Error(t, sign("", "x", "y"))
	require.Error(t, verify("bogus", "x", "y"))
}
