// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/model-signing/pkg/oms"
)

// The "simple" model of the OMS conformance suite and the root digest of
// the signed test vectors produced from it.
const simpleRootDigest = "92745110b1ab4368471cbe31664e10174e954b113a3df333db860317b2c6dec4"

func writeSimpleModel(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "simple")
	require.NoError(t, os.MkdirAll(root, 0o750))
	for name, content := range map[string]string{"signme-1": "signme-1\n", "signme-2": "signme-2", "ignore-me": ""} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o600))
	}
	return root
}

func writeKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return path
}

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := New()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestDigest(t *testing.T) {
	t.Parallel()
	root := writeSimpleModel(t)

	out, err := run(t, "digest", root, "--ignore-path", "ignore-me")
	require.NoError(t, err)
	require.Equal(t, "sha256:"+simpleRootDigest+"\n", out)

	out, err = run(t, "digest", root)
	require.NoError(t, err)
	require.NotEqual(t, "sha256:"+simpleRootDigest+"\n", out)

	_, err = run(t, "digest")
	require.Error(t, err)
	_, err = run(t, "digest", t.TempDir())
	require.ErrorContains(t, err, "no regular files")
}

// Signing with a key writes a key bundle whose subject is the model's
// digest; a bundle written inside the model is left out of that digest.
func TestSignWithKey(t *testing.T) {
	t.Parallel()
	root := writeSimpleModel(t)
	keyPath := writeKey(t)
	sig := filepath.Join(root, "model.sig")

	out, err := run(t, "sign", root, "--signing-key", keyPath, "--ignore-path", "ignore-me", "-o", sig)
	require.NoError(t, err)
	require.Contains(t, out, simpleRootDigest)
	require.Contains(t, out, "key method")

	b, err := oms.ReadBundle(sig)
	require.NoError(t, err)
	require.Equal(t, oms.MethodKey, b.Method())
	st, err := b.Statement()
	require.NoError(t, err)
	require.Equal(t, simpleRootDigest, st.GetSubject()[0].GetDigest()["sha256"])
	p, err := b.Predicate()
	require.NoError(t, err)
	require.Contains(t, p.Serialization.IgnorePaths, "model.sig")

	// Signing again with the bundle present gives the same subject.
	out, err = run(t, "sign", root, "--signing-key", keyPath, "--ignore-path", "ignore-me", "-o", sig)
	require.NoError(t, err)
	require.Contains(t, out, simpleRootDigest)
}

func TestSignErrors(t *testing.T) {
	t.Parallel()
	root := writeSimpleModel(t)
	sig := filepath.Join(t.TempDir(), "model.sig")

	_, err := run(t, "sign", root, "--signing-key", filepath.Join(t.TempDir(), "missing.pem"), "-o", sig)
	require.ErrorContains(t, err, "signing key")

	_, err = run(t, "sign", t.TempDir(), "--signing-key", writeKey(t), "-o", sig)
	require.ErrorContains(t, err, "no regular files")

	_, err = run(t, "sign", root, "--signing-key", writeKey(t), "-o", "")
	require.ErrorContains(t, err, "no output path")
}

func TestPathInside(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	inside, rel := pathInside(filepath.Join(root, "sub", "model.sig"), root)
	require.True(t, inside)
	require.Equal(t, "sub/model.sig", rel)
	inside, _ = pathInside(filepath.Join(filepath.Dir(root), "model.sig"), root)
	require.False(t, inside)
	inside, _ = pathInside(root, root)
	require.False(t, inside)
}

// Sign then verify through the CLI with a key: the public key verifies,
// a wrong key does not, a tampered model does not, and a bundle inside
// the model is left out of it.
func TestVerifyWithKey(t *testing.T) {
	t.Parallel()
	root := writeSimpleModel(t)
	keyPath, pubPath := writeKeyPair(t)
	_, wrongPub := writeKeyPair(t)
	sig := filepath.Join(root, "model.sig")

	_, err := run(t, "sign", root, "--signing-key", keyPath, "--ignore-path", "ignore-me", "-o", sig)
	require.NoError(t, err)

	out, err := run(t, "verify", root, "--bundle", sig, "--key", pubPath)
	require.NoError(t, err)
	require.Contains(t, out, "Verified simple (sha256:"+simpleRootDigest+")")
	require.Contains(t, out, "2 files match")

	_, err = run(t, "verify", root, "--bundle", sig, "--key", wrongPub)
	require.ErrorContains(t, err, "key hint")

	_, err = run(t, "verify", root, "--bundle", sig)
	require.ErrorContains(t, err, "public key is required")

	require.NoError(t, os.WriteFile(filepath.Join(root, "extra.bin"), []byte("x"), 0o600))
	_, err = run(t, "verify", root, "--bundle", sig, "--key", pubPath)
	require.ErrorContains(t, err, "extra.bin")
	_, err = run(t, "verify", root, "--bundle", sig, "--key", pubPath, "--ignore-unsigned-files")
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(root, "signme-1"), []byte("tampered"), 0o600))
	_, err = run(t, "verify", root, "--bundle", sig, "--key", pubPath, "--ignore-unsigned-files")
	require.ErrorContains(t, err, "signme-1")
}

// writeKeyPair writes a P-256 key pair and returns the private and public
// key paths.
func writeKeyPair(t *testing.T) (privPath, pubPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dir := t.TempDir()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPath = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPath = filepath.Join(dir, "pub.pem")
	require.NoError(t, os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600))
	return privPath, pubPath
}
