// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oms

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/policylabs/signer"
	"github.com/policylabs/signer/key"
	soptions "github.com/policylabs/signer/options"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/model-signing/pkg/serializer/dir"
	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

// The "simple" model of the OMS conformance suite and the subject digest
// of the signed test vectors produced from it.
const (
	simpleRootDigest = "92745110b1ab4368471cbe31664e10174e954b113a3df333db860317b2c6dec4"
	signme1Digest    = "bc9a717db6064a32cbe9eae6fc40651dd6d36ef1757183f590eff2b1765d7ebc"
	signme2Digest    = "32dcb1f8e1ae52d5963e56a6ba06ab58b424c15ed2a6b70d2feca1d089370028"
	signme1          = "signme-1"
	signme2          = "signme-2"
	ignoreMe         = "ignore-me"
)

func writeSimpleModel(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "simple")
	require.NoError(t, os.MkdirAll(root, 0o750))
	for name, content := range map[string]string{signme1: "signme-1\n", signme2: "signme-2", ignoreMe: ""} {
		require.NoError(t, os.WriteFile(filepath.Join(root, name), []byte(content), 0o600))
	}
	return root
}

func simpleOptions() *options.Options {
	o := options.Default()
	o.IgnorePaths = []string{ignoreMe}
	return o
}

// keySigner returns a signer configured with a fresh P-256 key.
func keySigner(t *testing.T) (*signer.Signer, *key.Private) {
	t.Helper()
	k, err := key.NewGenerator().GenerateKeyPair()
	require.NoError(t, err)
	s := signer.NewSigner()
	s.Options.Backend = soptions.BackendKey
	s.Options.Keys = []key.PrivateKeyProvider{k}
	return s, k
}

func keyHint(t *testing.T, k *key.Private) string {
	t.Helper()
	pub, err := k.PublicKey()
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(pub.Key)
	require.NoError(t, err)
	sum := sha256.Sum256(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return hex.EncodeToString(sum[:])
}

// The statement built for the conformance model is the one the signed
// test vectors carry: same subject, resources and serialization.
func TestStatementMatchesVector(t *testing.T) {
	t.Parallel()
	m, err := dir.New(simpleOptions()).Serialize(writeSimpleModel(t))
	require.NoError(t, err)

	st, err := NewStatement(m)
	require.NoError(t, err)
	require.Equal(t, PredicateType, st.GetPredicateType())
	require.Len(t, st.GetSubject(), 1)
	require.Equal(t, "simple", st.GetSubject()[0].GetName())
	require.Equal(t, map[string]string{HashSHA256: simpleRootDigest}, st.GetSubject()[0].GetDigest())

	p, err := PredicateOf(st)
	require.NoError(t, err)
	require.Equal(t, []Resource{
		{Name: signme1, Algorithm: HashSHA256, Digest: signme1Digest},
		{Name: signme2, Algorithm: HashSHA256, Digest: signme2Digest},
	}, p.Resources)
	require.Equal(t, Serialization{
		Method:        MethodFiles,
		HashType:      HashSHA256,
		AllowSymlinks: false,
		IgnorePaths:   []string{".git", ".gitattributes", ".github", ".gitignore", ignoreMe},
	}, p.Serialization)

	// The JSON form parses back as an OMS statement.
	data, err := protojson.Marshal(st)
	require.NoError(t, err)
	parsed, err := ParseStatement(data)
	require.NoError(t, err)
	require.Equal(t, simpleRootDigest, parsed.GetSubject()[0].GetDigest()[HashSHA256])

	_, err = ParseStatement([]byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x","digest":{"sha256":"00"}}],"predicateType":"https://example.com/other","predicate":{}}`))
	require.ErrorContains(t, err, "predicate type")
}

// Signing with a key produces a key bundle: the hint names the key, the
// payload is the statement, the file round-trips and the signature
// verifies with the public key.
func TestSignWithKey(t *testing.T) {
	t.Parallel()
	s, k := keySigner(t)
	root := writeSimpleModel(t)

	b, err := NewSigner(s, simpleOptions()).Sign(root)
	require.NoError(t, err)
	require.Equal(t, MethodKey, b.Method())
	require.Equal(t, "application/vnd.dev.sigstore.bundle.v0.3+json", b.GetMediaType())
	require.Equal(t, keyHint(t, k), b.GetVerificationMaterial().GetPublicKey().GetHint())

	st, err := b.Statement()
	require.NoError(t, err)
	require.Equal(t, simpleRootDigest, st.GetSubject()[0].GetDigest()[HashSHA256])

	path := filepath.Join(t.TempDir(), "model.sig")
	require.NoError(t, b.Write(path))
	read, err := ReadBundle(path)
	require.NoError(t, err)
	require.Equal(t, MethodKey, read.Method())
	p, err := read.Predicate()
	require.NoError(t, err)
	require.Len(t, p.Resources, 2)

	pub, err := k.PublicKey()
	require.NoError(t, err)
	res, err := signer.NewVerifier().VerifyParsedDSSE(read.GetDsseEnvelope(), []key.PublicKeyProvider{pub})
	require.NoError(t, err)
	require.True(t, res.Verified)

	// A per-call key works on a signer configured for another backend.
	_, other := keySigner(t)
	b, err = NewSigner(signer.NewSigner(), simpleOptions()).Sign(root, soptions.WithKey(other))
	require.NoError(t, err)
	require.Equal(t, keyHint(t, other), b.GetVerificationMaterial().GetPublicKey().GetHint())
}

// A certificate chain for the key produces a certificate bundle.
func TestSignWithCertificate(t *testing.T) {
	t.Parallel()
	s, k := keySigner(t)
	priv, ok := k.Key.(crypto.Signer)
	require.True(t, ok, "key %T is not a crypto.Signer", k.Key)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	b, err := NewSigner(s, simpleOptions()).Sign(writeSimpleModel(t), soptions.WithCertificateChain(leaf))
	require.NoError(t, err)
	require.Equal(t, MethodCertificate, b.Method())
	certs := b.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	require.Len(t, certs, 1)
	require.Equal(t, der, certs[0].GetRawBytes())
}

// Signing refuses a model with nothing to hash.
func TestSignEmptyModel(t *testing.T) {
	t.Parallel()
	s, _ := keySigner(t)
	_, err := NewSigner(s, nil).Sign(t.TempDir())
	require.ErrorContains(t, err, "no regular files")
}

// The bundles published as OMS test vectors parse, report their method
// and carry the statement of the conformance model.
func TestParseVectors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		file   string
		method Method
		digest string
	}{
		{"key", MethodKey, simpleRootDigest},
		{"certificate", MethodCertificate, simpleRootDigest},
		{"sigstore", MethodSigstore, "61d4849d9d90076d6215f4d525f13d6574af8e3f67aef3e6f36fc40a14fdd226"},
	} {
		b, err := ReadBundle(filepath.Join("testdata", tc.file+".bundle.json"))
		require.NoError(t, err, tc.file)
		require.Equal(t, tc.method, b.Method(), tc.file)
		st, err := b.Statement()
		require.NoError(t, err)
		require.Equal(t, tc.digest, st.GetSubject()[0].GetDigest()[HashSHA256], tc.file)
		p, err := b.Predicate()
		require.NoError(t, err)
		require.Equal(t, MethodFiles, p.Serialization.Method)
		require.Len(t, p.Resources, 2)
	}
}
