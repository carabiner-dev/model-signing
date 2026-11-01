// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oms

import (
	"fmt"

	"github.com/policylabs/signer"
	soptions "github.com/policylabs/signer/options"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/model-signing/pkg/serializer/dir"
	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

// Signer signs models into OMS bundles. The signing method follows the
// policylabs signer it wraps: keys produce key bundles, keys with a
// certificate chain produce certificate bundles and the sigstore backend
// produces sigstore bundles.
type Signer struct {
	signer     *signer.Signer
	serializer *options.Options
}

// NewSigner returns a Signer that signs with s and serializes models with
// serOpts (the defaults when nil).
func NewSigner(s *signer.Signer, serOpts *options.Options) *Signer {
	if serOpts == nil {
		serOpts = options.Default()
	}
	return &Signer{signer: s, serializer: serOpts}
}

// Sign serializes the model at modelPath and signs it. The per-call sign
// options are passed to the signer; options.WithKey and
// options.WithCertificateChain select the key and certificate methods
// for this call.
func (s *Signer) Sign(modelPath string, fn ...soptions.SignOptFn) (*Bundle, error) {
	manifest, err := dir.New(s.serializer).Serialize(modelPath)
	if err != nil {
		return nil, fmt.Errorf("serializing model: %w", err)
	}
	return s.SignManifest(manifest, fn...)
}

// SignManifest signs an already serialized model.
func (s *Signer) SignManifest(m *dir.Manifest, fn ...soptions.SignOptFn) (*Bundle, error) {
	if s.signer == nil {
		return nil, fmt.Errorf("no signer configured")
	}
	st, err := NewStatement(m)
	if err != nil {
		return nil, fmt.Errorf("building statement: %w", err)
	}
	payload, err := protojson.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("encoding statement: %w", err)
	}

	// Ask for a bundle so the key backend answers with one; the other
	// backends always do. SignStatement honors per-call keys, which
	// SignStatementBundle does not.
	fn = append(append([]soptions.SignOptFn{}, fn...), soptions.WithBundle())
	art, err := s.signer.SignStatement(payload, fn...)
	if err != nil {
		return nil, fmt.Errorf("signing statement: %w", err)
	}
	ba, ok := art.(*signer.BundleArtifact)
	if !ok || ba.Bundle == nil {
		return nil, fmt.Errorf("signer produced a %T, not a bundle", art)
	}
	b := &Bundle{Bundle: ba.Bundle}
	if b.Method() == MethodUnknown {
		return nil, fmt.Errorf("signer produced verification material OMS does not define")
	}
	return b, nil
}
