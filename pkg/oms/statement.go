// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package oms produces and reads OpenSSF Model Signing (OMS) bundles:
// sigstore bundles whose DSSE payload is an in-toto statement with the
// OMS predicate, as defined in https://github.com/ossf/model-signing-spec.
package oms

import (
	"encoding/json"
	"errors"
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/carabiner-dev/model-signing/pkg/serializer/dir"
)

const (
	// PredicateType is the predicate type of OMS statements (spec 5.1).
	PredicateType = "https://model_signing/signature/v1.0"

	// PayloadType is the DSSE payload type of the signed statement.
	PayloadType = "application/vnd.in-toto+json"

	// MethodFiles is the file serialization method (spec 6.3.1), the
	// only one this package produces.
	MethodFiles = "files"

	// HashSHA256 is the file digest algorithm this package produces.
	HashSHA256 = "sha256"
)

// Predicate is the OMS predicate body (spec 5.2).
type Predicate struct {
	Resources     []Resource    `json:"resources"`
	Serialization Serialization `json:"serialization"`
}

// Resource describes one file of the model (spec 5.2.1).
type Resource struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// Serialization records how the model was enumerated and hashed
// (spec 5.2.2), so a verifier can repeat it.
type Serialization struct {
	Method        string   `json:"method"`
	HashType      string   `json:"hash_type"`
	AllowSymlinks bool     `json:"allow_symlinks"`
	IgnorePaths   []string `json:"ignore_paths"`
}

// NewPredicate builds the OMS predicate of a serialized model.
func NewPredicate(m *dir.Manifest) (*Predicate, error) {
	if m == nil || len(m.Files) == 0 {
		return nil, errors.New("manifest has no files")
	}
	resources := make([]Resource, 0, len(m.Files))
	for _, f := range m.Files {
		digest, ok := f.GetDigest()[HashSHA256]
		if !ok {
			return nil, fmt.Errorf("file %s has no %s digest", f.GetName(), HashSHA256)
		}
		resources = append(resources, Resource{Name: f.GetName(), Algorithm: HashSHA256, Digest: digest})
	}
	ignore := m.IgnorePaths
	if ignore == nil {
		ignore = []string{}
	}
	return &Predicate{
		Resources: resources,
		Serialization: Serialization{
			Method:        MethodFiles,
			HashType:      HashSHA256,
			AllowSymlinks: m.AllowSymlinks,
			IgnorePaths:   ignore,
		},
	}, nil
}

// NewStatement builds the in-toto statement OMS signs for a serialized
// model: the model's name and root digest as the subject (spec 6.5) and
// the OMS predicate (spec 6.6).
func NewStatement(m *dir.Manifest) (*intoto.Statement, error) {
	predicate, err := NewPredicate(m)
	if err != nil {
		return nil, err
	}
	rootDigest, err := dir.ComputeRootDigest(m)
	if err != nil {
		return nil, fmt.Errorf("computing root digest: %w", err)
	}

	// Route the predicate through JSON so the struct tags decide the
	// field names and structpb gets plain values.
	data, err := json.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("encoding predicate: %w", err)
	}
	pb := &structpb.Struct{}
	if err := protojson.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("decoding predicate: %w", err)
	}

	return &intoto.Statement{
		Type: intoto.StatementTypeUri,
		Subject: []*intoto.ResourceDescriptor{{
			Name:   m.ModelName,
			Digest: map[string]string{HashSHA256: rootDigest},
		}},
		PredicateType: PredicateType,
		Predicate:     pb,
	}, nil
}

// ParseStatement reads an OMS statement from its JSON form and checks
// that it is one (spec 8.3).
func ParseStatement(data []byte) (*intoto.Statement, error) {
	st := &intoto.Statement{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("parsing statement: %w", err)
	}
	if st.GetType() != intoto.StatementTypeUri {
		return nil, fmt.Errorf("statement type is %q, want %q", st.GetType(), intoto.StatementTypeUri)
	}
	if st.GetPredicateType() != PredicateType {
		return nil, fmt.Errorf("predicate type is %q, want %q", st.GetPredicateType(), PredicateType)
	}
	if len(st.GetSubject()) != 1 {
		return nil, fmt.Errorf("statement has %d subjects, want 1", len(st.GetSubject()))
	}
	if st.GetPredicate() == nil {
		return nil, errors.New("statement has no predicate")
	}
	return st, nil
}

// PredicateOf decodes the OMS predicate of a statement.
func PredicateOf(st *intoto.Statement) (*Predicate, error) {
	if st.GetPredicate() == nil {
		return nil, errors.New("statement has no predicate")
	}
	data, err := protojson.Marshal(st.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("encoding predicate: %w", err)
	}
	p := &Predicate{}
	if err := json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("decoding predicate: %w", err)
	}
	if len(p.Resources) == 0 {
		return nil, errors.New("predicate lists no resources")
	}
	if p.Serialization.Method == "" || p.Serialization.HashType == "" {
		return nil, errors.New("predicate serialization lacks method or hash_type")
	}
	return p, nil
}
