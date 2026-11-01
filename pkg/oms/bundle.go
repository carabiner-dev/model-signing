// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oms

import (
	"errors"
	"fmt"
	"io"
	"os"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/signer/bundle"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"
)

// Method is the OMS signing method a bundle was produced with
// (spec 4.1), read from its verification material.
type Method string

const (
	// MethodKey identifies the key by a hint; verifiers bring the key.
	MethodKey Method = "key"
	// MethodCertificate carries the signing certificate and its chain.
	MethodCertificate Method = "certificate"
	// MethodSigstore carries a Fulcio certificate and a Rekor entry.
	MethodSigstore Method = "sigstore"
	// MethodUnknown is answered for material OMS does not define.
	MethodUnknown Method = ""
)

// Bundle is an OMS bundle: a sigstore bundle whose DSSE payload is an
// OMS statement.
type Bundle struct {
	*sbundle.Bundle
}

// ParseBundle parses an OMS bundle from its JSON form, checking the
// sigstore bundle structure and that the payload is an OMS statement
// (spec 8.1 and 8.3). The signature is not verified here.
func ParseBundle(data []byte) (*Bundle, error) {
	sb, err := bundle.ParseJSON(data)
	if err != nil {
		return nil, err
	}
	b := &Bundle{Bundle: sb}
	if _, err := b.Statement(); err != nil {
		return nil, err
	}
	if b.Method() == MethodUnknown {
		return nil, errors.New("bundle verification material matches no OMS signing method")
	}
	return b, nil
}

// ReadBundle reads and parses an OMS bundle file.
func ReadBundle(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading bundle: %w", err)
	}
	return ParseBundle(data)
}

// Method reports the signing method the bundle's verification material
// corresponds to.
func (b *Bundle) Method() Method {
	vm := b.GetVerificationMaterial()
	switch {
	case vm == nil:
		return MethodUnknown
	case vm.GetPublicKey() != nil:
		return MethodKey
	case vm.GetX509CertificateChain() != nil:
		return MethodCertificate
	case vm.GetCertificate() != nil && len(vm.GetTlogEntries()) > 0:
		return MethodSigstore
	default:
		return MethodUnknown
	}
}

// Statement decodes the OMS statement in the bundle's DSSE payload.
func (b *Bundle) Statement() (*intoto.Statement, error) {
	env := b.GetDsseEnvelope()
	if env == nil {
		return nil, errors.New("bundle carries no DSSE envelope")
	}
	if env.GetPayloadType() != PayloadType {
		return nil, fmt.Errorf("DSSE payload type is %q, want %q", env.GetPayloadType(), PayloadType)
	}
	return ParseStatement(env.GetPayload())
}

// Predicate decodes the OMS predicate of the bundle's statement.
func (b *Bundle) Predicate() (*Predicate, error) {
	st, err := b.Statement()
	if err != nil {
		return nil, err
	}
	return PredicateOf(st)
}

// WriteTo writes the bundle as JSON.
func (b *Bundle) WriteTo(w io.Writer) (int64, error) {
	data, err := protojson.Marshal(b.Bundle.Bundle)
	if err != nil {
		return 0, fmt.Errorf("encoding bundle: %w", err)
	}
	n, err := w.Write(data)
	return int64(n), err
}

// Write writes the bundle to a file.
func (b *Bundle) Write(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating bundle file: %w", err)
	}
	if _, err := b.WriteTo(f); err != nil {
		f.Close() //nolint:errcheck,gosec // the write error is the one to report
		return err
	}
	return f.Close()
}
