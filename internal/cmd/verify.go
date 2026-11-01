// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/policylabs/signer"
	soptions "github.com/policylabs/signer/options"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/model-signing/pkg/oms"
)

type verifyOptions struct {
	Bundle              string
	IgnorePaths         []string
	IgnoreUnsignedFiles bool
	CertificateChain    []string
	Identity            string
	Issuer              string
	SkipIdentity        bool
	VerifierSet         *soptions.VerifierSet
}

func newVerifyCommand() *cobra.Command {
	opts := &verifyOptions{VerifierSet: soptions.DefaultVerifierSet()}
	cmd := &cobra.Command{
		Use:   "verify MODEL_PATH",
		Short: "verify a model against an OMS bundle",
		Long: `Verify a model directory (or single model file) against an OpenSSF
Model Signing bundle: the bundle's signature is checked with the trust
material for its signing method, then the model is hashed the way the
bundle records and every file is compared with the signed manifest.

A key bundle is verified with the public keys given with --key, a
certificate bundle with the CA certificates given with
--certificate-chain, and a sigstore bundle against the sigstore trust
roots and the signer identity given with --sigstore-identity and
--sigstore-issuer (or any identity with --sigstore-skip-identity).

Files in the model that the bundle does not list fail verification
unless --ignore-unsigned-files is set. The bundle file itself is left
out of the model when it lives inside it.`,
		Example: `  oms verify ./my-model --bundle ./my-model/model.sig --key pub.pem
  oms verify ./my-model --bundle model.sig --certificate-chain ca.pem
  oms verify ./my-model --bundle model.sig --sigstore-identity me@example.com --sigstore-issuer https://accounts.google.com`,
		Args: modelPathArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.run(cmd, args[0])
		},
	}
	cmd.Flags().StringVarP(&opts.Bundle, "bundle", "b", "model.sig", "path of the signature bundle to verify")
	cmd.Flags().StringSliceVar(&opts.IgnorePaths, "ignore-path", nil, "paths to leave out of the model on top of the ones the bundle records (repeatable)")
	cmd.Flags().BoolVar(&opts.IgnoreUnsignedFiles, "ignore-unsigned-files", false, "tolerate files in the model that the bundle does not list")
	cmd.Flags().StringSliceVar(&opts.CertificateChain, "certificate-chain", nil, "PEM file with CA certificates a certificate bundle's chain must lead to (repeatable)")
	cmd.Flags().StringVar(&opts.Identity, "sigstore-identity", "", "identity (certificate SAN) a sigstore bundle must be signed by")
	cmd.Flags().StringVar(&opts.Issuer, "sigstore-issuer", "", "OIDC issuer of the identity a sigstore bundle must be signed by")
	cmd.Flags().BoolVar(&opts.SkipIdentity, "sigstore-skip-identity", false, "accept a sigstore bundle signed by any identity")
	opts.VerifierSet.AddFlags(cmd)
	return cmd
}

func (o *verifyOptions) run(cmd *cobra.Command, modelPath string) error {
	if o.Bundle == "" {
		return errors.New("no bundle path specified")
	}
	if err := o.VerifierSet.Validate(); err != nil {
		return fmt.Errorf("checking verification options: %w", err)
	}

	bundle, err := oms.ReadBundle(o.Bundle)
	if err != nil {
		return err
	}

	verifier, err := signer.NewVerifierFromSet(o.VerifierSet)
	if err != nil {
		return fmt.Errorf("building verifier: %w", err)
	}
	if o.Identity != "" || o.Issuer != "" {
		if err := soptions.WithExpectedIdentity(o.Issuer, o.Identity)(&verifier.Options.Verification); err != nil {
			return fmt.Errorf("setting expected identity: %w", err)
		}
	}
	if o.SkipIdentity {
		if err := soptions.WithSkipIdentityCheck(true)(&verifier.Options.Verification); err != nil {
			return err
		}
	}
	keys, err := o.VerifierSet.Keys.ParseKeys()
	if err != nil {
		return fmt.Errorf("reading public keys: %w", err)
	}
	roots, err := readRoots(o.CertificateChain)
	if err != nil {
		return err
	}

	vopts := &oms.VerifyOptions{
		Keys:                keys,
		Roots:               roots,
		Verifier:            verifier,
		IgnoreUnsignedFiles: o.IgnoreUnsignedFiles,
		IgnorePaths:         o.IgnorePaths,
	}
	if inside, rel := pathInside(o.Bundle, modelPath); inside {
		vopts.IgnorePaths = append(vopts.IgnorePaths, rel)
	}

	res, err := oms.Verify(modelPath, bundle, vopts)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	subject := res.Statement.GetSubject()[0]
	who := res.Signer
	if who == "" {
		who = "an unnamed signer"
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Verified %s (sha256:%s): %s bundle signed by %s, %d files match\n",
		subject.GetName(), subject.GetDigest()[oms.HashSHA256], res.Method, who, res.Files)
	return err
}

// readRoots reads every certificate in the given PEM files.
func readRoots(paths []string) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading certificate chain: %w", err)
		}
		certs, err := cryptoutils.UnmarshalCertificatesFromPEM(data)
		if err != nil {
			return nil, fmt.Errorf("parsing %q: %w", p, err)
		}
		if len(certs) == 0 {
			return nil, fmt.Errorf("no certificates found in %q", p)
		}
		roots = append(roots, certs...)
	}
	return roots, nil
}
