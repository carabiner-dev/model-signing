// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/policylabs/signer"
	soptions "github.com/policylabs/signer/options"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/model-signing/pkg/oms"
)

type signOptions struct {
	serializerOptions
	Output    string
	SignerSet *soptions.SignerSet
}

func newSignCommand() *cobra.Command {
	opts := &signOptions{SignerSet: soptions.DefaultSignerSet()}
	cmd := &cobra.Command{
		Use:   "sign MODEL_PATH",
		Short: "sign a model into an OMS bundle",
		Long: `Sign a model directory (or single model file) into an OpenSSF Model
Signing bundle. The model is hashed as OMS defines and the resulting
statement is signed with the configured backend: a key (--signing-key)
gives a key bundle, a key with its certificate (--signing-cert and
--signing-cert-chain) a certificate bundle, and sigstore, the default,
a keyless bundle.

The bundle is written to --output, model.sig by default. When the
output lies inside the model it is left out of the model's digest, as
the specification requires.`,
		Example: `  oms sign ./my-model --signing-key key.pem -o ./my-model/model.sig
  oms sign ./my-model --signing-key key.pem --signing-cert cert.pem --signing-cert-chain chain.pem
  oms sign ./my-model`,
		Args: modelPathArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.run(cmd, args[0])
		},
	}
	opts.AddFlags(cmd)
	cmd.Flags().StringVarP(&opts.Output, "output", "o", "model.sig", "path to write the signature bundle to")
	opts.SignerSet.AddFlags(cmd)
	return cmd
}

func (o *signOptions) run(cmd *cobra.Command, modelPath string) error {
	if o.Output == "" {
		return errors.New("no output path specified")
	}
	if err := o.SignerSet.Validate(); err != nil {
		return fmt.Errorf("checking signing options: %w", err)
	}

	serOpts := o.Options()
	if inside, rel := pathInside(o.Output, modelPath); inside {
		serOpts.IgnorePaths = append(serOpts.IgnorePaths, rel)
	}

	s, err := signer.NewSignerFromSet(o.SignerSet)
	if err != nil {
		return fmt.Errorf("building signer: %w", err)
	}

	bundle, err := oms.NewSigner(s, serOpts).Sign(modelPath)
	if err != nil {
		return err
	}
	if err := bundle.Write(o.Output); err != nil {
		return err
	}

	st, err := bundle.Statement()
	if err != nil {
		return err
	}
	subject := st.GetSubject()[0]
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Signed %s (sha256:%s) with %s method, bundle written to %s\n",
		subject.GetName(), subject.GetDigest()[oms.HashSHA256], bundle.Method(), o.Output)
	return err
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
