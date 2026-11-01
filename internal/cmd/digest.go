// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/model-signing/pkg/serializer/dir"
)

func newDigestCommand() *cobra.Command {
	opts := &serializerOptions{}
	cmd := &cobra.Command{
		Use:   "digest MODEL_PATH",
		Short: "compute the OMS root digest of a model",
		Long: `Compute the root digest of a model directory (or single model file) as
the OpenSSF Model Signing specification defines it: every regular file
is hashed and the digests, in path order, are hashed again. This is the
digest OMS signatures record as their subject.`,
		Example: "  oms digest ./my-model --ignore-path model.sig",
		Args:    modelPathArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			digest, err := dir.ComputeDigest(args[0], opts.Options())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), digest)
			return err
		},
	}
	opts.AddFlags(cmd)
	return cmd
}
