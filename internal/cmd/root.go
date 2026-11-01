// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package cmd implements the oms command line tool.
package cmd

import (
	"errors"

	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/version"

	"github.com/carabiner-dev/model-signing/pkg/serializer/options"
)

const appname = "oms"

// New returns the root command of the CLI.
func New() *cobra.Command {
	root := &cobra.Command{
		Use:   appname,
		Short: "sign AI models following the OpenSSF Model Signing spec",
		Long: `oms works with AI models following the OpenSSF Model Signing (OMS)
specification: it computes the digest of a model directory the way OMS
defines, signs models into OMS bundles with keys, certificates or
sigstore, and verifies models against those bundles.`,
		SilenceUsage: true,
	}
	root.AddCommand(newDigestCommand(), newSignCommand(), newVerifyCommand(), version.WithFont("doom"))
	return root
}

// serializerOptions are the flags that control how a model is hashed,
// shared by the commands that serialize models.
type serializerOptions struct {
	IgnorePaths    []string
	AllowSymlinks  bool
	IgnoreGitPaths bool
}

func (o *serializerOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&o.IgnorePaths, "ignore-path", nil, "paths to leave out of the model, relative to the model root (repeatable)")
	cmd.Flags().BoolVar(&o.AllowSymlinks, "allow-symlinks", false, "hash symlinks through their targets instead of rejecting them")
	cmd.Flags().BoolVar(&o.IgnoreGitPaths, "ignore-git-paths", true, "leave git metadata at the model root out of the model")
}

// Options returns the serializer options the flags describe.
func (o *serializerOptions) Options() *options.Options {
	opts := options.Default()
	opts.IgnorePaths = append(opts.IgnorePaths, o.IgnorePaths...)
	opts.AllowSymlinks = o.AllowSymlinks
	opts.IgnoreGitPaths = o.IgnoreGitPaths
	return opts
}

// modelPathArg validates that the model path is the only argument.
func modelPathArg(_ *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("the path to the model must be the only argument")
	}
	return nil
}
