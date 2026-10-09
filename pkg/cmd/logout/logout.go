// Package logout is for the logout command
package logout

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"

	"github.com/brevdev/brev-cli/pkg/cmd/cmderrors"
	"github.com/brevdev/brev-cli/pkg/cmd/tunnel"
	breverrors "github.com/brevdev/brev-cli/pkg/errors"
	"github.com/brevdev/brev-cli/pkg/nbembed"
)

type LogoutOptions struct {
	auth         Auth
	store        LogoutStore
	cleanupLocal func() error
}

type Auth interface {
	Logout() error
}

type LogoutStore interface {
	ClearDefaultOrganization() error
	GetCurrentWorkspaceID() (string, error)
}

func NewCmdLogout(auth Auth, store LogoutStore) *cobra.Command {
	opts := LogoutOptions{
		auth:         auth,
		store:        store,
		cleanupLocal: cleanupNetBird,
	}

	cmd := &cobra.Command{
		Annotations:           map[string]string{"configuration": ""},
		Use:                   "logout",
		DisableFlagsInUseLine: true,
		Short:                 "Log out of Brev",
		Long:                  "Log out of brev by deleting the credential file",
		Example:               "brev logout",
		Args:                  cmderrors.TransformToValidationError(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := opts.RunLogout()
			if err != nil {
				return breverrors.WrapAndTrace(err)
			}
			return nil
		},
	}
	return cmd
}

func (o *LogoutOptions) RunLogout() error {
	workspaceID, err := o.store.GetCurrentWorkspaceID()
	if err != nil {
		return breverrors.WrapAndTrace(err)
	}
	if workspaceID != "" {
		return fmt.Errorf("can not logout of workspace")
	}

	// best effort
	var allErr error
	if o.cleanupLocal != nil {
		if cleanupErr := o.cleanupLocal(); cleanupErr != nil {
			allErr = multierror.Append(allErr, cleanupErr)
		}
	}
	err = o.auth.Logout()
	if err != nil {
		if !strings.Contains(err.Error(), ".brev/credentials.json: no such file or directory") {
			allErr = multierror.Append(allErr, err)
		}
	}

	err = o.store.ClearDefaultOrganization()
	if err != nil {
		allErr = multierror.Append(allErr, err)
	}

	if allErr != nil {
		return breverrors.WrapAndTrace(allErr)
	}
	return nil
}

func cleanupNetBird() error {
	dir, err := nbembed.DefaultDir()
	if err != nil {
		return fmt.Errorf("resolve local NetBird identity: %w", err)
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect local NetBird identity: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, statusErr := nbembed.Status(ctx, dir)
	if statusErr == nil && !status.Enrolled && !status.Running {
		return nil
	}
	if err := tunnel.CleanupLocal(ctx, dir); err != nil {
		return fmt.Errorf("remove local NetBird identity: %w", err)
	}
	_, _ = fmt.Fprintln(os.Stderr, "Local NetBird identity removed. Ask your administrator to delete the peer in NetBird management to complete remote revocation.")
	return nil
}
