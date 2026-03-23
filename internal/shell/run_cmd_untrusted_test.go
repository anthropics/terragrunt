package shell_test

import (
	"testing"

	"github.com/gruntwork-io/terragrunt/internal/configbridge"
	"github.com/gruntwork-io/terragrunt/internal/shell"
	"github.com/gruntwork-io/terragrunt/pkg/options"
	"github.com/gruntwork-io/terragrunt/test/helpers/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunHclCommandWithOutput(t *testing.T) {
	t.Parallel()

	opts, err := options.NewTerragruntOptionsForTest("")
	require.NoError(t, err)

	l := logger.CreateLogger()

	t.Run("allowed by default", func(t *testing.T) {
		t.Parallel()
		out, err := shell.RunHclCommandWithOutput(t.Context(), l, configbridge.ShellRunOptsFromOpts(opts), "", true, false, "true")
		require.NoError(t, err)
		require.NotNil(t, out)
	})

	t.Run("blocked when Untrusted set", func(t *testing.T) {
		t.Parallel()

		runOpts := configbridge.ShellRunOptsFromOpts(opts)
		runOpts.Untrusted = true

		out, err := shell.RunHclCommandWithOutput(t.Context(), l, runOpts, "", true, false, "definitely-not-a-real-binary")
		require.Error(t, err)
		require.Nil(t, out)

		var target shell.HclExecDisabledError
		require.ErrorAs(t, err, &target)
		assert.Equal(t, "definitely-not-a-real-binary", target.Command)
	})

	t.Run("plumbed from TerragruntOptions", func(t *testing.T) {
		t.Parallel()

		gatedOpts, err := options.NewTerragruntOptionsForTest("")
		require.NoError(t, err)

		gatedOpts.Untrusted = true

		runOpts := configbridge.ShellRunOptsFromOpts(gatedOpts)
		require.True(t, runOpts.Untrusted)
	})
}
