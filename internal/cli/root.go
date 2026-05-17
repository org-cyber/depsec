package cli

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "depsec",
	Short: "Dependency security gate",
	Long: `depsec validates package names against registry typosquats
and scans dependencies for malicious code before installation.`,
}

func Execute() error {
	return rootCmd.Execute()
}
