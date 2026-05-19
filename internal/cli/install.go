package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
	"depsec/internal/gate"
	"depsec/internal/project"
	"depsec/internal/quarantine"
	"depsec/internal/registry"
	"depsec/internal/scanner"
	"depsec/internal/typosquat"
)

var installCmd = &cobra.Command{
	Use:   "install [language] [package]",
	Short: "Intercept, validate, and scan a package (and its tree) before install",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		lang := args[0]
		pkgName := args[1]

		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get cwd: %w", err)
		}
		projType, _ := project.Detect(cwd)

		regClient, err := registry.ForLanguage(lang)
		if err != nil {
			return err
		}

		tqEngine := typosquat.New(typosquat.Top100())
		g := gate.Gate{
			Registry:  regClient,
			Typosquat: tqEngine,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		defer cancel()

		// --- FEATURE 1: Gate check on top-level package ---
		outcome, err := g.Evaluate(ctx, gate.Request{
			Language:   lang,
			Package:    pkgName,
			ProjectDir: cwd,
			ProjType:   projType,
		})
		if err != nil {
			return fmt.Errorf("gate evaluation failed: %w", err)
		}

		switch outcome.Verdict {
		case gate.Allow:
			fmt.Printf("[depsec] ALLOWED: %s@%s\n", pkgName, outcome.ResolvedVersion)

			if outcome.TarballURL != "" {
				q, err := quarantine.New()
				if err != nil {
					return fmt.Errorf("quarantine failed: %w", err)
				}
				defer q.Cleanup()

				engine := scanner.NewEngine()

				// --- FEATURE 2: Tree scanning for npm ---
				if regClient.Name() == "npm" {
					fmt.Println("[depsec] Resolving dependency tree...")

					tree, err := regClient.ResolveTree(ctx, pkgName, outcome.ResolvedVersion, 3)
					if err != nil {
						return fmt.Errorf("tree resolution failed: %w", err)
					}

					ts := scanner.NewTreeScanner(engine, q)
					results, err := ts.ScanTree(ctx, tree)
					if err != nil {
						return fmt.Errorf("tree scan failed: %w", err)
					}

					blocked := false
					for _, r := range results {
						if len(r.Findings) > 0 {
							fmt.Printf("[depsec] %s@%s findings:\n", r.Package, r.Version)
							for _, f := range r.Findings {
								fmt.Printf("  [%s] %s: %s\n", f.Severity, f.RuleID, f.Title)
								if f.Evidence != "" {
									fmt.Printf("    Evidence: %s\n", f.Evidence)
								}
							}
						}
						if r.Error != nil {
							fmt.Printf("[depsec] %s@%s scan error: %v\n", r.Package, r.Version, r.Error)
						}
						if scanner.HasCriticalOrHigh(r.Findings) {
							blocked = true
						}
					}

					if blocked {
						fmt.Println("\n[depsec] BLOCKED: malicious code detected in dependency tree.")
						os.Exit(1)
					}

					fmt.Printf("[depsec] Scanned %d unique packages in tree. Clean.\n", len(results))
				} else {
					// Non-npm: fallback to single-package scan
					pkgDir, err := q.DownloadAndExtract(outcome.TarballURL, pkgName, outcome.ResolvedVersion, outcome.Shasum)
					if err != nil {
						return fmt.Errorf("download failed: %w", err)
					}

					findings, err := engine.Scan(pkgDir)
					if err != nil {
						return fmt.Errorf("scan failed: %w", err)
					}

					if len(findings) > 0 {
						for _, f := range findings {
							fmt.Printf("  [%s] %s: %s\n", f.Severity, f.RuleID, f.Title)
						}
					}
					if scanner.HasCriticalOrHigh(findings) {
						fmt.Println("[depsec] BLOCKED: malicious code detected.")
						os.Exit(1)
					}
				}

				fmt.Println("[depsec] Proceeding with install.")
			}

			return passthrough(lang, pkgName)

		case gate.Warn:
			fmt.Printf("[depsec] WARNING: %s\n", outcome.Reason)
			if outcome.Suggestion != "" {
				fmt.Printf("           Did you mean: %s?\n", outcome.Suggestion)
			}
			fmt.Print("Install anyway? [y/N]: ")
			var resp string
			fmt.Scanln(&resp)
			if resp == "y" || resp == "Y" {
				return passthrough(lang, pkgName)
			}
			fmt.Println("[depsec] Aborted.")
			return nil

		case gate.Block:
			fmt.Printf("[depsec] BLOCKED: %s\n", outcome.Reason)
			if outcome.Suggestion != "" {
				fmt.Printf("           Did you mean: %s?\n", outcome.Suggestion)
			}
			os.Exit(1)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(installCmd)
}

func passthrough(lang, pkg string) error {
	var cmd *exec.Cmd
	switch lang {
	case "npm":
		cmd = exec.Command("npm", "install", pkg)
	case "pip":
		cmd = exec.Command("pip", "install", pkg)
	case "cargo":
		cmd = exec.Command("cargo", "add", pkg)
	default:
		return fmt.Errorf("unsupported language: %s", lang)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
