package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func npmPostinstallNetworkRule() Rule {
	return Rule{
		ID:       "npm-postinstall-network",
		Title:    "Install script contains network call",
		Severity: Critical,
		Analyze: func(pkgDir string, manifest map[string]interface{}) ([]Finding, error) {
			scripts, ok := manifest["scripts"].(map[string]interface{})
			if !ok {
				return nil, nil
			}

			var findings []Finding
			for scriptName, scriptVal := range scripts {
				script, ok := scriptVal.(string)
				if !ok {
					continue
				}
				if scriptName != "preinstall" && scriptName != "install" && scriptName != "postinstall" && scriptName != "prepare" {
					continue
				}

				lower := strings.ToLower(script)
				if strings.Contains(lower, "http") || strings.Contains(lower, "curl") || strings.Contains(lower, "wget") || strings.Contains(lower, "fetch") || strings.Contains(lower, "node -e") {
					findings = append(findings, Finding{
						RuleID:      "npm-postinstall-network",
						Title:       "Install script contains network call",
						Description: fmt.Sprintf("%s script attempts network access or code execution", scriptName),
						Severity:    Critical,
						File:        "package.json",
						Evidence:    script,
					})
				}
			}
			return findings, nil
		},
	}
}

func npmPersistencePathRule() Rule {
	return Rule{
		ID:       "npm-persistence-path",
		Title:    "Package writes to IDE/AI configuration directories",
		Severity: Critical,
		Analyze: func(pkgDir string, manifest map[string]interface{}) ([]Finding, error) {
			var findings []Finding

			err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				rel, _ := filepath.Rel(pkgDir, path)
				lower := strings.ToLower(rel)

				if strings.Contains(lower, ".claude/") || strings.Contains(lower, ".vscode/") || strings.Contains(lower, ".github/workflows/") {
					findings = append(findings, Finding{
						RuleID:      "npm-persistence-path",
						Title:       "Suspicious file path in package",
						Description: fmt.Sprintf("File %s targets a persistence directory", rel),
						Severity:    Critical,
						File:        rel,
						Evidence:    rel,
					})
				}
				return nil
			})

			return findings, err
		},
	}
}
