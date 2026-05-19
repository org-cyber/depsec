package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// -----------------------------------------------------------------------------
// Rule 1: Install scripts with network calls
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Rule 2: Persistence paths in tarball
// -----------------------------------------------------------------------------

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



// -----------------------------------------------------------------------------
// Rule 1: Install scripts with network calls
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Rule 2: Persistence paths in tarball
// -----------------------------------------------------------------------------

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


// -----------------------------------------------------------------------------
// Rule 3: Obfuscated code patterns
// -----------------------------------------------------------------------------

func npmEvalObfuscationRule() Rule {
	return Rule{
		ID:       "npm-eval-obfuscation",
		Title:    "Obfuscated code execution pattern detected",
		Severity: High,
		Analyze: func(pkgDir string, manifest map[string]interface{}) ([]Finding, error) {
			var findings []Finding

			err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				// Skip large files (minified bundles, source maps)
				if info.Size() > 500*1024 {
					return nil
				}

				// Only scan JS files
				ext := strings.ToLower(filepath.Ext(path))
				if ext != ".js" && ext != ".mjs" && ext != ".cjs" {
					return nil
				}

				data, err := os.ReadFile(path)
				if err != nil {
					return nil
				}

				content := string(data)
				lower := strings.ToLower(content)
				rel, _ := filepath.Rel(pkgDir, path)

				// Pattern 1: eval(atob(...)) or eval(Buffer.from(...).toString())
				if strings.Contains(lower, "eval(") && (strings.Contains(lower, "atob(") || strings.Contains(lower, "buffer.from")) {
					findings = append(findings, Finding{
						RuleID:      "npm-eval-obfuscation",
						Title:       "Obfuscated eval execution",
						Description: "Code uses eval() with base64 or buffer decoding, common in obfuscated malware",
						Severity:    High,
						File:        rel,
						Evidence:    extractEvidence(content, "eval"),
					})
				}

				// Pattern 2: new Function(...) with encoded strings
				if strings.Contains(lower, "new function(") || (strings.Contains(lower, "function(") && strings.Contains(lower, "atob(")) {
					findings = append(findings, Finding{
						RuleID:      "npm-eval-obfuscation",
						Title:       "Dynamic function construction",
						Description: "Code constructs functions from strings at runtime, possible code injection",
						Severity:    High,
						File:        rel,
						Evidence:    extractEvidence(content, "Function"),
					})
				}

				// Pattern 3: Long hex strings (>100 chars) with eval or Function
				if (strings.Contains(lower, "eval(") || strings.Contains(lower, "function(")) && hasLongHexString(content) {
					findings = append(findings, Finding{
						RuleID:      "npm-eval-obfuscation",
						Title:       "Hex-encoded payload with execution",
						Description: "Code contains long hexadecimal strings combined with execution primitives",
						Severity:    High,
						File:        rel,
						Evidence:    "hex string + eval/Function pattern",
					})
				}

				return nil
			})

			return findings, err
		},
	}
}

// -----------------------------------------------------------------------------
// Rule 4: Suspicious require() side effects
// -----------------------------------------------------------------------------

func npmRequireSideEffectRule() Rule {
	return Rule{
		ID:       "npm-require-side-effect",
		Title:    "Suspicious module import pattern",
		Severity: High,
		Analyze: func(pkgDir string, manifest map[string]interface{}) ([]Finding, error) {
			var findings []Finding

			// Check if this is a native/binary package
			isNative := false
			if gyp, ok := manifest["gypfile"].(bool); ok && gyp {
				isNative = true
			}

			err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				// Skip large files
				if info.Size() > 500*1024 {
					return nil
				}

				ext := strings.ToLower(filepath.Ext(path))
				if ext != ".js" && ext != ".mjs" && ext != ".cjs" {
					return nil
				}

				data, err := os.ReadFile(path)
				if err != nil {
					return nil
				}

				content := string(data)
				lower := strings.ToLower(content)
				rel, _ := filepath.Rel(pkgDir, path)

				// Pattern 1: require('child_process') in non-native packages
				if strings.Contains(lower, "require('child_process')") || strings.Contains(lower, "require(\"child_process\")") {
					if !isNative {
						findings = append(findings, Finding{
							RuleID:      "npm-require-side-effect",
							Title:       "child_process imported in non-native package",
							Description: "Package imports child_process module without declaring native bindings",
							Severity:    High,
							File:        rel,
							Evidence:    "require('child_process')",
						})
					}
				}

				// Pattern 2: require('fs') with writeFile targeting home/config dirs
				if strings.Contains(lower, "require('fs')") || strings.Contains(lower, "require(\"fs\")") {
					if strings.Contains(lower, "writefilesync") || strings.Contains(lower, "writefile") {
						if strings.Contains(lower, "homedir") || strings.Contains(lower, "userprofile") ||
							strings.Contains(lower, ".ssh") || strings.Contains(lower, ".aws") ||
							strings.Contains(lower, ".npmrc") || strings.Contains(lower, ".bashrc") {
							findings = append(findings, Finding{
								RuleID:      "npm-require-side-effect",
								Title:       "File system write to sensitive path",
								Description: "Package writes to user home or config directories using fs module",
								Severity:    Critical,
								File:        rel,
								Evidence:    "fs.writeFile targeting sensitive path",
							})
						}
					}
				}

				// Pattern 3: require('http') or require('https') at top level
				if (strings.Contains(lower, "require('http')") || strings.Contains(lower, "require('https')") ||
					strings.Contains(lower, "require(\"http\")") || strings.Contains(lower, "require(\"https\")")) &&
					!strings.Contains(lower, "function") && !strings.Contains(lower, "=>") {
					findings = append(findings, Finding{
						RuleID:      "npm-require-side-effect",
						Title:       "Top-level HTTP module import",
						Description: "Package imports HTTP/HTTPS at module load time rather than on-demand",
						Severity:    Medium,
						File:        rel,
						Evidence:    "require('http') at top level",
					})
				}

				return nil
			})

			return findings, err
		},
	}
}

// -----------------------------------------------------------------------------
// Rule 5: Unexpected native binaries
// -----------------------------------------------------------------------------

func npmBinaryDropRule() Rule {
	return Rule{
		ID:       "npm-binary-drop",
		Title:    "Unexpected native binary in package",
		Severity: High,
		Analyze: func(pkgDir string, manifest map[string]interface{}) ([]Finding, error) {
			var findings []Finding

			// Check if package declares native bindings
			isNative := false
			if gyp, ok := manifest["gypfile"].(bool); ok && gyp {
				isNative = true
			}
			if scripts, ok := manifest["scripts"].(map[string]interface{}); ok {
				if _, hasInstall := scripts["install"]; hasInstall {
					isNative = true
				}
			}
			if deps, ok := manifest["dependencies"].(map[string]interface{}); ok {
				if _, hasBindings := deps["bindings"]; hasBindings {
					isNative = true
				}
				if _, hasNan := deps["nan"]; hasNan {
					isNative = true
				}
				if _, hasNapi := deps["node-addon-api"]; hasNapi {
					isNative = true
				}
			}

			if isNative {
				return nil, nil
			}

			err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				// Skip large files
				if info.Size() > 500*1024 {
					return nil
				}

				rel, _ := filepath.Rel(pkgDir, path)
				lower := strings.ToLower(rel)

				isBinary := strings.HasSuffix(lower, ".exe") ||
					strings.HasSuffix(lower, ".dll") ||
					strings.HasSuffix(lower, ".so") ||
					strings.HasSuffix(lower, ".dylib") ||
					strings.HasSuffix(lower, ".bin")

				if isBinary {
					findings = append(findings, Finding{
						RuleID:      "npm-binary-drop",
						Title:       "Native binary in non-native package",
						Description: fmt.Sprintf("Package contains %s but does not declare native bindings", filepath.Ext(rel)),
						Severity:    High,
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


if err != nil {
					return nil
				}

				content := string(data)
				lower := strings.ToLower(content)
				rel, _ := filepath.Rel(pkgDir, path)

				// Pattern 1: eval(atob(...)) or eval(Buffer.from(...).toString())
				if strings.Contains(lower, "eval(") && (strings.Contains(lower, "atob(") || strings.Contains(lower, "buffer.from")) {
					findings = append(findings, Finding{
						RuleID:      "npm-eval-obfuscation",
						Title:       "Obfuscated eval execution",
						Description: "Code uses eval() with base64 or buffer decoding, common in obfuscated malware",
						Severity:    High,
						File:        rel,
						Evidence:    extractEvidence(content, "eval"),
					})
				}

				// Pattern 2: new Function(...) with encoded strings
				if strings.Contains(lower, "new function(") || strings.Contains(lower, "function(") && strings.Contains(lower, "atob(") {
					findings = append(findings, Finding{
						RuleID:      "npm-eval-obfuscation",
						Title:       "Dynamic function construction",
						Description: "Code constructs functions from strings at runtime, possible code injection",
						Severity:    High,
						File:        rel,
						Evidence:    extractEvidence(content, "Function"),
					})
				}

				// Pattern 3: Long hex strings (>100 chars) with eval or Function
				if (strings.Contains(lower, "eval(") || strings.Contains(lower, "function(")) && hasLongHexString(content) {
					findings = append(findings, Finding{
						RuleID:      "npm-eval-obfuscation",
						Title:       "Hex-encoded payload with execution",
						Description: "Code contains long hexadecimal strings combined with execution primitives",
						Severity:    High,
						File:        rel,
						Evidence:    "hex string + eval/Function pattern",
					})
				}

				return nil
			})

			return findings, err
		},
	}
}

// -----------------------------------------------------------------------------
// Rule 4: Suspicious require() side effects
// -----------------------------------------------------------------------------

func npmRequireSideEffectRule() Rule {
	return Rule{
		ID:       "npm-require-side-effect",
		Title:    "Suspicious module import pattern",
		Severity: High,
		Analyze: func(pkgDir string, manifest map[string]interface{}) ([]Finding, error) {
			var findings []Finding

			// Check if this is a native/binary package (has gypfile or bindings)
			isNative := false
			if gyp, ok := manifest["gypfile"].(bool); ok && gyp {
				isNative = true
			}

			err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				if !strings.HasSuffix(strings.ToLower(path), ".js") &&
					!strings.HasSuffix(strings.ToLower(path), ".mjs") &&
					!strings.HasSuffix(strings.ToLower(path), ".cjs") {
					return nil
				}

				data, err := os.ReadFile(path)
				if err != nil {
					return nil
				}

				content := string(data)
				lower := strings.ToLower(content)
				rel, _ := filepath.Rel(pkgDir, path)

				// Pattern 1: require('child_process') in non-native packages
				if strings.Contains(lower, "require('child_process')") || strings.Contains(lower, "require(\"child_process\")") {
					if !isNative {
						findings = append(findings, Finding{
							RuleID:      "npm-require-side-effect",
							Title:       "child_process imported in non-native package",
							Description: "Package imports child_process module without declaring native bindings",
							Severity:    High,
							File:        rel,
							Evidence:    "require('child_process')",
						})
					}
				}

				// Pattern 2: require('fs') with writeFile targeting home/config dirs
				if strings.Contains(lower, "require('fs')") || strings.Contains(lower, "require(\"fs\")") {
					if strings.Contains(lower, "writefilesync") || strings.Contains(lower, "writefile") {
						if strings.Contains(lower, "homedir") || strings.Contains(lower, "userprofile") ||
							strings.Contains(lower, ".ssh") || strings.Contains(lower, ".aws") ||
							strings.Contains(lower, ".npmrc") || strings.Contains(lower, ".bashrc") {
							findings = append(findings, Finding{
								RuleID:      "npm-require-side-effect",
								Title:       "File system write to sensitive path",
								Description: "Package writes to user home or config directories using fs module",
								Severity:    Critical,
								File:        rel,
								Evidence:    "fs.writeFile targeting sensitive path",
							})
						}
					}
				}

				// Pattern 3: require('http') or require('https') at top level (not in a function)
				// Simple heuristic: appears in first 50% of file, not inside function braces
				if (strings.Contains(lower, "require('http')") || strings.Contains(lower, "require('https')") ||
					strings.Contains(lower, "require(\"http\")") || strings.Contains(lower, "require(\"https\")")) &&
					!strings.Contains(lower, "function") && !strings.Contains(lower, "=>") {
					// Very naive check - flag for review
					findings = append(findings, Finding{
						RuleID:      "npm-require-side-effect",
						Title:       "Top-level HTTP module import",
						Description: "Package imports HTTP/HTTPS at module load time rather than on-demand",
						Severity:    Medium,
						File:        rel,
						Evidence:    "require('http') at top level",
					})
				}

				return nil
			})

			return findings, err
		},
	}
}

// -----------------------------------------------------------------------------
// Rule 5: Unexpected native binaries
// -----------------------------------------------------------------------------

func npmBinaryDropRule() Rule {
	return Rule{
		ID:       "npm-binary-drop",
		Title:    "Unexpected native binary in package",
		Severity: High,
		Analyze: func(pkgDir string, manifest map[string]interface{}) ([]Finding, error) {
			var findings []Finding

			// Check if package declares native bindings
			isNative := false
			if gyp, ok := manifest["gypfile"].(bool); ok && gyp {
				isNative = true
			}
			if scripts, ok := manifest["scripts"].(map[string]interface{}); ok {
				if _, hasInstall := scripts["install"]; hasInstall {
					isNative = true
				}
			}
			if deps, ok := manifest["dependencies"].(map[string]interface{}); ok {
				if _, hasBindings := deps["bindings"]; hasBindings {
					isNative = true
				}
				if _, hasNan := deps["nan"]; hasNan {
					isNative = true
				}
				if _, hasNapi := deps["node-addon-api"]; hasNapi {
					isNative = true
				}
			}

			// If it's a known native package, be less aggressive
			if isNative {
				return nil, nil
			}

			err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				rel, _ := filepath.Rel(pkgDir, path)
				lower := strings.ToLower(rel)

				// Check for native binaries
				isBinary := strings.HasSuffix(lower, ".exe") ||
					strings.HasSuffix(lower, ".dll") ||
					strings.HasSuffix(lower, ".so") ||
					strings.HasSuffix(lower, ".dylib") ||
					strings.HasSuffix(lower, ".bin")

				if isBinary {
					findings = append(findings, Finding{
						RuleID:      "npm-binary-drop",
						Title:       "Native binary in non-native package",
						Description: fmt.Sprintf("Package contains %s but does not declare native bindings (no gypfile, no install script, no nan/node-addon-api)", filepath.Ext(rel)),
						Severity:    High,
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

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func extractEvidence(content, keyword string) string {
	// Find the line containing the keyword and return it
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 120 {
				return trimmed[:120] + "..."
			}
			return trimmed
		}
	}
	return keyword + " found"
}

func hasLongHexString(content string) bool {
	// Look for sequences of 100+ hex characters
	hexCount := 0
	for _, ch := range content {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			hexCount++
			if hexCount >= 100 {
				return true
			}
		} else {
			hexCount = 0
		}
	}
	return false
}
// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func extractEvidence(content, keyword string) string {
	// Find the line containing the keyword and return it
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
			trimmed := strings.TrimSpace(line)
			if len(trimmed) > 120 {
				return trimmed[:120] + "..."
			}
			return trimmed
		}
	}
	return keyword + " found"
}

func hasLongHexString(content string) bool {
	// Look for sequences of 100+ hex characters
	hexCount := 0
	for _, ch := range content {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') {
			hexCount++
			if hexCount >= 100 {
				return true
			}
		} else {
			hexCount = 0
		}
	}
	return false
}
