package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Type string

const (
	NPM   Type = "npm"
	Pip   Type = "pip"
	Cargo Type = "cargo"
)

func Detect(dir string) (Type, error) {
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return NPM, nil
	}
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		return Pip, nil
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
		return Cargo, nil
	}
	return "", fmt.Errorf("no supported manifest found in %s", dir)
}

func IsExistingDependency(dir string, lang Type, pkgName string) (bool, error) {
	switch lang {
	case NPM:
		return isNPMDependency(dir, pkgName)
	case Pip:
		return isPipDependency(dir, pkgName)
	case Cargo:
		return isCargoDependency(dir, pkgName)
	default:
		return false, fmt.Errorf("unsupported project type: %s", lang)
	}
}

func isNPMDependency(dir, pkgName string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return false, err
	}
	var manifest struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return false, err
	}
	_, inDeps := manifest.Dependencies[pkgName]
	_, inDev := manifest.DevDependencies[pkgName]
	return inDeps || inDev, nil
}

func isPipDependency(dir, pkgName string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.FieldsFunc(line, func(r rune) bool {
			return r == '=' || r == '<' || r == '>' || r == '!' || r == '[' || r == ';'
		})[0]
		if name == pkgName {
			return true, nil
		}
	}
	return false, nil
}

func isCargoDependency(dir, pkgName string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		return false, err
	}
	content := string(data)
	inDeps := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[dependencies]" || trimmed == "[dev-dependencies]" {
			inDeps = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inDeps = false
			continue
		}
		if inDeps {
			if strings.HasPrefix(trimmed, pkgName+" ") || strings.HasPrefix(trimmed, pkgName+"=") {
				return true, nil
			}
		}
	}
	return false, nil
}
