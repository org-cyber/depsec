package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Severity int

const (
	Clean Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return "CLEAN"
	}
}

type Finding struct {
	RuleID      string
	Title       string
	Description string
	Severity    Severity
	File        string
	Evidence    string
}

type Rule struct {
	ID       string
	Title    string
	Severity Severity
	Analyze  func(pkgDir string, manifest map[string]interface{}) ([]Finding, error)
}

type Engine struct {
	rules []Rule
}

func NewEngine() *Engine {
	return &Engine{
		rules: []Rule{
			npmPostinstallNetworkRule(),
			npmPersistencePathRule(),
		},
	}
}

func (e *Engine) Scan(pkgDir string) ([]Finding, error) {
	manifest := make(map[string]interface{})
	manifestPath := filepath.Join(pkgDir, "package", "package.json")
	if _, err := os.Stat(manifestPath); err != nil {
		manifestPath = filepath.Join(pkgDir, "package.json")
	}
	if data, err := os.ReadFile(manifestPath); err == nil {
		_ = json.Unmarshal(data, &manifest)
	}

	var allFindings []Finding
	for _, rule := range e.rules {
		findings, err := rule.Analyze(pkgDir, manifest)
		if err != nil {
			return nil, fmt.Errorf("rule %s failed: %w", rule.ID, err)
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}

func (e *Engine) HasCriticalOrHigh(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity >= High {
			return true
		}
	}
	return false
}
