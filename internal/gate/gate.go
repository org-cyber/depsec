package gate

import (
	"context"
	"fmt"

	"depsec/internal/project"
	"depsec/internal/registry"
	"depsec/internal/typosquat"
)

type Verdict int

const (
	Allow Verdict = iota
	Warn
	Block
)

type Request struct {
	Language   string
	Package    string
	ProjectDir string
	ProjType   project.Type
}

type Outcome struct {
	Verdict         Verdict
	Reason          string
	Suggestion      string
	ResolvedVersion string
	TarballURL      string
	Shasum          string
}

type Gate struct {
	Registry  registry.Client
	Typosquat *typosquat.Engine
}

func (g *Gate) Evaluate(ctx context.Context, req Request) (*Outcome, error) {
	meta, err := g.Registry.Check(ctx, req.Package)
	if err != nil {
		return nil, fmt.Errorf("registry check failed: %w", err)
	}

	if !meta.Exists {
		suggestion := g.Typosquat.Suggest(req.Package)
		return &Outcome{
			Verdict:    Block,
			Reason:     fmt.Sprintf("package %q not found in registry", req.Package),
			Suggestion: suggestion,
		}, nil
	}

	// Check 2: Typosquat. Since DownloadCount is -1 (unknown) in MVP,
	// we rely on author age + similarity. Warn if package is young AND looks like a popular name.
	tqResult := g.Typosquat.Check(req.Package)
	if tqResult.IsTyposquat && meta.AuthorAgeDays >= 0 && meta.AuthorAgeDays < 30 {
		return &Outcome{
			Verdict:         Warn,
			Reason:          fmt.Sprintf("%q is suspiciously similar to popular package %q", req.Package, tqResult.MatchedName),
			Suggestion:      tqResult.MatchedName,
			ResolvedVersion: meta.Version,
			TarballURL:      meta.TarballURL,
			Shasum:          meta.Shasum,
		}, nil
	}

	// Check 3: New dependency in project + very new package
	isExisting, err := project.IsExistingDependency(req.ProjectDir, req.ProjType, req.Package)
	if err != nil {
		isExisting = false
	}

	if !isExisting && meta.AuthorAgeDays >= 0 && meta.AuthorAgeDays < 14 {
		return &Outcome{
			Verdict:         Warn,
			Reason:          fmt.Sprintf("%q is new to this project and was published %d days ago", req.Package, meta.AuthorAgeDays),
			ResolvedVersion: meta.Version,
			TarballURL:      meta.TarballURL,
			Shasum:          meta.Shasum,
		}, nil
	}

	return &Outcome{
		Verdict:         Allow,
		ResolvedVersion: meta.Version,
		TarballURL:      meta.TarballURL,
		Shasum:          meta.Shasum,
	}, nil
}
