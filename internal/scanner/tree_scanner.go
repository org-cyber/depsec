package scanner

import (
	"context"
	"fmt"
	"sync"

	"depsec/internal/quarantine"
	"depsec/internal/registry"
)

// TreeResult holds the scan outcome for a single package in the tree.
type TreeResult struct {
	Package  string
	Version  string
	Findings []Finding
	Error    error
}

// TreeScanner scans an entire dependency tree concurrently.
type TreeScanner struct {
	Engine     *Engine
	Quarantine *quarantine.Manager
	Workers    int
}

func NewTreeScanner(engine *Engine, q *quarantine.Manager) *TreeScanner {
	return &TreeScanner{
		Engine:     engine,
		Quarantine: q,
		Workers:    5,
	}
}

// ScanTree flattens the tree, deduplicates, and scans each unique package.
func (ts *TreeScanner) ScanTree(ctx context.Context, root *registry.TreeNode) ([]TreeResult, error) {
	var nodes []*registry.TreeNode
	flattenTree(root, &nodes)

	// Deduplicate by name@version.
	seen := make(map[string]bool)
	var unique []*registry.TreeNode
	for _, n := range nodes {
		key := n.Name + "@" + n.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, n)
	}

	results := make([]TreeResult, len(unique))
	var wg sync.WaitGroup
	sem := make(chan struct{}, ts.Workers)

	for i, node := range unique {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, n *registry.TreeNode) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				results[idx] = TreeResult{
					Package: n.Name,
					Version: n.Version,
					Error:   ctx.Err(),
				}
				return
			}

			if n.TarballURL == "" {
				results[idx] = TreeResult{
					Package: n.Name,
					Version: n.Version,
					Error:   fmt.Errorf("no tarball URL"),
				}
				return
			}

			pkgDir, err := ts.Quarantine.DownloadAndExtract(n.TarballURL, n.Name, n.Version, n.Shasum)
			if err != nil {
				results[idx] = TreeResult{
					Package: n.Name,
					Version: n.Version,
					Error:   err,
				}
				return
			}

			findings, err := ts.Engine.Scan(pkgDir)
			results[idx] = TreeResult{
				Package:  n.Name,
				Version:  n.Version,
				Findings: findings,
				Error:    err,
			}
		}(i, node)
	}

	wg.Wait()
	return results, nil
}

func flattenTree(node *registry.TreeNode, out *[]*registry.TreeNode) {
	if node == nil {
		return
	}
	*out = append(*out, node)
	for _, child := range node.Children {
		flattenTree(child, out)
	}
}

// HasCriticalOrHigh returns true if any finding is Critical or High.
func HasCriticalOrHigh(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity >= High {
			return true
		}
	}
	return false
}
