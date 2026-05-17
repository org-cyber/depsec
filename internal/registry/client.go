package registry

import (
	"context"
	"fmt"
)

type PackageMeta struct {
	Name          string
	Version       string
	Exists        bool
	DownloadCount int64
	AuthorAgeDays int
	Published     string
	TarballURL    string
	Shasum        string
	ChecksumAlgo  string
}

type TreeNode struct {
	Name         string
	Version      string
	TarballURL   string
	Shasum       string
	ChecksumAlgo string
	Children     []*TreeNode
}

type Client interface {
	Name() string
	Check(ctx context.Context, name string) (*PackageMeta, error)
	ResolveTree(ctx context.Context, name, version string, maxDepth int) (*TreeNode, error)
}

func ForLanguage(lang string) (Client, error) {
	switch lang {
	case "npm":
		return newNPMClient(), nil
	case "pip":
		return &pipClient{}, nil
	case "cargo":
		return &cargoClient{}, nil
	default:
		return nil, fmt.Errorf("unsupported language: %s", lang)
	}
}
