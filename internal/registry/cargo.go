package registry

import (
	"context"
	"fmt"
)

type cargoClient struct{}

func (c *cargoClient) Name() string { return "cargo" }

func (c *cargoClient) Check(ctx context.Context, name string) (*PackageMeta, error) {
	return nil, fmt.Errorf("cargo registry not yet implemented")
}

func (c *cargoClient) ResolveTree(ctx context.Context, name, version string, maxDepth int) (*TreeNode, error) {
	return nil, fmt.Errorf("cargo tree resolution not yet implemented")
}
