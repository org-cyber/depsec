package registry

import (
	"context"
	"fmt"
)

type pipClient struct{}

func (c *pipClient) Name() string { return "pip" }

func (c *pipClient) Check(ctx context.Context, name string) (*PackageMeta, error) {
	return nil, fmt.Errorf("pip registry not yet implemented")
}

func (c *pipClient) ResolveTree(ctx context.Context, name, version string, maxDepth int) (*TreeNode, error) {
	return nil, fmt.Errorf("pip tree resolution not yet implemented")
}
