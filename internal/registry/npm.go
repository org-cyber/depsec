package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type npmClient struct {
	cache  sync.Map
	client *http.Client
}

func newNPMClient() *npmClient {
	return &npmClient{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *npmClient) Name() string { return "npm" }

type npmPackageResponse struct {
	Name     string            `json:"name"`
	DistTags map[string]string `json:"dist-tags"`
	Versions map[string]struct {
		Dist struct {
			Tarball string `json:"tarball"`
			Shasum  string `json:"shasum"`
		} `json:"dist"`
		Dependencies map[string]string `json:"dependencies"`
	} `json:"versions"`
	Time struct {
		Created  string `json:"created"`
		Modified string `json:"modified"`
	} `json:"time"`
}

func (c *npmClient) Check(ctx context.Context, name string) (*PackageMeta, error) {
	meta, err := c.fetchPackageMeta(ctx, name)
	if err != nil {
		if isNotFound(err) {
			return &PackageMeta{Name: name, Exists: false}, nil
		}
		return nil, err
	}

	latestVersion := meta.DistTags["latest"]
	var tarballURL, shasum string
	if v, ok := meta.Versions[latestVersion]; ok {
		tarballURL = v.Dist.Tarball
		shasum = v.Dist.Shasum
	}

	authorAge := -1
	if meta.Time.Created != "" {
		created, err := time.Parse(time.RFC3339, meta.Time.Created)
		if err == nil {
			authorAge = int(time.Since(created).Hours() / 24)
		}
	}

	return &PackageMeta{
		Name:          meta.Name,
		Version:       latestVersion,
		Exists:        true,
		DownloadCount: -1,
		AuthorAgeDays: authorAge,
		Published:     meta.Time.Created,
		TarballURL:    tarballURL,
		Shasum:        shasum,
		ChecksumAlgo:  "sha1",
	}, nil
}

func (c *npmClient) ResolveTree(ctx context.Context, name, version string, maxDepth int) (*TreeNode, error) {
	return c.resolveNode(ctx, name, version, maxDepth, make(map[string]bool))
}

func (c *npmClient) resolveNode(ctx context.Context, name, version string, depth int, seen map[string]bool) (*TreeNode, error) {
	if depth <= 0 {
		return nil, nil
	}

	cacheKey := name + "@" + version
	if seen[cacheKey] {
		return nil, nil
	}
	seen[cacheKey] = true

	meta, err := c.fetchPackageMeta(ctx, name)
	if err != nil {
		return nil, err
	}

	latestVersion := meta.DistTags["latest"]
	resolvedVersion := latestVersion
	if v, ok := meta.Versions[version]; ok {
		resolvedVersion = version
		tarballURL := v.Dist.Tarball
		shasum := v.Dist.Shasum

		node := &TreeNode{
			Name:         meta.Name,
			Version:      resolvedVersion,
			TarballURL:   tarballURL,
			Shasum:       shasum,
			ChecksumAlgo: "sha1",
		}

		for depName, depRange := range v.Dependencies {
			child, err := c.resolveNode(ctx, depName, depRange, depth-1, seen)
			if err != nil {
				continue
			}
			if child != nil {
				node.Children = append(node.Children, child)
			}
		}
		return node, nil
	}

	// Fallback: use latest version if specific version not found
	if v, ok := meta.Versions[latestVersion]; ok {
		node := &TreeNode{
			Name:         meta.Name,
			Version:      latestVersion,
			TarballURL:   v.Dist.Tarball,
			Shasum:       v.Dist.Shasum,
			ChecksumAlgo: "sha1",
		}

		for depName, depRange := range v.Dependencies {
			child, err := c.resolveNode(ctx, depName, depRange, depth-1, seen)
			if err != nil {
				continue
			}
			if child != nil {
				node.Children = append(node.Children, child)
			}
		}
		return node, nil
	}

	return nil, fmt.Errorf("no version found for %s", name)
}

func (c *npmClient) fetchPackageMeta(ctx context.Context, name string) (*npmPackageResponse, error) {
	// Check cache first.
	if cached, ok := c.cache.Load(name); ok {
		return cached.(*npmPackageResponse), nil
	}

	url := fmt.Sprintf("https://registry.npmjs.org/%s", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned %d", resp.StatusCode)
	}

	var npmResp npmPackageResponse
	if err := json.NewDecoder(resp.Body).Decode(&npmResp); err != nil {
		return nil, fmt.Errorf("decode registry response: %w", err)
	}

	// Store in cache.
	c.cache.Store(name, &npmResp)
	return &npmResp, nil
}

var errNotFound = fmt.Errorf("package not found")

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return err == errNotFound
}
