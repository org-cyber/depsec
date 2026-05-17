package quarantine

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Manager struct {
	Root string
}

func New() (*Manager, error) {
	dir, err := os.MkdirTemp("", "depsec-*")
	if err != nil {
		return nil, err
	}
	return &Manager{Root: dir}, nil
}

func (m *Manager) Cleanup() {
	os.RemoveAll(m.Root)
}

// DownloadAndExtract fetches a tarball, verifies its SHA1 checksum against
// the registry's declared shasum, and extracts it to a temp directory.
func (m *Manager) DownloadAndExtract(url, name, version, expectedShasum string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}

	tgzPath := filepath.Join(m.Root, fmt.Sprintf("%s-%s.tgz", name, version))
	f, err := os.Create(tgzPath)
	if err != nil {
		return "", err
	}

	// Stream download into file while computing SHA1 in parallel.
	hasher := sha1.New()
	tee := io.TeeReader(resp.Body, hasher)

	if _, err := io.Copy(f, tee); err != nil {
		f.Close()
		return "", err
	}
	f.Close()

	// Verify checksum. npm registry historically uses SHA1 in the dist.shasum field.
	if expectedShasum != "" {
		actual := hex.EncodeToString(hasher.Sum(nil))
		if actual != expectedShasum {
			os.Remove(tgzPath)
			return "", fmt.Errorf("checksum mismatch: expected %s, got %s", expectedShasum, actual)
		}
	}

	extractDir := filepath.Join(m.Root, fmt.Sprintf("%s-%s", name, version))
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return "", err
	}

	if err := extractTarGz(tgzPath, extractDir); err != nil {
		return "", fmt.Errorf("extract failed: %w", err)
	}

	return extractDir, nil
}

func extractTarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(dst, header.Name)

		// Prevent path traversal attacks in malicious tarballs.
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(dst)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid tar path: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}
	return nil
}
