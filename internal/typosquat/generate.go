//go:build ignore

package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"
)

type npmSearchResult struct {
	Objects []struct {
		Package struct {
			Name      string `json:"name"`
			Downloads int    `json:"downloads"` // monthly downloads from search endpoint
		} `json:"package"`
	} `json:"objects"`
	Total int `json:"total"`
}

func main() {
	allNames := make(map[string]int) // name -> downloads

	// Fetch 4 pages of 250 = 1000 packages
	for page := 0; page < 4; page++ {
		from := page * 250
		url := fmt.Sprintf("https://registry.npmjs.org/-/v1/search?text=popularity:1.0&size=250&from=%d", from)
		
		fmt.Printf("Fetching page %d...\n", page+1)
		
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fetch failed: %v\n", err)
			os.Exit(1)
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Fprintf(os.Stderr, "status %d: %s\n", resp.StatusCode, string(body))
			os.Exit(1)
		}

		var result npmSearchResult
		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Fprintf(os.Stderr, "decode failed: %v\n", err)
			os.Exit(1)
		}

		for _, obj := range result.Objects {
			name := obj.Package.Name
			// Skip scoped packages for MVP (contain @, harder to typosquat)
			if len(name) > 40 || len(name) < 2 {
				continue
			}
			allNames[name] = obj.Package.Downloads
		}

		time.Sleep(500 * time.Millisecond) // rate limit
	}

	// Sort by downloads, take top 1000
	type pair struct {
		name      string
		downloads int
	}
	pairs := make([]pair, 0, len(allNames))
	for name, dls := range allNames {
		pairs = append(pairs, pair{name, dls})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].downloads > pairs[j].downloads
	})

	if len(pairs) > 1000 {
		pairs = pairs[:1000]
	}

	names := make([]string, len(pairs))
	for i, p := range pairs {
		names[i] = p.name
	}

	// Write compressed JSON
	data, _ := json.Marshal(names)
	
	f, _ := os.Create("popular.json.gz")
	gz := gzip.NewWriter(f)
	gz.Write(data)
	gz.Close()
	f.Close()

	fmt.Printf("Wrote %d package names to popular.json.gz\n", len(names))
}
