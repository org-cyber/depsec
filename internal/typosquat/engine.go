package typosquat

import (
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
)

//go:embed popular.json.gz
var popularData []byte

var popularNames []string

func init() {
	var err error
	popularNames, err = loadPopular()
	if err != nil {
		// Fallback to hardcoded minimal list if embedded data fails
		popularNames = minimalFallback()
	}
}

func loadPopular() ([]string, error) {
	if len(popularData) == 0 {
		return nil, fmt.Errorf("no embedded data")
	}

	gz, err := gzip.NewReader(strings.NewReader(string(popularData)))
	if err != nil {
		return nil, err
	}
	defer gz.Close()

	data, err := io.ReadAll(gz)
	if err != nil {
		return nil, err
	}

	var names []string
	if err := json.Unmarshal(data, &names); err != nil {
		return nil, err
	}

	return names, nil
}

func minimalFallback() []string {
	return []string{
		"lodash", "express", "react", "react-dom", "axios", "tslib",
		"chalk", "commander", "core-js", "semver", "uuid", "debug",
	}
}

// Top100 returns the full embedded list (now ~926 packages).
func Top100() []string {
	return popularNames
}

type Result struct {
	IsTyposquat bool
	MatchedName string
	Similarity  float64
	Reason      string
}

type Engine struct {
	popular []string
}

func New(popular []string) *Engine {
	return &Engine{popular: popular}
}

func (e *Engine) Check(name string) *Result {
	for _, pop := range e.popular {
		if name == pop {
			continue
		}

		dist := levenshtein(name, pop)
		maxLen := math.Max(float64(len(name)), float64(len(pop)))
		similarity := 1.0 - float64(dist)/maxLen

		if dist <= 2 && len(name) >= 4 && similarity > 0.7 {
			return &Result{
				IsTyposquat: true,
				MatchedName: pop,
				Similarity:  similarity,
				Reason:      "levenshtein",
			}
		}
	}
	return &Result{IsTyposquat: false}
}

func (e *Engine) Suggest(name string) string {
	best := ""
	bestDist := 100
	for _, pop := range e.popular {
		if pop == name {
			continue
		}
		d := levenshtein(name, pop)
		if d < bestDist {
			bestDist = d
			best = pop
		}
	}
	if bestDist <= 3 {
		return best
	}
	return ""
}

func levenshtein(a, b string) int {
	la := len(a)
	lb := len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(
				curr[j-1]+1,
				prev[j]+1,
				prev[j-1]+cost,
			)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
