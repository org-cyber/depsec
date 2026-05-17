package typosquat

import (
	"math"
)

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

// Top100 returns a hardcoded list of the top 100 npm packages for MVP.
func Top100() []string {
	return []string{
		"lodash", "express", "react", "react-dom", "axios", "tslib",
		"chalk", "commander", "core-js", "semver", "uuid", "debug",
		"typescript", "@types/node", "glob", "rimraf", "minimatch",
		"inherits", "ms", "mkdirp", "once", "wrappy", "safe-buffer",
		"string_decoder", "util-deprecate", "isarray", "process-nextick-args",
		"readable-stream", "yallist", "minipass", "fs-minipass", "tar",
		"color", "colors", "has-flag", "supports-color", "ansi-styles",
		"escape-string-regexp", "strip-ansi", "ansi-regex", "is-fullwidth-code-point",
		"emoji-regex", "get-stream", "pump", "end-of-stream", "once",
		"signal-exit", "wrappy", "inherits", "util", "path-is-absolute",
		"glob", "brace-expansion", "balanced-match", "concat-map", "minimatch",
		"inflight", "wrappy", "once", "mkdirp", "rimraf", "semver", "which",
		"isexe", "cross-spawn", "shebang-command", "shebang-regex",
		"strip-eof", "npm-run-path", "path-key", "is-stream", "p-finally",
		"make-dir", "pify", "jsonfile", "universalify", "graceful-fs",
		"imurmurhash", "slide", "async", "bluebird", "request", "qs",
		"form-data", "combined-stream", "delayed-stream", "mime-types",
		"mime-db", "http-errors", "setprototypeof", "statuses", "depd",
		"on-finished", "ee-first", "forwarded", "ipaddr.js", "proxy-addr",
		"range-parser", "send", "mime", "destroy", "fresh", "etag",
		"cookie", "cookie-signature", "merge-descriptors", "methods",
		"negotiator", "vary", "accepts", "mime-types", "mime-db",
	}
}

// Check compares the given name against the popular list.
func (e *Engine) Check(name string) *Result {
	for _, pop := range e.popular {
		if name == pop {
			continue // exact match is not a typosquat
		}

		dist := levenshtein(name, pop)
		maxLen := math.Max(float64(len(name)), float64(len(pop)))
		similarity := 1.0 - float64(dist)/maxLen

		// Threshold: distance <= 2 and name length >= 4
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

// Suggest returns the closest popular package name for a non-existent package.
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

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la := len(a)
	lb := len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use two rows instead of full matrix for memory efficiency
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
				curr[j-1]+1,      // insertion
				prev[j]+1,        // deletion
				prev[j-1]+cost,   // substitution
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
