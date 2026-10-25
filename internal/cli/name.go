package cli

import "strings"

const cleanedSuffix = "_cleaned"

// cleanedName inserts "_cleaned" before the last extension of name. Leading
// dots are a prefix, not an extension: ".env" becomes ".env_cleaned" and
// ".env.local" becomes ".env_cleaned.local".
func cleanedName(name string) string {
	rest := strings.TrimLeft(name, ".")
	prefix := name[:len(name)-len(rest)]
	if i := strings.LastIndexByte(rest, '.'); i >= 0 {
		return prefix + rest[:i] + cleanedSuffix + rest[i:]
	}
	return prefix + rest + cleanedSuffix
}

// splitTyped splits a typed path at the last "/" without cleaning it, so dir
// keeps its trailing slash (or is empty) and dir+name rebuilds the spelling
// the user typed.
func splitTyped(path string) (dir, base string) {
	i := strings.LastIndexByte(path, '/')
	return path[:i+1], path[i+1:]
}
