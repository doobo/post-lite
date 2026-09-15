package executor

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GraphQLBody composes the JSON envelope a GraphQL endpoint expects:
//
//	{"query": "...", "variables": {...}}
//
// Variables are optional and are left out entirely when the editor is empty, so
// a query without variables produces the minimal body. They are parsed here
// rather than passed through as a string because "variables": "{\"a\":1}" (a
// string instead of an object) is the single most common way a hand-written
// GraphQL request fails, and the error message should say so instead of coming
// back from the server as a schema error.
func GraphQLBody(query, variables string) (string, error) {
	payload := map[string]any{"query": query}
	if trimmed := strings.TrimSpace(variables); trimmed != "" {
		var vars any
		if err := json.Unmarshal([]byte(trimmed), &vars); err != nil {
			return "", fmt.Errorf("graphql variables must be JSON (an object, not a string): %v", err)
		}
		payload["variables"] = vars
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("compose graphql body: %w", err)
	}
	return string(out), nil
}
