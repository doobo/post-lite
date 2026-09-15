package executor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGraphQLBodyComposesTheEnvelope(t *testing.T) {
	got, err := GraphQLBody("query ($id: ID!) { user(id: $id) { name } }", `{"id":"42"}`)
	if err != nil {
		t.Fatalf("GraphQLBody: %v", err)
	}

	var payload struct {
		Query     string         `json:"query"`
		Variables map[string]any `json:"variables"`
	}
	if err := json.Unmarshal([]byte(got), &payload); err != nil {
		t.Fatalf("composed body is not JSON: %v (%s)", err, got)
	}
	if !strings.Contains(payload.Query, "user(id: $id)") {
		t.Errorf("query = %q, want the query document", payload.Query)
	}
	if payload.Variables["id"] != "42" {
		t.Errorf("variables = %v, want id=42", payload.Variables)
	}
}

// An empty variables box must not turn into "variables": "" or {}: a GraphQL
// server rejects the former and the latter is noise in every logged request.
func TestGraphQLBodyOmitsEmptyVariables(t *testing.T) {
	for _, variables := range []string{"", "   ", "\n"} {
		got, err := GraphQLBody("query { me { name } }", variables)
		if err != nil {
			t.Fatalf("GraphQLBody(%q): %v", variables, err)
		}
		if strings.Contains(got, "variables") {
			t.Errorf("GraphQLBody(%q) = %s, want no variables key", variables, got)
		}
	}
}

func TestGraphQLBodyKeepsNestedVariables(t *testing.T) {
	got, err := GraphQLBody("mutation { x }", `{"input":{"ids":[1,2],"flag":true},"n":null}`)
	if err != nil {
		t.Fatalf("GraphQLBody: %v", err)
	}
	var payload struct {
		Variables struct {
			Input struct {
				IDs  []int `json:"ids"`
				Flag bool  `json:"flag"`
			} `json:"input"`
			N *int `json:"n"`
		} `json:"variables"`
	}
	if err := json.Unmarshal([]byte(got), &payload); err != nil {
		t.Fatalf("composed body is not JSON: %v (%s)", err, got)
	}
	if len(payload.Variables.Input.IDs) != 2 || !payload.Variables.Input.Flag || payload.Variables.N != nil {
		t.Errorf("variables lost structure: %s", got)
	}
}

func TestGraphQLBodyRejectsNonJSONVariables(t *testing.T) {
	for _, variables := range []string{"id=42", "{'id':1}", `{"id":}`, "[1,2"} {
		if _, err := GraphQLBody("query { me { name } }", variables); err == nil {
			t.Errorf("GraphQLBody(%q) succeeded, want an error", variables)
		}
	}
}
