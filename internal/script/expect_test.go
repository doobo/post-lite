package script

import (
	"strings"
	"testing"
)

// Each case runs as a single pm.test; the expectation is whether it passes and,
// when it fails, which message the user sees.
func TestExpectAssertions(t *testing.T) {
	cases := []struct {
		name string
		expr string
		pass bool
		msg  string
	}{
		{name: "equal", expr: "pm.expect(200).to.equal(200)", pass: true},
		{name: "equal-number-type", expr: "pm.expect(1).to.equal(1.0)", pass: true},
		{name: "equal-fails", expr: "pm.expect(500).to.equal(200)", msg: "expected 500 to equal 200"},
		{name: "not-equal", expr: "pm.expect(1).to.not.equal(2)", pass: true},
		{name: "not-equal-fails", expr: "pm.expect(1).to.not.equal(1)", msg: "expected 1 not to equal 1"},
		{name: "string-equal", expr: `pm.expect("a").to.equal("a")`, pass: true},
		{name: "deep-equal", expr: "pm.expect({a:[1,2]}).to.deep.equal({a:[1,2]})", pass: true},
		{name: "eql", expr: "pm.expect([1,{b:2}]).to.eql([1,{b:2}])", pass: true},
		{name: "object-identity", expr: "pm.expect({a:1}).to.equal({a:1})", msg: "to equal"},
		{name: "same-reference", expr: "const o = {a:1}; pm.expect(o).to.equal(o)", pass: true},
		{name: "above", expr: "pm.expect(5).to.be.above(3)", pass: true},
		{name: "above-fails", expr: "pm.expect(2).to.be.above(3)", msg: "expected 2 to be above 3"},
		{name: "below", expr: "pm.expect(2).to.be.below(3)", pass: true},
		{name: "least", expr: "pm.expect(3).to.be.at.least(3)", pass: true},
		{name: "most", expr: "pm.expect(3).to.be.at.most(3)", pass: true},
		{name: "within", expr: "pm.expect(5).to.be.within(1, 10)", pass: true},
		{name: "within-fails", expr: "pm.expect(50).to.be.within(1, 10)", msg: "expected 50 to be within 1..10"},
		{name: "truthy", expr: "pm.expect('x').to.be.ok", pass: true},
		{name: "truthy-fails", expr: "pm.expect(0).to.be.ok", msg: "expected 0 to be truthy"},
		{name: "falsy", expr: "pm.expect(0).to.not.be.ok", pass: true},
		{name: "true", expr: "pm.expect(true).to.be.true", pass: true},
		{name: "false", expr: "pm.expect(false).to.be.false", pass: true},
		{name: "null", expr: "pm.expect(null).to.be.null", pass: true},
		{name: "undefined", expr: "pm.expect(undefined).to.be.undefined", pass: true},
		{name: "NaN", expr: "pm.expect(NaN).to.be.NaN", pass: true},
		{name: "exist", expr: "pm.expect(0).to.exist", pass: true},
		{name: "exist-fails", expr: "pm.expect(null).to.exist", msg: "expected null to exist"},
		{name: "empty-array", expr: "pm.expect([]).to.be.empty", pass: true},
		{name: "empty-string", expr: "pm.expect('').to.be.empty", pass: true},
		{name: "not-empty", expr: "pm.expect([1]).to.not.be.empty", pass: true},
		{name: "not-empty-fails", expr: "pm.expect([]).to.not.be.empty", msg: "expected [] not to be empty"},
		{name: "type", expr: "pm.expect('a').to.be.a('string')", pass: true},
		{name: "type-array", expr: "pm.expect([1]).to.be.an('array')", pass: true},
		{name: "type-number", expr: "pm.expect(1).to.be.a('number')", pass: true},
		{name: "type-fails", expr: "pm.expect(1).to.be.an('array')", msg: "expected 1 to be a array"},
		{name: "include-string", expr: "pm.expect('hello').to.include('ell')", pass: true},
		{name: "include-array", expr: "pm.expect([1,2]).to.include(2)", pass: true},
		{name: "include-object", expr: "pm.expect({a:1,b:2}).to.include({a:1})", pass: true},
		{name: "include-fails", expr: "pm.expect('hello').to.include('z')", msg: `expected "hello" to include "z"`},
		{name: "length", expr: "pm.expect([1,2,3]).to.have.length(3)", pass: true},
		{name: "length-fails", expr: "pm.expect('ab').to.have.length(3)", msg: "expected \"ab\" to have a length of 3"},
		{name: "property", expr: "pm.expect({a:1}).to.have.property('a')", pass: true},
		{name: "property-value", expr: "pm.expect({a:1}).to.have.property('a', 1)", pass: true},
		{name: "property-missing", expr: "pm.expect({}).to.have.property('a')", msg: `expected {} to have property "a"`},
		{name: "property-value-fails", expr: "pm.expect({a:1}).to.have.property('a', 2)", msg: "to have property"},
		{name: "match", expr: "pm.expect('abc').to.match(/^a/)", pass: true},
		{name: "match-fails", expr: "pm.expect('abc').to.match(/^z/)", msg: "to match /^z/"},
		{name: "oneOf", expr: "pm.expect('b').to.be.oneOf(['a','b'])", pass: true},
		{name: "oneOf-fails", expr: "pm.expect('z').to.be.oneOf(['a','b'])", msg: "to be one of"},
		{name: "satisfy", expr: "pm.expect(4).to.satisfy((n) => n % 2 === 0)", pass: true},
		{name: "satisfy-fails", expr: "pm.expect(3).to.satisfy((n) => n % 2 === 0)", msg: "to satisfy the given predicate"},
		{name: "chained", expr: "pm.expect([1]).to.be.an('array').that.is.not.empty", pass: true},
		{name: "chained-across-modifier", expr: "pm.expect(1).to.be.above(0).and.to.be.below(2)", pass: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, _ := runScript(t, "pm.test('case', () => { "+tc.expr+"; });")
			results := rt.Tests()
			if len(results) != 1 {
				t.Fatalf("recorded %d results, want 1", len(results))
			}
			if results[0].Passed != tc.pass {
				t.Fatalf("passed = %v, want %v (message %q)", results[0].Passed, tc.pass, results[0].Message)
			}
			if tc.msg != "" && !strings.Contains(results[0].Message, tc.msg) {
				t.Errorf("message = %q, want it to contain %q", results[0].Message, tc.msg)
			}
		})
	}
}

func TestExpectUnsupportedAssertionIsLoud(t *testing.T) {
	// Calling a chai method post-lite does not implement fails the script instead
	// of silently passing. (Merely *reading* an unknown property stays a no-op,
	// which is what chai 4 — the version Postman ships — does too.)
	// "Object has no member" is goja's wording for calling a missing method.
	expectJSError(t, "pm.expect(1).to.throw(Error);", "has no member 'throw'")
	expectJSError(t, "pm.expect(1).to.be.closeTo(1, 0.1);", "has no member 'closeTo'")
}

func TestTestRecording(t *testing.T) {
	rt, _ := runScript(t, `
		pm.test('first', () => { pm.expect(1).to.equal(1); });
		pm.test('second fails', () => { pm.expect(1).to.equal(2); });
		pm.test('throws', () => { throw new Error('boom'); });
		pm.test('not a function', 'nope');
		pm.test('third', () => { pm.expect('x').to.be.a('string'); });
	`)
	results := rt.Tests()
	if len(results) != 5 {
		t.Fatalf("recorded %d results, want 5: %+v", len(results), results)
	}
	wantNames := []string{"first", "second fails", "throws", "not a function", "third"}
	for i, want := range wantNames {
		if results[i].Name != want {
			t.Errorf("result %d name = %q, want %q", i, results[i].Name, want)
		}
	}
	// Every test runs: one failure does not stop the script.
	if !results[0].Passed || results[1].Passed || results[2].Passed || results[3].Passed || !results[4].Passed {
		t.Errorf("unexpected pass/fail pattern: %+v", results)
	}
	if !strings.Contains(results[1].Message, "expected 1 to equal 2") {
		t.Errorf("assertion message = %q", results[1].Message)
	}
	if !strings.Contains(results[2].Message, "boom") {
		t.Errorf("exception message = %q", results[2].Message)
	}
	if !strings.Contains(results[3].Message, "must be a function") {
		t.Errorf("bad-argument message = %q", results[3].Message)
	}
}

func TestLegacyTestsObject(t *testing.T) {
	rt, out := runScript(t, `
		tests['status is 200'] = true;
		tests['body is json'] = false;
		tests['not a boolean'] = 'truthy string';
		globalThis.out = {keys: Object.keys(tests).join(',')};
	`)
	results := rt.Tests()
	if len(results) != 3 {
		t.Fatalf("recorded %d results, want 3: %+v", len(results), results)
	}
	if results[0].Name != "status is 200" || !results[0].Passed {
		t.Errorf("first result = %+v", results[0])
	}
	if results[1].Passed || !strings.Contains(results[1].Message, "was set to false") {
		t.Errorf("second result = %+v", results[1])
	}
	// Truthiness decides, so a non-empty string passes (old Postman behaviour).
	if !results[2].Passed {
		t.Errorf("third result = %+v", results[2])
	}
	if out["keys"] != "status is 200,body is json,not a boolean" {
		t.Errorf("Object.keys(tests) = %v", out["keys"])
	}
}

func TestTestsAreAvailableWithoutABoundRequest(t *testing.T) {
	// pm.test/pm.expect need no request context: an assertion library that only
	// worked inside the execute pipeline would be useless for unit-ish scripts.
	rt, _ := runScript(t, "pm.test('pure', () => { pm.expect(2 + 2).to.equal(4); });")
	if len(rt.Tests()) != 1 || !rt.Tests()[0].Passed {
		t.Fatalf("results = %+v", rt.Tests())
	}
}
