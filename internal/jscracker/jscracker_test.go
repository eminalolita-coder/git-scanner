package jscracker

import "testing"

func TestEndpointsAndPaths(t *testing.T) {
	js := []byte(`
		fetch("https://api.example.com/v1/users");
		const u = "https://cdn.example.org/app.js";
		const p = "/api/internal/metrics";
	`)
	eps := Endpoints(js)
	if len(eps) < 2 {
		t.Fatalf("expected >=2 endpoints, got %v", eps)
	}
	paths := Paths(js)
	if len(paths) == 0 {
		t.Fatal("expected at least one path")
	}
}

func TestConfigLeaks(t *testing.T) {
	js := []byte(`const cfg = { apiKey: "AIzaSyA1234567890", token: "abc123def456" };`)
	leaks := ConfigLeaks(js)
	if len(leaks) == 0 {
		t.Fatal("expected config leaks")
	}
}

func TestSourceMaps(t *testing.T) {
	js := []byte(`//# sourceMappingURL=app.js.map`)
	maps := SourceMaps(js)
	if len(maps) != 1 || maps[0] != "app.js.map" {
		t.Fatalf("got %v", maps)
	}
}

func TestSubdomains(t *testing.T) {
	js := []byte(`x("https://a.example.com/1");x("https://b.example.org/2")`)
	subs := Subdomains(js)
	if len(subs) < 2 {
		t.Fatalf("expected >=2 subdomains, got %v", subs)
	}
}
