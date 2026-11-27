package patterns

import (
	"reflect"
	"testing"
)

func TestSelectKeepsOnlyRequestedAndReportsUnknown(t *testing.T) {
	ps := []Pattern{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}

	got, unknown := Select(ps, []string{"a", "c", "typo"}, nil)
	if ids := IDs(got); !reflect.DeepEqual(ids, []string{"a", "c"}) {
		t.Fatalf("kept = %v, want [a c]", ids)
	}
	if !reflect.DeepEqual(unknown, []string{"typo"}) {
		t.Fatalf("unknown = %v, want [typo]", unknown)
	}
}

func TestSelectSkipWinsOverKeep(t *testing.T) {
	ps := []Pattern{{ID: "a"}, {ID: "b"}, {ID: "c"}}

	got, unknown := Select(ps, []string{"a", "b"}, []string{"b"})
	if ids := IDs(got); !reflect.DeepEqual(ids, []string{"a"}) {
		t.Fatalf("kept = %v, want [a]", ids)
	}
	if len(unknown) != 0 {
		t.Fatalf("unknown = %v, want none (b exists, it is just skipped after keep)", unknown)
	}
}

func TestSelectSkipOnly(t *testing.T) {
	ps := []Pattern{{ID: "a"}, {ID: "b"}, {ID: "c"}}

	got, unknown := Select(ps, nil, []string{"b"})
	if ids := IDs(got); !reflect.DeepEqual(ids, []string{"a", "c"}) {
		t.Fatalf("kept = %v, want [a c]", ids)
	}
	if len(unknown) != 0 {
		t.Fatalf("unknown = %v, want none for a skip-only call", unknown)
	}
}

func TestSelectEmptyListsReturnEverything(t *testing.T) {
	ps := []Pattern{{ID: "a"}, {ID: "b"}}

	got, unknown := Select(ps, nil, nil)
	if len(got) != 2 || len(unknown) != 0 {
		t.Fatalf("got %d rules / %v unknown, want 2 / none", len(got), unknown)
	}
	// whitespace-only entries are ignored, not treated as a real filter
	got, unknown = Select(ps, []string{" ", ""}, []string{"  "})
	if len(got) != 2 || len(unknown) != 0 {
		t.Fatalf("blank lists must behave as no filter, got %d / %v", len(got), unknown)
	}
}
