package patterns

import (
	"sort"
	"strings"
)

// Select filters a rule set by an allowlist (keep) and a denylist (skip),
// both matching the exact rule ID. A rule present in both lists is skipped.
//
// It returns the kept rules and the allowlist IDs that matched nothing, so a
// typo cannot silently run the wrong set (and print zero findings instead of
// the expected ones). An empty allowlist keeps everything.
func Select(ps []Pattern, keep, skip []string) ([]Pattern, []string) {
	if len(keep) == 0 && len(skip) == 0 {
		return ps, nil
	}
	skipSet := map[string]struct{}{}
	for _, s := range skip {
		if s = strings.TrimSpace(s); s != "" {
			skipSet[s] = struct{}{}
		}
	}
	keepSet := map[string]struct{}{}
	for _, k := range keep {
		if k = strings.TrimSpace(k); k != "" {
			keepSet[k] = struct{}{}
		}
	}
	if len(keepSet) == 0 && len(skipSet) == 0 {
		return ps, nil
	}

	var out []Pattern
	found := map[string]bool{}
	for _, p := range ps {
		found[p.ID] = true
	}
	for _, p := range ps {
		if _, bad := skipSet[p.ID]; bad {
			continue
		}
		if len(keepSet) > 0 {
			if _, ok := keepSet[p.ID]; !ok {
				continue
			}
		}
		out = append(out, p)
	}

	var unknown []string
	for id := range keepSet {
		if !found[id] {
			unknown = append(unknown, id)
		}
	}
	sort.Strings(unknown)
	return out, unknown
}

// IDs returns the rule IDs of ps, in order.
func IDs(ps []Pattern) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.ID)
	}
	return out
}
