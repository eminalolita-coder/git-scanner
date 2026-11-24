package cli

import "regexp"

// DefaultObjectFilter matches object names that usually hold configuration or
// secrets, so a bucket listing can be prioritised instead of taking the first
// N keys alphabetically.
const DefaultObjectFilter = `(?i)(^|/)(\.env.*|wp-config\.php|config\.(json|php|ya?ml)|settings\.py|credentials.*|.*secret.*|.*password.*|docker-compose\.ya?ml|docker-compose\.yml|appsettings\..*|.*\.(sql|sql\.gz|dump|pem|key|p12|pfx|bak|old|backup|orig|save|tfstate|ini|conf|cfg|properties))$`

// selectObjects filters keys with filter and caps the result. When nothing
// matches, it falls back to the first keys so a scan still does something.
func selectObjects(keys []string, filter string, limit int) []string {
	if limit <= 0 {
		limit = 20
	}
	if filter == "" {
		if len(keys) > limit {
			return keys[:limit]
		}
		return keys
	}
	re, err := regexp.Compile(filter)
	if err != nil {
		if len(keys) > limit {
			return keys[:limit]
		}
		return keys
	}
	var out []string
	for _, k := range keys {
		if re.MatchString(k) {
			out = append(out, k)
			if len(out) >= limit {
				break
			}
		}
	}
	if len(out) == 0 {
		if len(keys) > limit {
			return keys[:limit]
		}
		return keys
	}
	return out
}
