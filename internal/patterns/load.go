package patterns

import (
	"encoding/json"
	"os"
)

// LoadFile reads a JSON array of custom patterns.
func LoadFile(path string) ([]Pattern, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ps []Pattern
	if err := json.Unmarshal(data, &ps); err != nil {
		return nil, err
	}
	return ps, nil
}

// SaveFile writes patterns as indented JSON.
func SaveFile(path string, ps []Pattern) error {
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
