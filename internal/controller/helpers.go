package controller

import (
	"encoding/json"
	"fmt"
)

func toJson(v any) string {
	a, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("Error marshaling to JSON: %v", err)
	}
	return string(a)
}
