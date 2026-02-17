package parser

import (
	"encoding/json"
	"fmt"
)

type ParseData struct {
	Timestamps   []string
	CVEID        []string
	TotalResults int
}

// type parameter , allows me to return the same type of any

func Unmarshal[T any](data []byte) (T, error) {
	var report T
	if err := json.Unmarshal(data, &report); err != nil {
		return report, fmt.Errorf("error unmarshaling: %w", err)
	}
	return report, nil
}
