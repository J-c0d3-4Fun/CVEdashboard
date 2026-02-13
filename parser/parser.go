package parser

import (
	"encoding/json"
	"fmt"

	"cvedashboard2.0/structs"
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

func GetVulnID(vuln []*structs.NvdJson) []string {

	var ids []string
	for _, nvd := range vuln {
		for _, v := range nvd.Vulnerabilities {
			ids = append(ids, v.Cve.ID)
		}

	}

	return ids

}
