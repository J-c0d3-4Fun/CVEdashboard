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

func Unmarshal(data []byte) (structs.NvdJson, error) {
	var report structs.NvdJson
	if err := json.Unmarshal(data, &report); err != nil {
		return structs.NvdJson{}, fmt.Errorf("error unmarshaling: %w", err)
	}
	return report, nil
}
func Response(responseData *structs.NvdJson) []*structs.NvdJson {
	var allResponses []*structs.NvdJson

	for i := 0; i < responseData.TotalResults; i++ {
		allResponses = append(allResponses, responseData)
	}
	return allResponses
}

// !FIXME
// func GetTimeStamp(time []*structs.NvdJson) []string {
// 	var timestamps []string
// 	for _, d := range time {
// 		timestamps = append(timestamps, d.Timestamp)
// 	}

// 	return timestamps
// }

func GetVulnID(vuln []*structs.NvdJson) []string {

	var ids []string
	for _, nvd := range vuln {
		for _, v := range nvd.Vulnerabilities {
			ids = append(ids, v.Cve.ID)
		}

	}

	return ids

}

// !FIXME
// func GetVulnTags(vuln *structs.NvdJson) []string {
// 	var ids []string
// 	for _, v := range vuln.Vulnerabilities {
// 		ids = append(ids, v.Cve.CveTags)
// 	}

// 	return ids

// }

// !FIXME

// func GetVulnDescription(vuln *structs.NvdJson) []string {
// 	var ids []string
// 	for _, v := range vuln.Vulnerabilities {
// 		ids = append(ids, v.Cve.D)
// 	}

// 	return ids

// }
