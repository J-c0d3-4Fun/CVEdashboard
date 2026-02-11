package structs

import "time"

type GithubJson struct {
	GhsaID                string      `json:"ghsa_id"`
	CveID                 interface{} `json:"cve_id"`
	URL                   string      `json:"url"`
	HTMLURL               string      `json:"html_url"`
	Summary               string      `json:"summary"`
	Description           string      `json:"description"`
	Type                  string      `json:"type"`
	Severity              string      `json:"severity"`
	RepositoryAdvisoryURL interface{} `json:"repository_advisory_url"`
	SourceCodeLocation    string      `json:"source_code_location"`
	Identifiers           []struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	} `json:"identifiers"`
	References       []string    `json:"references"`
	PublishedAt      time.Time   `json:"published_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	GithubReviewedAt time.Time   `json:"github_reviewed_at"`
	NvdPublishedAt   interface{} `json:"nvd_published_at"`
	WithdrawnAt      interface{} `json:"withdrawn_at"`
	Vulnerabilities  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string        `json:"vulnerable_version_range"`
		FirstPatchedVersion    interface{}   `json:"first_patched_version"`
		VulnerableFunctions    []interface{} `json:"vulnerable_functions"`
	} `json:"vulnerabilities"`
	CvssSeverities struct {
		CvssV3 struct {
			VectorString interface{} `json:"vector_string"`
			Score        float64     `json:"score"`
		} `json:"cvss_v3"`
		CvssV4 struct {
			VectorString interface{} `json:"vector_string"`
			Score        float64     `json:"score"`
		} `json:"cvss_v4"`
	} `json:"cvss_severities"`
	Cwes    []interface{} `json:"cwes"`
	Credits []interface{} `json:"credits"`
	Cvss    struct {
		VectorString interface{} `json:"vector_string"`
		Score        interface{} `json:"score"`
	} `json:"cvss"`
}
