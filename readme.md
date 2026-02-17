# CVE Dashboard

A vulnerability aggregation dashboard built in Go that consolidates security data from multiple sources into a unified API. Currently integrates with the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/), with GitHub Security Advisories as the next planned integration.

## Architecture

```
┌────────────────────┐      ┌────────────┐      ┌──────────┐      ┌──────────────┐
│  External APIs     │─────▶│  Parser    │─────▶│  Storage │─────▶│  REST API    │
│  (NVD, GitHub...)  │      │            │      │ (SQLite) │      │  (Gin :8080) │
└────────────────────┘      └────────────┘      └──────────┘      └──────────────┘
```

## Project Structure

```
CVEdashboard/
├── api/            # HTTP client, Gin routes, and request handlers
├── parser/         # JSON deserialization and data extraction utilities
├── storage/        # SQLite database layer (connect, insert, read)
├── structs/        # Go struct definitions mapping the NVD API response
└── Improvements/   # Planned enhancements
```

## Tech Stack

- **Language:** Go
- **HTTP Framework:** [Gin](https://github.com/gin-gonic/gin)
- **Database:** SQLite via [go-sqlite3](https://github.com/mattn/go-sqlite3)
- **Data Source:** [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0/)

## Getting Started

### Prerequisites

- Go 1.25+
- GCC (required for `go-sqlite3` CGo compilation)

### Installation

```bash
git clone https://github.com/J-c0d3-4Fun/CVEdashboard.git
cd CVEdashboard
go mod download
```

### Run

```bash
go run api/api.go
```

The server starts on `http://localhost:8080`.

### API Endpoints

| Method | Endpoint            | Description                                          |
|--------|---------------------|------------------------------------------------------|
| GET    | `/vulnerabilities`  | Fetches CVEs from NVD, stores them, and returns all stored vulnerabilities |

### Example

```bash
curl http://localhost:8080/vulnerabilities
```

Response returns an array of vulnerability objects:

```json
[
  {
    "CVEID": "CVE-2024-XXXXX",
    "SourceIdentifier": "cve@mitre.org",
    "Published": "2024-01-15T00:00:00.000",
    "LastModified": "2024-01-16T00:00:00.000",
    "Description": "A vulnerability was found in...",
    "BaseScore": 7.5
  }
]
```

## Roadmap

- [X] **GitHub Security Advisories** — Integrate the [GitHub Advisory Database API](https://docs.github.com/en/rest/security-advisories) as a second data source
- [X] Pagination support for large CVE result sets
- [ ] Filtering and search by CVE ID, severity, date range <- can currently search based on name
- [ ] CVSS v3.1 metric support
- [X] Scheduled background sync (replace on-demand fetch)
- [ ] Frontend dashboard UI
- [ ] Add Mux handler for a router
- [ ] Add Slack Integration 
## License

This project is open source and available under the [MIT License](LICENSE).
