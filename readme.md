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
| GET    | `/nvd`              | Returns all NVD vulnerabilities from database        |
| GET    | `/nvd/search`       | Search NVD vulnerabilities by product/criteria (query param: `service=xxx`) |
| GET    | `/github`           | Returns all GitHub Security Advisories from database |
| GET    | `/github/search`    | Search GitHub advisories by package name (query param: `advisory=xxx`) |
| GET    | `/`                 | Homepage—returns latest 30 vulnerabilities from each source |
| GET    | `/sync/nvd`         | Manually trigger NVD data sync (background process) |
| GET    | `/sync/github`      | Manually trigger GitHub data sync (background process) |

### Examples

**Fetch all NVD vulnerabilities:**
```bash
curl http://localhost:8081/nvd
```

**Search vulnerabilities by product:**
```bash
curl http://localhost:8081/nvd/search?service=apache
```

**Search GitHub advisories:**
```bash
curl http://localhost:8081/github/search?advisory=express
```

**Response Format (NVD):**
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

**Response Format (GitHub):**
```json
[
  {
    "GHSAID": "GHSA-xxxx-xxxx-xxxx",
    "CVEID": "CVE-2024-XXXXX",
    "Identifier": "GHSA-xxx-xxx-xxx",
    "Published": "2024-01-15T00:00:00.000",
    "Summary": "Vulnerability in package X",
    "Description": "Detailed description...",
    "Severity": "high",
    "Type": "unreviewed"
  }
]
```

### Environment Variables

| Variable                   | Description                                          |
|---------------------------|------------------------------------------------------|
| `API_KEY`                  | NVD API key (get from https://nvd.nist.gov/account/login) |
| `GITHUB_TOKEN`             | GitHub personal access token (requires `security_events:read` scope) |
| `DATABASE_CONNECTION_STRING` | SQLite database path (default: `./cve_dashboard.db`) |

### Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./parser -v
go test ./storage -v
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
