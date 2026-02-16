package storage

import (
	"database/sql"
	"fmt"
	"log"

	"cvedashboard2.0/structs"
	_ "github.com/mattn/go-sqlite3"
)

/*
Main Vulnerabilities Page
Timestamp
Vulnerabilities.CVE.ID
Vulnerabilities.CVE.SourceIdentifier
Vulnerabilities.CVE.Published
Vulnerabilities.CVE.Description.Value
Vulnerabilities.CVE.Metrics.CVEMetric2[].BaseScore

Function that Loops through the data
ParseData()

Page 2 or Maybe filters that can be toggled?

3 SQL functions = 3 functions
Insert()
Update()
Delete()

First Table Vulnerabilities
*/

type DBVulnerabilityNVD struct {
	CVEID            string
	SourceIdentifier string
	Published        string
	LastModified     string
	Description      string
	BaseScore        float64
}
type DBVulnerabilityGithub struct {
	GHSAID      string
	CVEID       string
	Identifier  string
	Published   string
	Summary     string
	Description string
	Severity    string
	Type        string
}

type DB struct {
	conn *sql.DB
}

//  Check for connection

func Connect() (*DB, error) {
	conn, err := sql.Open("sqlite3", "/Users/jbrown/Meshify/cve_dashboard/sqldb/database.db")
	if err != nil {
		return nil, err
	}
	// WAL mode lets readers and writers operate concurrently on SQLite
	// was having issues witht eh goroutines trying to write to Db at the same time
	conn.Exec("PRAGMA journal_mode=WAL")
	return &DB{conn: conn}, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) InsertVulnDataNVD(data *structs.NvdJson) error {
	for _, v := range data.Vulnerabilities {
		desc := ""
		if len(v.Cve.Descriptions) > 0 {
			desc = v.Cve.Descriptions[0].Value
		}
		var baseScore float64
		if len(v.Cve.Metrics.CvssMetricV2) > 0 {
			baseScore = v.Cve.Metrics.CvssMetricV2[0].CvssData.BaseScore
		}
		for _, config := range v.Cve.Configurations {
			for _, node := range config.Nodes {
				for _, cpe := range node.CpeMatch {
					db.conn.Exec(
						`INSERT OR REPLACE INTO AffectedProducts (cve_id, criteria, vulnerable) VALUES (?, ?, ?)`,
						v.Cve.ID, cpe.Criteria, cpe.Vulnerable,
					)
				}
			}
		}

		_, err := db.conn.Exec(
			`INSERT OR REPLACE INTO Vulnerabilities 
			(cve_id, source_identifier, published, last_modified, description, base_score) 
			VALUES (?, ?, ?, ?, ?, ?)`,
			v.Cve.ID, v.Cve.SourceIdentifier, v.Cve.Published,
			v.Cve.LastModified, desc, baseScore,
		)
		if err != nil {
			return fmt.Errorf("failed to insert %s: %w", v.Cve.ID, err)
		}
	}
	return nil
}

func (db *DB) InsertVulnDataGithub(data []structs.GithubJson) error {
	for _, v := range data {
		identifier := ""
		if len(v.Identifiers) > 0 {
			identifier = v.Identifiers[0].Value
		}

		for _, vulns := range v.Vulnerabilities {
			_, err := db.conn.Exec(`INSERT OR REPLACE INTO AffectedAdvisories (ghsa_id, packageName, packageEco) VALUES (?, ?, ?)`, v.GhsaID, vulns.Package.Name, vulns.Package.Ecosystem)
			if err != nil {
				return fmt.Errorf("failed to insert advisory package %s: %w", vulns.Package.Name, err)
			}
		}

		_, err := db.conn.Exec(
			`INSERT OR REPLACE INTO GithubAdvisories 
			(ghsa_id, cve_id, identifier, published, summary, description, severity, type) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			v.GhsaID, v.CveID, identifier, v.PublishedAt.Format("2006-01-02T15:04:05"),
			v.Summary, v.Description, v.Severity, v.Type,
		)
		if err != nil {
			return fmt.Errorf("failed to insert %s: %w", v.GhsaID, err)
		}
	}
	return nil
}

func (db *DB) Read() ([]DBVulnerabilityNVD, error) {
	rows, err := db.conn.Query("SELECT cve_id, source_identifier, published, last_modified, description, base_score FROM Vulnerabilities")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var results []DBVulnerabilityNVD

	for rows.Next() {
		var v DBVulnerabilityNVD
		err := rows.Scan(&v.CVEID, &v.SourceIdentifier, &v.Published, &v.LastModified, &v.Description, &v.BaseScore)
		if err != nil {
			log.Fatal(err)
		}
		results = append(results, v)
	}
	return results, rows.Err()
}

func (db *DB) ReadGithub() ([]DBVulnerabilityGithub, error) {
	// COALESCE(cve_id, '') checks for null or no value
	rows, err := db.conn.Query("SELECT ghsa_id, COALESCE(cve_id, ''), COALESCE(identifier, ''), published, summary, description, severity, type FROM GithubAdvisories")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var results []DBVulnerabilityGithub

	for rows.Next() {
		var v DBVulnerabilityGithub
		err := rows.Scan(&v.GHSAID, &v.CVEID, &v.Identifier, &v.Published, &v.Summary, &v.Description, &v.Severity, &v.Type)
		if err != nil {
			log.Fatal(err)
		}
		results = append(results, v)
	}
	return results, rows.Err()
}

func (db *DB) FilterRequestNVD(filter string) ([]DBVulnerabilityNVD, error) {
	var result []DBVulnerabilityNVD
	rows, err := db.conn.Query(`SELECT v.cve_id, v.source_identifier, v.published, v.last_modified, v.description, v.base_score 
         FROM Vulnerabilities v
         JOIN AffectedProducts ap ON v.cve_id = ap.cve_id
         WHERE ap.criteria LIKE ?`, "%"+filter+"%")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var v DBVulnerabilityNVD
		err := rows.Scan(&v.CVEID, &v.SourceIdentifier, &v.Published, &v.LastModified, &v.Description, &v.BaseScore)
		if err != nil {
			log.Fatal(err)
		}
		result = append(result, v)
	}
	return result, rows.Err()

}

func (db *DB) FilterRequestGithub(filter string) ([]DBVulnerabilityGithub, error) {
	var result []DBVulnerabilityGithub
	rows, err := db.conn.Query(`SELECT g.ghsa_id, COALESCE(g.cve_id, ''), COALESCE(g.identifier, ''), g.published, g.summary, g.description, g.severity, g.type
         FROM GithubAdvisories g
         JOIN AffectedAdvisories gh ON g.ghsa_id = gh.ghsa_id
         WHERE gh.packageName LIKE ?`, "%"+filter+"%")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var v DBVulnerabilityGithub
		err := rows.Scan(&v.GHSAID, &v.CVEID, &v.Identifier, &v.Published, &v.Summary, &v.Description, &v.Severity, &v.Type)
		if err != nil {
			log.Fatal(err)
		}
		result = append(result, v)
	}
	return result, rows.Err()
}
