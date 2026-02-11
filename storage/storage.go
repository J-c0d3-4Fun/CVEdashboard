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
		_, err := db.conn.Exec(
			`INSERT OR REPLACE INTO GithubAdvisories 
			(ghsa_id, cve_id, identifier, published, summary, description, severity, type) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			v.GhsaID, v.CveID, identifier, v.PublishedAt,
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
