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

type DBVulnerability struct {
	CVEID            string
	SourceIdentifier string
	Published        string
	LastModified     string
	Description      string
	BaseScore        float64
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

func (db *DB) InsertVulnData(data *structs.NvdJson) error {
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

func (db *DB) Read() ([]DBVulnerability, error) {
	rows, err := db.conn.Query("SELECT cve_id, source_identifier, published, last_modified, description, base_score FROM Vulnerabilities")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var results []DBVulnerability

	for rows.Next() {
		var v DBVulnerability
		err := rows.Scan(&v.CVEID, &v.SourceIdentifier, &v.Published, &v.LastModified, &v.Description, &v.BaseScore)
		if err != nil {
			log.Fatal(err)
		}
		results = append(results, v)
	}
	return results, rows.Err()
}
