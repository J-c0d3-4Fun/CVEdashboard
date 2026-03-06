package storage

import (
	"database/sql"
	"fmt"
	"time"

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

	DBinit, err := sql.Open("sqlite3", "./cvedb.db")
	if err != nil {
		return nil, err
	}
	// WAL mode lets readers and writers operate concurrently on SQLite
	// was having issues witht eh goroutines trying to write to Db at the same time
	DBinit.Exec("PRAGMA journal_mode=WAL")

	DBinit.SetMaxOpenConns(25)
	DBinit.SetMaxIdleConns(25)
	DBinit.SetConnMaxLifetime(5 * time.Minute)

	return &DB{conn: DBinit}, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) queryDB(query string, args ...interface{}) (*sql.Rows, error) {
	return db.conn.Query(query, args...)
}

func (db *DB) insertDB(query string, args ...interface{}) (sql.Result, error) {
	return db.conn.Exec(query, args...)
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
					db.insertDB(
						`INSERT OR REPLACE INTO AffectedProducts (cve_id, criteria, vulnerable) VALUES (?, ?, ?)`,
						v.Cve.ID, cpe.Criteria, cpe.Vulnerable,
					)
				}
			}
		}

		_, err := db.insertDB(
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
			_, err := db.insertDB(`INSERT OR REPLACE INTO AffectedAdvisories (ghsa_id, packageName, packageEco, packageVersion) VALUES (?, ?, ? ,?)`, v.GhsaID, vulns.Package.Name, vulns.Package.Ecosystem, vulns.VulnerableVersionRange)
			if err != nil {
				return fmt.Errorf("failed to insert advisory package %s: %w", vulns.Package.Name, err)
			}
		}

		_, err := db.insertDB(
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

func (db *DB) Read(offset, limit int) ([]DBVulnerabilityNVD, error) {
	rows, err := db.queryDB("SELECT cve_id, source_identifier, published, last_modified, description, base_score FROM Vulnerabilities ORDER BY published DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAll(rows, func(r *sql.Rows) (DBVulnerabilityNVD, error) {
		var v DBVulnerabilityNVD
		err := r.Scan(&v.CVEID, &v.SourceIdentifier, &v.Published, &v.LastModified, &v.Description, &v.BaseScore)
		return v, err
	})

}

func (db *DB) ReadGithub(offset, limit int) ([]DBVulnerabilityGithub, error) {
	// COALESCE(cve_id, '') checks for null or no value
	rows, err := db.queryDB("SELECT ghsa_id, COALESCE(cve_id, ''), COALESCE(identifier, ''), published, summary, description, severity, type FROM GithubAdvisories ORDER BY published DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAll(rows, func(r *sql.Rows) (DBVulnerabilityGithub, error) {
		var v DBVulnerabilityGithub
		err := r.Scan(&v.GHSAID, &v.CVEID, &v.Identifier, &v.Published, &v.Summary, &v.Description, &v.Severity, &v.Type)
		return v, err
	})

}

func (db *DB) ReadHomepageGithub() ([]DBVulnerabilityGithub, error) {
	rows, err := db.queryDB("SELECT ghsa_id, COALESCE(cve_id, ''), COALESCE(identifier, ''), published, summary, description, severity, type FROM GithubAdvisories ORDER BY published DESC LIMIT 30")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAll(rows, func(r *sql.Rows) (DBVulnerabilityGithub, error) {
		var v DBVulnerabilityGithub
		err := r.Scan(&v.GHSAID, &v.CVEID, &v.Identifier, &v.Published, &v.Summary, &v.Description, &v.Severity, &v.Type)
		return v, err
	})

}

func (db *DB) ReadHomepageNVd() ([]DBVulnerabilityNVD, error) {
	rows, err := db.queryDB("SELECT cve_id, source_identifier, published, last_modified, description, base_score FROM Vulnerabilities ORDER BY published DESC LIMIT 30")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAll(rows, func(r *sql.Rows) (DBVulnerabilityNVD, error) {
		var v DBVulnerabilityNVD
		err := r.Scan(&v.CVEID, &v.SourceIdentifier, &v.Published, &v.LastModified, &v.Description, &v.BaseScore)
		return v, err
	})

}

func (db *DB) FilterRequestNVD(filter, version string, offset, limit int) ([]DBVulnerabilityNVD, error) {
	query := `SELECT v.cve_id, v.source_identifier, v.published, v.last_modified, v.description, v.base_score
	     FROM Vulnerabilities v
	     JOIN AffectedProducts ap ON v.cve_id = ap.cve_id
	     WHERE ap.criteria LIKE ?`
	newQuery, args, err := argsParams(filter, version, query, offset, limit)
	if err != nil {
		return []DBVulnerabilityNVD{}, err
	}

	rows, err := db.queryDB(newQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAll(rows, func(r *sql.Rows) (DBVulnerabilityNVD, error) {
		var v DBVulnerabilityNVD
		err := r.Scan(&v.CVEID, &v.SourceIdentifier, &v.Published, &v.LastModified, &v.Description, &v.BaseScore)
		return v, err
	})

}

func (db *DB) FilterRequestGithub(filter string, version string, offset, limit int) ([]DBVulnerabilityGithub, error) {
	query := `SELECT g.ghsa_id, COALESCE(g.cve_id, ''), COALESCE(g.identifier, ''), g.published, g.summary, g.description, g.severity, g.type
         FROM GithubAdvisories g
         JOIN AffectedAdvisories gh ON g.ghsa_id = gh.ghsa_id
         WHERE gh.packageName LIKE ?`

	newQuery, args, err := argsParamsGithub(filter, version, query, offset, limit)
	if err != nil {
		return []DBVulnerabilityGithub{}, err
	}
	rows, err := db.queryDB(newQuery, args...)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanAll(rows, func(r *sql.Rows) (DBVulnerabilityGithub, error) {

		var v DBVulnerabilityGithub
		err := r.Scan(&v.GHSAID, &v.CVEID, &v.Identifier, &v.Published, &v.Summary, &v.Description, &v.Severity, &v.Type)
		return v, err
	})

}

func scanAll[T any](rows *sql.Rows, fn func(*sql.Rows) (T, error)) ([]T, error) {
	var results []T
	for rows.Next() {
		v, err := fn(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, v)
	}

	return results, rows.Err()
}

func argsParams(filter, version, query string, offset, limit int) (string, []interface{}, error) {
	args := []interface{}{"%" + filter + "%"}
	if version != "" {
		query += `And ap.criteria LIKE ?`
		args = append(args, "%"+version+"%")
	}
	query += ` ORDER BY v.published DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	return query, args, nil
}

func argsParamsGithub(filter, version, query string, offset, limit int) (string, []interface{}, error) {
	args := []interface{}{"%" + filter + "%"}
	if version != "" {
		query += `And gh.packageVersion LIKE ?`
		args = append(args, "%"+version+"%")
	}
	query += `ORDER BY g.published DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	return query, args, nil
}

func (db *DB) GetHeatMapData() ([]map[string]interface{}, error) {
	rows, err := db.queryDB(`
		SELECT strftime('%Y', published), base_score, cve_id, description, published FROM Vulnerabilities
		WHERE published IS NOT NULL
		ORDER BY published
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var data []map[string]interface{}
	for rows.Next() {
		var year string
		var score float64
		var cveID string
		var description string
		var published string
		if err := rows.Scan(&year, &score, &cveID, &description, &published); err != nil {
			return nil, err
		}
		// Truncate description for tooltip
		if len(description) > 150 {
			description = description[:150] + "..."
		}
		data = append(data, map[string]interface{}{
			"x":           year,
			"y":           score,
			"cve":         cveID,
			"description": description,
			"published":   published,
		})
	}
	return data, rows.Err()

}
