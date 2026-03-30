package storage

import (
	"database/sql"
	"fmt"

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

type ConnectionPool struct {
	connections chan *sql.DB
	maxSize     int
}

func NewConnectionPool(maxSize int) *ConnectionPool {
	// create the connection
	pool := &ConnectionPool{
		connections: make(chan *sql.DB, maxSize),
		maxSize:     maxSize,
	}

	for i := 0; i < maxSize; i++ {
		db, _ := sql.Open("sqlite3", "./cvedb.db")
		db.Exec("PRAGMA journal_mode=WAL")
		pool.connections <- db
	}
	return pool

}

func (p *ConnectionPool) Get() *sql.DB {
	return <-p.connections // reuse existing connection
}

func (p *ConnectionPool) Release(db *sql.DB) {
	p.connections <- db // return to pool
}

func (p *ConnectionPool) Close() error {
	close(p.connections)
	for db := range p.connections {
		db.Close()
	}
	return nil
}

// func (pool *ConnectionPool) queryDB(query string, args ...interface{}) (*sql.Rows, error) {
// dbConn := pool.Get()
// defer pool.Release(dbConn)
// 	return dbConn.Query(query, args...)
// }

// func (pool *ConnectionPool) insertDB(query string, args ...interface{}) (sql.Result, error) {
// 	dbConn := pool.Get()
// 	defer pool.Release(dbConn)
// 	return dbConn.Exec(query, args...)
// }

func (pool *ConnectionPool) InsertVulnDataNVD(data *structs.NvdJson) error {
	dbConn := pool.Get()
	defer pool.Release(dbConn)

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
					dbConn.Exec(
						`INSERT OR REPLACE INTO AffectedProducts (cve_id, criteria, vulnerable) VALUES (?, ?, ?)`,
						v.Cve.ID, cpe.Criteria, cpe.Vulnerable,
					)
				}
			}
		}

		_, err := dbConn.Exec(
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

func (pool *ConnectionPool) InsertVulnDataGithub(data []structs.GithubJson) error {
	dbConn := pool.Get()
	defer pool.Release(dbConn)
	for _, v := range data {
		identifier := ""
		if len(v.Identifiers) > 0 {
			identifier = v.Identifiers[0].Value
		}

		for _, vulns := range v.Vulnerabilities {
			_, err := dbConn.Exec(`INSERT OR REPLACE INTO AffectedAdvisories (ghsa_id, packageName, packageEco, packageVersion) VALUES (?, ?, ? ,?)`, v.GhsaID, vulns.Package.Name, vulns.Package.Ecosystem, vulns.VulnerableVersionRange)
			if err != nil {
				return fmt.Errorf("failed to insert advisory package %s: %w", vulns.Package.Name, err)
			}
		}

		_, err := dbConn.Exec(
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

func (pool *ConnectionPool) Read(offset, limit int) ([]DBVulnerabilityNVD, error) {
	dbConn := pool.Get()
	defer pool.Release(dbConn)
	rows, err := dbConn.Query("SELECT cve_id, source_identifier, published, last_modified, description, base_score FROM Vulnerabilities ORDER BY published DESC LIMIT ? OFFSET ?", limit, offset)
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

func (pool *ConnectionPool) ReadGithub(offset, limit int) ([]DBVulnerabilityGithub, error) {

	dbConn := pool.Get()
	defer pool.Release(dbConn)
	// COALESCE(cve_id, '') checks for null or no value
	rows, err := dbConn.Query("SELECT ghsa_id, COALESCE(cve_id, ''), COALESCE(identifier, ''), published, summary, description, severity, type FROM GithubAdvisories ORDER BY published DESC LIMIT ? OFFSET ?", limit, offset)
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

func (pool *ConnectionPool) ReadHomepageGithub() ([]DBVulnerabilityGithub, error) {
	dbConn := pool.Get()
	defer pool.Release(dbConn)
	rows, err := dbConn.Query("SELECT ghsa_id, COALESCE(cve_id, ''), COALESCE(identifier, ''), published, summary, description, severity, type FROM GithubAdvisories ORDER BY published DESC LIMIT 30")
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

func (pool *ConnectionPool) ReadHomepageNVd() ([]DBVulnerabilityNVD, error) {
	dbConn := pool.Get()
	defer pool.Release(dbConn)
	rows, err := dbConn.Query("SELECT cve_id, source_identifier, published, last_modified, description, base_score FROM Vulnerabilities ORDER BY published DESC LIMIT 30")
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

func (pool *ConnectionPool) FilterRequestNVD(filter, version string, offset, limit int) ([]DBVulnerabilityNVD, error) {
	dbConn := pool.Get()
	defer pool.Release(dbConn)
	query := `SELECT v.cve_id, v.source_identifier, v.published, v.last_modified, v.description, v.base_score
	     FROM Vulnerabilities v
	     JOIN AffectedProducts ap ON v.cve_id = ap.cve_id
	     WHERE ap.criteria LIKE ?`
	newQuery, args, err := argsParams(filter, version, query, offset, limit)
	if err != nil {
		return []DBVulnerabilityNVD{}, err
	}

	rows, err := dbConn.Query(newQuery, args...)
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

func (pool *ConnectionPool) FilterRequestGithub(filter string, version string, offset, limit int) ([]DBVulnerabilityGithub, error) {
	dbConn := pool.Get()
	defer pool.Release(dbConn)
	query := `SELECT g.ghsa_id, COALESCE(g.cve_id, ''), COALESCE(g.identifier, ''), g.published, g.summary, g.description, g.severity, g.type
         FROM GithubAdvisories g
         JOIN AffectedAdvisories gh ON g.ghsa_id = gh.ghsa_id
         WHERE gh.packageName LIKE ?`

	newQuery, args, err := argsParamsGithub(filter, version, query, offset, limit)
	if err != nil {
		return []DBVulnerabilityGithub{}, err
	}
	rows, err := dbConn.Query(newQuery, args...)

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

func (pool *ConnectionPool) GetHeatMapData() ([]map[string]interface{}, error) {
	dbConn := pool.Get()
	defer pool.Release(dbConn)
	rows, err := dbConn.Query(`
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
