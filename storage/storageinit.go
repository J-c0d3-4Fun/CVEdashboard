package storage

func (db *DB) CreateGithubAdvisoriesTable() error {
	_, err := db.insertDB(`CREATE TABLE IF NOT EXISTS GithubAdvisories (
        ghsa_id TEXT PRIMARY KEY,
        cve_id TEXT,
        identifier TEXT,
        published TEXT,
        summary TEXT,
        description TEXT,
        severity TEXT,
        type TEXT
    )`)
	return err

}
func (db *DB) CreateVulnerabilitiesTable() error {
	_, err := db.insertDB(`CREATE TABLE IF NOT EXISTS Vulnerabilities (
    cve_id    TEXT PRIMARY KEY,
    source_identifier TEXT,
    published         TEXT,
    last_modified     TEXT,
    description       TEXT,
    base_score        REAL
    )`)
	return err

}

func (db *DB) CreateAffectedProductsTable() error {
	_, err := db.insertDB(`CREATE TABLE IF NOT EXISTS AffectedProducts (
    cve_id     TEXT,
    criteria   TEXT,
    vulnerable BOOLEAN,
    PRIMARY KEY (cve_id, criteria),
    FOREIGN KEY (cve_id) REFERENCES Vulnerabilities(cve_id)
)`)
	return err
}

func (db *DB) CreateAffectedAdvisories() error {
	_, err := db.insertDB(`CREATE TABLE IF NOT EXISTS AffectedAdvisories (
    ghsa_id      TEXT,
    packageName  TEXT,
    packageEco   TEXT,
    packageVersion TEXT,
    PRIMARY KEY (ghsa_id, packageName),
    FOREIGN KEY (ghsa_id) REFERENCES GithubAdvisories(ghsa_id)
)`)
	return err
}
