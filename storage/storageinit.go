package storage

func (pool *ConnectionPool) CreateGithubAdvisoriesTable() error {
	_, err := pool.insertDB(`CREATE TABLE IF NOT EXISTS GithubAdvisories (
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
func (pool *ConnectionPool) CreateVulnerabilitiesTable() error {
	_, err := pool.insertDB(`CREATE TABLE IF NOT EXISTS Vulnerabilities (
    cve_id    TEXT PRIMARY KEY,
    source_identifier TEXT,
    published         TEXT,
    last_modified     TEXT,
    description       TEXT,
    base_score        REAL
    )`)
	return err

}

func (pool *ConnectionPool) CreateAffectedProductsTable() error {
	_, err := pool.insertDB(`CREATE TABLE IF NOT EXISTS AffectedProducts (
    cve_id     TEXT,
    criteria   TEXT,
    vulnerable BOOLEAN,
    PRIMARY KEY (cve_id, criteria),
    FOREIGN KEY (cve_id) REFERENCES Vulnerabilities(cve_id)
)`)
	return err
}

func (pool *ConnectionPool) CreateAffectedAdvisories() error {
	_, err := pool.insertDB(`CREATE TABLE IF NOT EXISTS AffectedAdvisories (
    ghsa_id      TEXT,
    packageName  TEXT,
    packageEco   TEXT,
    packageVersion TEXT,
    PRIMARY KEY (ghsa_id, packageName),
    FOREIGN KEY (ghsa_id) REFERENCES GithubAdvisories(ghsa_id)
)`)
	return err
}
