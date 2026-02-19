package storage_test

import (
	"testing"

	"cvedashboard2.0/storage"
	"cvedashboard2.0/structs"
)

// Test Storing to the DB

func TestDataReadGithub(t *testing.T) {
	limit := 20
	offset := 1 * limit
	t.Run("Testing DB read action", func(t *testing.T) {
		database, err := storage.Connect()
		if err != nil {
			t.Errorf("Unable to connect to Database")
		}

		_, err1 := database.ReadGithub(offset, limit)
		if err1 != nil {
			t.Errorf("Unable to read any Github data from the Database")
		}
		defer database.Close()

		t.Logf("Able to successfully read Github Data from Database")

	})
}

func TestDataReadNVD(t *testing.T) {
	limit := 20
	offset := 1 * limit
	t.Run("Testing DB read action", func(t *testing.T) {
		database, err := storage.Connect()
		if err != nil {
			t.Errorf("Unable to connect to Database")
		}

		_, err1 := database.Read(offset, limit)
		if err1 != nil {
			DbError(t, "Unable to read any %s data from the Database", "NVD", err)
		}
		defer database.Close()

		t.Logf("Able to successfully read NVDData from Database")

	})
}

func TestCheckNumberOfRowsGithub(t *testing.T) {
	limit := 20
	offset := 1 * limit
	database, err := storage.Connect()
	if err != nil {
		t.Errorf("Unable to connect to Database")
	}
	rows, err := database.ReadGithub(offset, 20)
	if err != nil {
		DbError(t, "Unable to read any %s data from the Database", "Github", err)
	}
	if len(rows) == 0 {
		DbError(t, "Warning: Database connected but returned 0 %s records.", "Github", err)
	}
	defer database.Close()
	t.Logf("Able to successfully grab rows from Github Data from Database")

}

func TestCheckNumberOfRowsNVD(t *testing.T) {
	limit := 20
	offset := 1 * limit
	database, err := storage.Connect()
	if err != nil {
		t.Errorf("Unable to connect to Database")
	}
	rows, err := database.Read(offset, limit)
	if err != nil {
		DbError(t, "Unable to read any %s data from the Database", "NVD", err)
	}
	if len(rows) == 0 {
		DbError(t, "Warning: Database connected but returned 0 %s records.", "NVD", err)
	}
	defer database.Close()
	t.Logf("Able to successfully grab rows from NVD Data from Database")

}

func DbError(t *testing.T, msg string, name string, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("%s %s: %v ", msg, name, err)
	}
}

func TestStoringToDBGithub(t *testing.T) {

	database := connectToDB(t)
	defer database.Close()

	testStruct := structs.GithubJson{
		GhsaID:      "123456",
		CveID:       "CVE-2026-1234",
		Description: "Test Vulnerability",
		Summary:     "Test Summary",
		Type:        "Test",
		Severity:    "High",
	}
	err := database.InsertVulnDataGithub([]structs.GithubJson{testStruct})
	if err != nil {
		DbError(t, "Unable to insert Data into %s Database", "Github", err)
	}

	t.Log("Able to successfully insert data into Github Database")
}

func TestStoringToDBNVD(t *testing.T) {

	database := connectToDB(t)
	defer database.Close()

	testStruct := structs.NvdJson{
		TotalResults: 100,
	}

	err := database.InsertVulnDataNVD(&testStruct)
	if err != nil {
		DbError(t, "Unable to insert Data into %s Database", "NVD", err)
	}

	t.Log("Able to successfully insert data into NVD Database")
}

func connectToDB(t *testing.T) *storage.DB {
	t.Helper()
	data, err := storage.Connect()
	if err != nil {
		t.Errorf("Unable to connect to Database")
	}
	return data
}

func TestMain(m *testing.M) {
	database, _ := storage.Connect()
	database.CreateGithubAdvisoriesTable()
	database.CreateVulnerabilitiesTable()
	database.CreateAffectedProductsTable()
	database.CreateAffectedAdvisories()
	database.Close()

	m.Run()
}
