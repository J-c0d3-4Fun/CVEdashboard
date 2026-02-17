package parser

import (
	"testing"
)

func TestParser(t *testing.T) {
	t.Run("Testing the Parser to make sure it Unmashals the data", func(t *testing.T) {
		data := `{"Timestamps":["2006-01-02 15:04:05"], "CVEID":[ "CVE-2026-1234"], "TotalResults":0}`

		marshaler, err := Unmarshal[ParseData]([]byte(data))
		if err != nil {
			t.Errorf("Unable to Unmarshal data!")
		}

		t.Logf("Able to Successfully Unmarshal data %v", marshaler)
	})

}
