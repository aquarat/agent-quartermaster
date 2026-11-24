package config

import "testing"

// The Help page prints these into commands people paste: HTTPS only, nothing else.
func TestCLIDownloadBaseURL(t *testing.T) {
	if c, err := Parse([]byte(updatesBase + "cli_download_base_url = \"https://downloads.example.com/aqmas\"\n")); err != nil || c.CLIDownloadBaseURL != "https://downloads.example.com/aqmas" {
		t.Fatal(c, err)
	}
	for _, bad := range []string{"http://downloads.example.com/aqmas", "ftp://downloads.example.com/aqmas", "https://user:pw@downloads.example.com/aqmas", "https://downloads.example.com/aqmas?x=1", "downloads.example.com/aqmas"} {
		if _, err := Parse([]byte(updatesBase + "cli_download_base_url = \"" + bad + "\"\n")); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
