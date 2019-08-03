package nister

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecentCVES(t *testing.T) {
	report := RecentCVES([]string{"cisco"})
	for _, v := range report["modified_CVE"] {
		assert.Equal(t, 13, len(v.CVE.MetaData.ID))
	}

}

// func parsecveFile() Data {
// 	cve := Data{}
// 	body, err := ioutil.ReadFile("./test_data/nvdcve-1.0-recent.json")
// 	if err != nil {
// 		log.Fatal("failed to read cve file error :", err)
// 	}

// 	err = json.Unmarshal(body, &cve)
// 	if err != nil {
// 		log.Fatal("unmarshalling file failed error: ", err)
// 	}

// 	return cve
// }
