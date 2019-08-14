package nister

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecentCVES(t *testing.T) {
	report := RecentCVES("cisco")
	for _, v := range report["modified_CVE"] {
		assert.Equal(t, 13, len(v.CVE.MetaData.ID))
	}

}
