package nister

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCVEReport(t *testing.T) {
	data := ParseCVEReport(recentURL)
	assert.NotNil(t, data)
}
