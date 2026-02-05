package scanners

import (
	"github.com/moby/moby/api/types/image"
)

// Finding represents a single security issue found during a scan.
type Finding struct {
	Scanner     string `json:"scanner"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Details     string `json:"details"`
}

// Scanner is the interface that all scanner modules must implement.
type Scanner interface {
	Name() string
	Scan(img image.Summary, context map[string]interface{}) ([]Finding, error)
}
