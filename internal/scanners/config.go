package scanners

import (
	"fmt"
	"strings"

	"github.com/moby/moby/api/types/image"
)

type ConfigScanner struct{}

func (s *ConfigScanner) Name() string {
	return "ConfigScanner"
}

func (s *ConfigScanner) Scan(img image.Summary, context map[string]interface{}) ([]Finding, error) {
	var findings []Finding

	inspect, ok := context["inspect"].(image.InspectResponse)
	if !ok {
		// ImageInspect might return a pointer in some SDK versions/wrappers
		inspectPtr, okPtr := context["inspect"].(*image.InspectResponse)
		if !okPtr {
			return findings, nil
		}
		inspect = *inspectPtr
	}

	config := inspect.Config
	if config == nil {
		return findings, nil
	}

	// Check User
	if config.User == "" || config.User == "0" || config.User == "root" {
		findings = append(findings, Finding{
			Scanner:     s.Name(),
			Severity:    "MEDIUM",
			Description: "Running as root",
			Details:     fmt.Sprintf("User is set to '%s'. It is best practice to run as a non-root user.", config.User),
		})
	}

	// Check Healthcheck
	if config.Healthcheck == nil {
		findings = append(findings, Finding{
			Scanner:     s.Name(),
			Severity:    "LOW",
			Description: "No Healthcheck defined",
			Details:     "Image does not define a HEALTHCHECK instruction.",
		})
	}

	// Check Exposed Ports
	sensitivePorts := map[string]struct{}{
		"22/tcp":   {},
		"23/tcp":   {},
		"3389/tcp": {},
	}

	for port := range config.ExposedPorts {
		if _, ok := sensitivePorts[string(port)]; ok {
			findings = append(findings, Finding{
				Scanner:     s.Name(),
				Severity:    "HIGH",
				Description: "Sensitive Port Exposed",
				Details:     fmt.Sprintf("Port %s is exposed in the image config.", port),
			})
		}
	}

	// Check Labels
	hasMaintainer := false
	if config.Labels != nil {
		if _, ok := config.Labels["maintainer"]; ok {
			hasMaintainer = true
		} else if _, ok := config.Labels["org.opencontainers.image.authors"]; ok {
			hasMaintainer = true
		}
	}
	if !hasMaintainer {
		findings = append(findings, Finding{
			Scanner:     s.Name(),
			Severity:    "LOW",
			Description: "Missing Maintainer Label",
			Details:     "Image does not have a 'maintainer' or 'org.opencontainers.image.authors' label.",
		})
	}

	// Check Environment Variables
	secretKeywords := []string{"PASS", "KEY", "SECRET", "TOKEN", "AUTH"}
	for _, env := range config.Env {
		upperEnv := strings.ToUpper(env)
		for _, keyword := range secretKeywords {
			if strings.Contains(upperEnv, keyword) {
				parts := strings.SplitN(env, "=", 2)
				findings = append(findings, Finding{
					Scanner:     s.Name(),
					Severity:    "HIGH",
					Description: "Potential Secret in Environment Variable",
					Details:     fmt.Sprintf("Found environment variable that may contain a secret: %s", parts[0]),
				})
				break
			}
		}
	}

	return findings, nil
}
