package scanners

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
)

type DastScanner struct{}

func (s *DastScanner) Name() string {
	return "DastScanner"
}

func (s *DastScanner) Scan(img image.Summary, ctx map[string]interface{}) ([]Finding, error) {
	var findings []Finding
	cli, ok := ctx["client"].(*client.Client)
	if !ok {
		return findings, nil
	}

	fmt.Println("Starting ephemeral container for DAST...")
	
	resp, err := cli.ContainerCreate(context.Background(), client.ContainerCreateOptions{
		Config: &container.Config{
			Image: img.ID,
		},
		HostConfig: &container.HostConfig{
			PublishAllPorts: true,
		},
	})
	if err != nil {
		return findings, err
	}
	defer cli.ContainerRemove(context.Background(), resp.ID, client.ContainerRemoveOptions{Force: true})

	if _, err := cli.ContainerStart(context.Background(), resp.ID, client.ContainerStartOptions{}); err != nil {
		return findings, err
	}

	// Wait for startup
	time.Sleep(2 * time.Second)

	inspect, err := cli.ContainerInspect(context.Background(), resp.ID, client.ContainerInspectOptions{})
	if err != nil {
		return findings, err
	}

	ports := inspect.Container.NetworkSettings.Ports
	if len(ports) == 0 {
		fmt.Println("No ports exposed by container, skipping HTTP probe.")
		return findings, nil
	}

	seenPorts := make(map[string]bool)
	for _, portBindings := range ports {
		for _, binding := range portBindings {
			if seenPorts[binding.HostPort] {
				continue
			}
			seenPorts[binding.HostPort] = true
			url := fmt.Sprintf("http://localhost:%s", binding.HostPort)
			findings = append(findings, s.probeHTTP(url)...)
		}
	}

	return findings, nil
}

func (s *DastScanner) probeHTTP(url string) []Finding {
	var findings []Finding
	client := http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	headers := resp.Header
	missingHeaders := []string{}
	if headers.Get("X-Content-Type-Options") == "" {
		missingHeaders = append(missingHeaders, "X-Content-Type-Options")
	}
	if headers.Get("X-Frame-Options") == "" {
		missingHeaders = append(missingHeaders, "X-Frame-Options")
	}
	if headers.Get("Content-Security-Policy") == "" {
		missingHeaders = append(missingHeaders, "Content-Security-Policy")
	}

	if len(missingHeaders) > 0 {
		findings = append(findings, Finding{
			Scanner:     s.Name(),
			Severity:    "LOW",
			Description: "Missing Security Headers",
			Details:     fmt.Sprintf("URL %s is missing headers: %s", url, strings.Join(missingHeaders, ", ")),
		})
	}

	if server := headers.Get("Server"); server != "" {
		findings = append(findings, Finding{
			Scanner:     s.Name(),
			Severity:    "LOW",
			Description: "Server Header Leaked",
			Details:     fmt.Sprintf("Server header returned: %s", server),
		})
	}

	return findings
}
