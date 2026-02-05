package scanners

import (
	"archive/tar"
	"context"
	"io"
	"regexp"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
)

type SastScanner struct {
	SecretPatterns map[string]*regexp.Regexp
	MaxFileSize    int64
}

func NewSastScanner() *SastScanner {
	return &SastScanner{
		SecretPatterns: map[string]*regexp.Regexp{
			"AWS Access Key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			"Private Key":          regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			"Google Cloud API Key": regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			"Slack Webhook":        regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
		},
		MaxFileSize: 1024 * 1024, // 1MB
	}
}

func (s *SastScanner) Name() string {
	return "SastScanner"
}

func (s *SastScanner) Scan(img image.Summary, ctx map[string]interface{}) ([]Finding, error) {
	findings := []Finding{}
	cli, ok := ctx["client"].(*client.Client)
	if !ok {
		return findings, nil
	}

	// Create container
	resp, err := cli.ContainerCreate(context.Background(), client.ContainerCreateOptions{
		Config: &container.Config{
			Image: img.ID,
		},
	})
	if err != nil {
		return findings, err
	}
	defer cli.ContainerRemove(context.Background(), resp.ID, client.ContainerRemoveOptions{})

	// Export filesystem
	reader, err := cli.ContainerExport(context.Background(), resp.ID, client.ContainerExportOptions{})
	if err != nil {
		return findings, err
	}
	defer reader.Close()

	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return findings, err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		if s.shouldSkip(header.Name) {
			continue
		}

		// Read limited content
		buf := make([]byte, s.MaxFileSize)
		n, _ := io.ReadFull(tarReader, buf)
		content := buf[:n]

		findings = append(findings, s.analyzeContent(header.Name, content)...)
	}

	return findings, nil
}

func (s *SastScanner) shouldSkip(filename string) bool {
	skipPrefixes := []string{"proc/", "sys/", "dev/"}
	for _, p := range skipPrefixes {
		if strings.HasPrefix(filename, p) {
			return true
		}
	}
	skipExts := []string{".so", ".pyc", ".o", ".bin", ".exe", ".dll"}
	for _, e := range skipExts {
		if strings.HasSuffix(filename, e) {
			return true
		}
	}
	return false
}

func (s *SastScanner) analyzeContent(filename string, content []byte) []Finding {
	findings := []Finding{}
	text := string(content)

	for name, pattern := range s.SecretPatterns {
		if pattern.MatchString(text) {
			findings = append(findings, Finding{
				Scanner:     s.Name(),
				Severity:    "HIGH",
				Description: "Potential Secret Found: " + name,
				Details:     "Found in file: " + filename,
			})
		}
	}

	if strings.HasSuffix(filename, "requirements.txt") {
		findings = append(findings, Finding{
			Scanner:     s.Name(),
			Severity:    "INFO",
			Description: "Python Dependencies",
			Details:     "Found requirements.txt at " + filename,
		})
	}

	return findings
}
