package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"context"

	"container-scanner/internal/scanners"
	"container-scanner/internal/utils"
)

type ScanRequest struct {
	ImageName string `json:"imageName"`
}

type ScanResponse struct {
	ImageID  string             `json:"imageId"`
	Findings []scanners.Finding `json:"findings"`
}

func StartServer(port string) error {
	cli, err := utils.GetDockerClient()
	if err != nil {
		return err
	}

	http.HandleFunc("/api/images", func(w http.ResponseWriter, r *http.Request) {
		images, err := utils.ListImages(cli)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(images)
	})

	http.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		img, err := utils.GetImage(cli, req.ImageName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		inspect, err := cli.ImageInspect(context.Background(), img.ID)
		if err != nil {
			fmt.Printf("Warning: Could not inspect image: %v\n", err)
		}

		ctx := map[string]interface{}{
			"client":  cli,
			"inspect": inspect,
		}

		activeScanners := []scanners.Scanner{
			&scanners.ConfigScanner{},
			scanners.NewSastScanner(),
			&scanners.DastScanner{},
		}

		var findings []scanners.Finding
		for _, s := range activeScanners {
			results, err := s.Scan(img, ctx)
			if err != nil {
				fmt.Printf("Error running %s: %v\n", s.Name(), err)
				continue
			}
			findings = append(findings, results...)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ScanResponse{
			ImageID:  img.ID,
			Findings: findings,
		})
	})

	// Serve frontend
	fs := http.FileServer(http.Dir("./web/ui/dist"))
	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api") {
			fs.ServeHTTP(w, r)
		}
	}))

	fmt.Printf("Server starting on http://localhost:%s\n", port)
	return http.ListenAndServe(":"+port, nil)
}
