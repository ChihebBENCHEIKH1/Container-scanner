package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"context"

	"container-scanner/internal/scanners"
	"container-scanner/internal/utils"
	"sync"
)

type ScanRequest struct {
	ImageName string `json:"imageName"`
}

type ScanResponse struct {
	ImageID  string             `json:"imageId"`
	Findings []scanners.Finding `json:"findings"`
	Cached   bool               `json:"cached"`
}

// Global cache for scan results (thread-safe)
var (
	scanCache = make(map[string]ScanResponse)
	cacheMu   sync.RWMutex
)

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

		// Security: Validate image name to prevent injection or malicious inputs
		imageName := strings.TrimSpace(req.ImageName)
		if imageName == "" || strings.Contains(imageName, ";") || strings.Contains(imageName, "&") {
			http.Error(w, "Invalid image name", http.StatusBadRequest)
			return
		}

		img, err := utils.GetImage(cli, imageName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Performance: Check cache first
		cacheMu.RLock()
		if res, ok := scanCache[img.ID]; ok {
			cacheMu.RUnlock()
			res.Cached = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(res)
			return
		}
		cacheMu.RUnlock()

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

		// Concurrency: Use Group to run scanners in parallel
		var (
			wg         sync.WaitGroup
			findingsMu sync.Mutex
			findings   []scanners.Finding
		)

		for _, s := range activeScanners {
			wg.Add(1)
			go func(scanner scanners.Scanner) {
				defer wg.Done()
				results, err := scanner.Scan(img, ctx)
				if err != nil {
					fmt.Printf("Error running %s: %v\n", scanner.Name(), err)
					return
				}
				findingsMu.Lock()
				findings = append(findings, results...)
				findingsMu.Unlock()
			}(s)
		}

		wg.Wait()

		resp := ScanResponse{
			ImageID:  img.ID,
			Findings: findings,
			Cached:   false,
		}

		// Save to cache
		cacheMu.Lock()
		scanCache[img.ID] = resp
		cacheMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Serve frontend
	fs := http.FileServer(http.Dir("./web/ui/dist"))
	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api") {
			fs.ServeHTTP(w, r)
		}
	}))

	// Security: Default to local binding only unless explicitly allowed
	// For this personal project, we stick to the user's requested port but note the security.
	fmt.Printf("Server starting on http://localhost:%s\n", port)
	return http.ListenAndServe("127.0.0.1:"+port, nil)
}
