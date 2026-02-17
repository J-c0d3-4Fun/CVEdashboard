package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cvedashboard2.0/middleware"
	"cvedashboard2.0/parser"
	"cvedashboard2.0/storage"
	"cvedashboard2.0/structs"
)

type Client struct {
	Clients     *http.Client
	baseUrl     string
	rateLimiter *time.Ticker
}

func NewClient() *Client {
	return &Client{
		Clients: &http.Client{
			Timeout: 60 * time.Second,
		},
		baseUrl:     "https://services.nvd.nist.gov/rest/json/cves/2.0/",
		rateLimiter: time.NewTicker(1 * time.Second),
	}
}

func NewClientGithub() *Client {
	return &Client{
		Clients: &http.Client{
			Timeout: 60 * time.Second,
		},
		baseUrl:     "https://api.github.com/advisories",
		rateLimiter: time.NewTicker(1 * time.Second),
	}
}

func (c *Client) FetchCVEs(ctx context.Context, startIndex, resultsPerPage int) ([]byte, error) {
	// Rate limiting - wait for ticker
	select {
	case <-c.rateLimiter.C:

	case <-ctx.Done():
		return nil, ctx.Err()
	}

	fullurl := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", c.baseUrl, resultsPerPage, startIndex)

	req, err := http.NewRequestWithContext(ctx, "GET", fullurl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	apiKey := os.Getenv("API_KEY")
	req.Header.Set("apiKey", apiKey)
	resp, err := c.Clients.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CVEs: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll((resp.Body))
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return body, nil
}

func (c *Client) FetchGithubAdvisories(ctx context.Context, url string) ([]byte, string, error) {

	if url == "" {
		url = fmt.Sprintf("%s?per_page=100", c.baseUrl)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	githubToken := os.Getenv("GITHUB_TOKEN")
	req.Header.Set("Authorization", "Bearer "+githubToken)
	resp, err := c.Clients.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch CVEs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response body: %w", err)
	}

	nextURL := parseNextLink(resp.Header.Get("Link"))
	return body, nextURL, nil
}

func parseNextLink(linkHeader string) string {
	for _, part := range strings.Split(linkHeader, ",") {
		if strings.Contains(part, `rel="next"`) {
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start != -1 && end != -1 {
				return part[start+1 : end]
			}
		}
	}
	return ""
}

func main() {

	port := ":8081"
	// Setup the routes

	http.HandleFunc("GET /github", getVulnsGithub)
	http.HandleFunc("GET /github/search", SearchGithub)
	http.HandleFunc("GET /nvd", getVulns)
	http.HandleFunc("GET /nvd/search", SearchNVD)
	http.HandleFunc("GET /", homePage)
	http.HandleFunc("GET /sync/github", SyncButtonGithub)
	http.HandleFunc("GET /sync/nvd", SyncButtonNVD)
	log.Println("Listening and serving HTTP on", port)

	pathLogging := middleware.PathLogging(http.DefaultServeMux)

	go AutoSyncNVDData()
	go AutoSyncGithubData()

	// everything must be before this line or it will not run
	log.Fatal(http.ListenAndServe(port, pathLogging))

}

func AutoSyncNVDData() {
	client := NewClient()
	startIndex := 0
	for {
		body, err := client.FetchCVEs(context.Background(), startIndex, 2000)
		if err != nil {
			fmt.Printf("fetch error at index %d: %v\n", startIndex, err)
			break
		}
		data, err := parser.Unmarshal[structs.NvdJson](body)
		if err != nil {
			fmt.Printf("unmarshal error: %v\n", err)
			break
		}
		db, err := storage.Connect()
		if err != nil {
			fmt.Printf("db connect error: %v\n", err)
			break
		}
		if err := db.InsertVulnDataNVD(&data); err != nil {
			fmt.Printf("insert error: %v\n", err)
		}
		db.Close()
		fmt.Printf("nvd data synced %d/%d\n", startIndex+len(data.Vulnerabilities), data.TotalResults)
		startIndex += 2000
		if startIndex >= data.TotalResults {
			break
		}
	}
	fmt.Println("NVD sync complete")
}

func AutoSyncGithubData() {
	client := NewClientGithub()
	nextURL := ""
	page := 1
	for {
		body, next, err := client.FetchGithubAdvisories(context.Background(), nextURL)
		if err != nil {
			fmt.Printf("fetch error: %s", err)
			break
		}
		data, err := parser.Unmarshal[[]structs.GithubJson](body)
		if err != nil {
			fmt.Printf("marshaler error: %s", err)
			break
		}
		if len(data) == 0 {
			break
		}
		db, err := storage.Connect()
		if err != nil {
			fmt.Printf("db connect error: %s", err)
			break
		}
		err1 := db.InsertVulnDataGithub(data)
		if err1 != nil {
			fmt.Printf("insert error: %s", err1)
			break
		}
		db.Close()
		fmt.Printf("github advisories synced page %d: %d advisories\n", page, len(data))
		page++
		nextURL = next
		if nextURL == "" {
			break
		}
	}
	fmt.Println("GitHub sync complete")
}

func getVulns(w http.ResponseWriter, r *http.Request) {

	d, err := storage.Connect()
	log.Println("Connecting to DB......")
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	i, err := d.Read()
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer d.Close()

	WriteJSON(w, http.StatusOK, i)
}

func getVulnsGithub(w http.ResponseWriter, r *http.Request) {

	d, err := storage.Connect()
	log.Println("Connecting to DB......")
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	i, err := d.ReadGithub()
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer d.Close()

	WriteJSON(w, http.StatusOK, i)

}

func WriteJSON(w http.ResponseWriter, status int, data any) {
	const jsonContentType = "application/json"
	w.Header().Set("Content-Type", jsonContentType)

	w.WriteHeader(status)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func ErrorHandler(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]any{"[ERROR]": msg})
}

func SearchNVD(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	log.Println("Connecting to DB......")
	d, err := storage.Connect()
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer d.Close()
	results, err := d.FilterRequestNVD(service)
	WriteJSON(w, http.StatusOK, results)

}

func SearchGithub(w http.ResponseWriter, r *http.Request) {
	advisory := r.URL.Query().Get("advisory")
	log.Println("Connecting to DB......")
	d, err := storage.Connect()
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer d.Close()
	results, err := d.FilterRequestGithub(advisory)

	WriteJSON(w, http.StatusOK, results)

}

// Filters for homepage
// Highest Severity Vuln
// Most Recent Vuln for github
// Most Recent Vuln for NVD
// heat map

func homePage(w http.ResponseWriter, r *http.Request) {
	d, err := storage.Connect()
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer d.Close()
	githubResult, err := d.ReadHomepageGithub()
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, githubResult)
	nvdResult, err := d.ReadHomepageNVd()
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}

	WriteJSON(w, http.StatusOK, nvdResult)

}

func SyncButtonGithub(w http.ResponseWriter, r *http.Request) {
	go AutoSyncGithubData()
	w.WriteHeader(http.StatusAccepted)
	fmt.Printf("Sync started in background")
}

func SyncButtonNVD(w http.ResponseWriter, r *http.Request) {
	go AutoSyncNVDData()
	w.WriteHeader(http.StatusAccepted)
	fmt.Printf("Sync started in background")
}
