package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
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
		body, _ := io.ReadAll(resp.Body)
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

	pool := storage.NewConnectionPool(5)
	defer pool.Close()


	port := ":8081"
	// Setup the routes

	http.HandleFunc("GET /api/github", getVulnsGithub)
	http.HandleFunc("GET /api/github/search", SearchGithub)
	http.HandleFunc("GET /api/nvd", getVulns)
	http.HandleFunc("GET /api/nvd/search", SearchNVD)
	http.HandleFunc("GET /api/home", homePage)
	http.HandleFunc("GET /api/sync/github", SyncButtonGithub)
	http.HandleFunc("GET /api/sync/nvd", SyncButtonNVD)
	http.HandleFunc("GET /api/heatmap", getHeatMap)
	log.Println("Listening and serving HTTP on", port)
	http.Handle("/", http.FileServer(http.Dir("./static")))

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
			log.Printf("fetch error at index %d: %v\n", startIndex, err)
			break
		}
		data, err := parser.Unmarshal[structs.NvdJson](body)
		if err != nil {
			log.Printf("unmarshal error: %v\n", err)
			break
		}
		db, err := 
		if err != nil {
			log.Printf("db connect error: %v\n", err)
			break
		}
		if err := db.InsertVulnDataNVD(&data); err != nil {
			log.Printf("insert error: %v\n", err)
		}
		db.Close()
		fmt.Printf("nvd data synced %d/%d\n", startIndex+len(data.Vulnerabilities), data.TotalResults)
		startIndex += 2000
		if startIndex >= data.TotalResults {
			break
		}
	}
	log.Println("NVD sync complete")
}

func AutoSyncGithubData() {
	client := NewClientGithub()
	nextURL := ""
	page := 1
	for {
		body, next, err := client.FetchGithubAdvisories(context.Background(), nextURL)
		if err != nil {
			log.Printf("fetch error: %v", err)
			break
		}
		data, err := parser.Unmarshal[[]structs.GithubJson](body)
		if err != nil {
			log.Printf("marshaler error: %v", err)
			break
		}
		if len(data) == 0 {
			break
		}
		db, err := storage.Connect()
		if err != nil {
			log.Printf("db connect error: %v", err)
			break
		}
		err1 := db.InsertVulnDataGithub(data)
		if err1 != nil {
			log.Printf("insert error: %v", err1)
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
	log.Println("GitHub sync complete")
}

func getVulns(w http.ResponseWriter, r *http.Request) {
	page := pageParam(r, "page", 1)
	limit := pageParam(r, "limit", 50)
	offset := (page - 1) * limit

	d, err := storage.Connect()
	log.Println("Connecting to DB......")
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	i, err := d.Read(offset, limit)
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer d.Close()

	WriteJSON(w, http.StatusOK, i)
}

func getVulnsGithub(w http.ResponseWriter, r *http.Request) {
	page := pageParam(r, "page", 1)
	limit := pageParam(r, "limit", 50)
	offset := (page - 1) * limit

	d, err := storage.Connect()
	log.Println("Connecting to DB......")
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	i, err := d.ReadGithub(offset, limit)
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
	page := pageParam(r, "page", 1)
	limit := pageParam(r, "limit", 50)
	offset := (page - 1) * limit
	service := queryValidation(w, r, "service")
	if service == "" {
		return
	}
	log.Println("Connecting to DB......")
	d, err := storage.Connect()
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer d.Close()
	version := r.URL.Query().Get("version")
	results, err := d.FilterRequestNVD(service, version, offset, limit)
	if err != nil {
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}

	WriteJSON(w, http.StatusOK, results)

}

func SearchGithub(w http.ResponseWriter, r *http.Request) {
	page := pageParam(r, "page", 1)
	limit := pageParam(r, "limit", 50)
	offset := (page - 1) * limit
	advisory := queryValidation(w, r, "advisory")
	if advisory == "" {
		return
	}

	log.Println("Connecting to DB......")
	d, err := storage.Connect()

	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer d.Close()
	version := r.URL.Query().Get("version")
	results, err := d.FilterRequestGithub(advisory, version, offset, limit)
	if err != nil {
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}

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

	nvdResult, err := d.ReadHomepageNVd()
	if err != nil {
		log.Printf("DB Error: %s", err)
		ErrorHandler(w, http.StatusInternalServerError, err.Error())
		return
	}
	var (
		lastNVDSync struct {
			Status string
			Error  string
			Time   time.Time
		}
		lastGithubSync struct {
			Status string
			Error  string
			Time   time.Time
		}
	)

	WriteJSON(w, http.StatusOK, map[string]any{
		"github": githubResult,
		"nvd":    nvdResult,
		"sync": map[string]any{
			"nvd":    lastNVDSync,
			"github": lastGithubSync,
		},
	})

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

func queryValidation(w http.ResponseWriter, r *http.Request, param string) string {
	query := r.URL.Query()
	if !query.Has(param) {
		WriteJSON(w, http.StatusBadRequest, "Missing advisory parameter!")
		return ""
	}
	queryParam := query.Get(param)

	if queryParam == " " {
		WriteJSON(w, http.StatusBadRequest, "advisory cannot be empty!")
		return ""
	}
	return queryParam
}

func pageParam(r *http.Request, name string, defaultVal int) int {
	val := r.URL.Query().Get(name)
	if val == "" {
		return defaultVal
	}
	intVal, err := strconv.Atoi(val)
	if err == nil {
		return intVal
	}
	return defaultVal

}

func getHeatMap(w http.ResponseWriter, r *http.Request) {
	data, _ := storage.Connect()
	d, _ := data.GetHeatMapData()
	WriteJSON(w, http.StatusOK, d)
}
