package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"cvedashboard2.0/parser"
	"cvedashboard2.0/storage"
	"cvedashboard2.0/structs"

	"github.com/gin-gonic/gin"
)

type Client struct {
	Clients     *http.Client
	baseUrl     string
	rateLimiter *time.Ticker
}

func NewClient() *Client {
	return &Client{
		Clients: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseUrl:     "https://services.nvd.nist.gov/rest/json/cves/2.0/",
		rateLimiter: time.NewTicker(1 * time.Second),
	}
}

func NewClientGithub() *Client {
	return &Client{
		Clients: &http.Client{
			Timeout: 30 * time.Second,
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

func (c *Client) FetchGithubAdvisories(ctx context.Context) ([]byte, error) {

	req, err := http.NewRequestWithContext(ctx, "GET", c.baseUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

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

func main() {
	api := gin.Default()

	// Setup the routes

	api.GET("/nvd", getVulns)
	api.GET("/github", getVulnsGithub)
	api.GET("/nvd/search", SearchNVD)
	// !FIXME

	go syncNVDData()

	api.Run(":8080")

}

func syncNVDData() {
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
		fmt.Printf("synced %d/%d\n", startIndex+len(data.Vulnerabilities), data.TotalResults)
		startIndex += 2000
		if startIndex >= data.TotalResults {
			break
		}
	}
	fmt.Println("NVD sync complete")
}

// Handlers
// TODO This is a proof of concept below:
// func getVulns(c *gin.Context) {
// 	a, err := NewClient().FetchCVEs(c.Request.Context(), 1, 100)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 		return
// 	}
// 	b, err := parser.Unmarshal(a)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 		return
// 	}
// 	c.JSON(http.StatusOK, b)
// }

func getVulns(c *gin.Context) {
	a, err := NewClient().FetchCVEs(c.Request.Context(), 1, 100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	b, err := parser.Unmarshal[structs.NvdJson](a)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	j, err := storage.Connect()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	l := j.InsertVulnDataNVD(&b)
	if l != nil {
		fmt.Print(l.Error())
	}
	err1 := j.Close()
	if err1 != nil {
		fmt.Print(err1.Error())
	}
	d, err := storage.Connect()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	i, err := d.Read()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	k := d.Close()
	if k != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, i)
}

func getVulnsGithub(c *gin.Context) {
	a, err := NewClientGithub().FetchGithubAdvisories(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	b, err := parser.Unmarshal[[]structs.GithubJson](a)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	j, err := storage.Connect()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	l := j.InsertVulnDataGithub(b)
	if l != nil {
		fmt.Print(l.Error())
	}
	err1 := j.Close()
	if err1 != nil {
		fmt.Print(err1.Error())
	}
	d, err := storage.Connect()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	i, err := d.ReadGithub()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	k := d.Close()
	if k != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, i)
}

func SearchNVD(c *gin.Context) {
	service := c.Query("service")
	d, err := storage.Connect()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	results, err := d.FilterRequestNVD(service)
	c.JSON(http.StatusOK, results)

}
