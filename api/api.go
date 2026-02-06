package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"cvedashboard2.0/parser"
	"cvedashboard2.0/storage"

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
			Timeout: 6 * time.Second,
		},
		baseUrl:     "https://services.nvd.nist.gov/rest/json/cves/2.0/",
		rateLimiter: time.NewTicker(5 * time.Second),
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
	// api.GET("/vulns", getVulns)
	api.GET("/vulnerabilities", getVulns)
	// !FIXME
	// api.GET("/timestamp", getTime)

	api.Run(":8080")

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
	b, err := parser.Unmarshal(a)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	j, err := storage.Connect()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	l := j.InsertVulnData(&b)
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

// !FIXME
// func getTime(c *gin.Context) {

// 	a, err := NewClient().FetchCVEs(c.Request.Context(), 1, 10)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 		return
// 	}
// 	b, err := parser.Unmarshal(a)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
// 		return
// 	}
// 	d := data.GetTimeStamp(b)
// 	c.JSON(http.StatusOK, d)
// }
