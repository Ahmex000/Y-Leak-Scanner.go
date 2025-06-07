package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Define a map of keywords with severity levels
var KEYWORDS = map[string]string{
	// your keywords list here
	// EX
	`affirm[-_]?private\s*[:=\"'\s]*\s*([a-zA-Z0-9_\-]{8,}[^'\":;\s,]*)`: "High",
	`app[-_]?token\s*[:=\"'\s]*\s*([a-zA-Z0-9_\-]{8,}[^'\":;\s,]*)`:      "High",
	`map[-_]?box\s*[:=\"'\s]*\s*([a-zA-Z0-9_\-]{8,}[^'\":;\s,]*) `:       "High",
	`private[-_]?token\s*[:=\"'\s]*\s*([a-zA-Z0-9_\-]{8,}[^'\":;\s,]*)`:  "High",
	`api[-_]?key\s*[:=\"'\s]*\s*([a-zA-Z0-9_\-]{8,}[^'\":;\s,]*)`:        "High",
}

// Global counters for tracking lines and current URL index
var (
	totalLines      int
	currentURLIndex int
	mutex           sync.Mutex
)

func main() {
	// Define command-line flags
	urlFile := flag.String("f", "", "File containing list of URLs to scan")
	threads := flag.Int("t", 10, "Number of concurrent threads (increase for more speed)")
	outputFile := flag.String("o", "", "Output file to store results")
	flag.Parse()

	// Check if URL file is provided
	if *urlFile == "" {
		fmt.Println("Please provide a file with URLs using the -f flag")
		fmt.Println("Usage: go run Y-LeakScanner.go -f urls.txt -t 10 -o output.txt")
		os.Exit(1)
	}

	// Open output file with buffered writer
	var outputWriter *bufio.Writer
	var output *os.File
	if *outputFile != "" {
		var err error
		output, err = os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Error opening output file: %v\n", err)
			os.Exit(1)
		}
		defer func() {
			if outputWriter != nil {
				outputWriter.Flush()
			}
			output.Close()
		}()
		outputWriter = bufio.NewWriter(output)
	}

	// Read URLs from file
	urls, err := readURLs(*urlFile)
	if err != nil {
		printProgress()
		os.Exit(1)
	}

	// Initialize totalLines with the number of URLs
	totalLines = len(urls)

	// Initialize WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup
	// Semaphore to limit concurrent goroutines
	semaphore := make(chan struct{}, *threads)

	// Process each URL concurrently
	for _, url := range urls {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire a thread slot
		go func(targetURL string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release the thread slot
			scanURL(targetURL, outputWriter)
		}(url)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	fmt.Println("\nScanning completed!")
}

func printProgress() {
	fmt.Printf("\r\033[2KProgress: [%d/%d]", currentURLIndex, totalLines)
}

// Read URLs from a file
func readURLs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}
	return urls, scanner.Err()
}

// Send HTTP request and scan response
func scanURL(url string, outputWriter *bufio.Writer) {
	// Increment current URL index and display progress
	mutex.Lock()
	currentURLIndex++
	printProgress()
	mutex.Unlock()

	// Create HTTP client with timeout for better performance
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		mutex.Lock()
		fmt.Printf("\nError fetching %s: %v\n", url, err)
		printProgress()
		mutex.Unlock()
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		mutex.Lock()
		fmt.Printf("\nError reading response from %s: %v\n", url, err)
		printProgress()
		mutex.Unlock()
		return
	}

	// Scan response body
	bodyStr := string(body)
	scanResponse(url, bodyStr, outputWriter)
}

// Scan response body for sensitive keywords
func scanResponse(url, body string, outputWriter *bufio.Writer) {
	for keyword, severity := range KEYWORDS {
		var re *regexp.Regexp
		if strings.ContainsAny(keyword, "[{(|?*+^$") {
			re = regexp.MustCompile("(?i)" + keyword)
		} else {
			re = regexp.MustCompile("(?i)" + regexp.QuoteMeta(keyword))
		}

		matches := re.FindAllString(body, -1)
		for _, match := range matches {
			severityColor := "\033[31m" // Red for High
			if severity != "High" {
				severityColor = "\033[32m"
			}

			alert := fmt.Sprintf(
				"\n\033[31m[ALERT]\033[0m Found sensitive data in \033[36m%s\033[0m\nMatch: \033[33m%s\033[0m\nSeverity: %s%s\033[0m\nRegex Pattern: \033[34m%s\033[0m\n",
				url, match, severityColor, severity, keyword,
			)

			mutex.Lock()

			fmt.Print(alert)
			printProgress()

			if outputWriter != nil {
				outputWriter.WriteString(alert)
				outputWriter.Flush()
			}
			mutex.Unlock()
		}
	}
}
