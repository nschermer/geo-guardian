package main

import (
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"time"
)

// generateRandomIP generates a random valid IP address
func generateRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(255)+1,
		rand.Intn(256),
		rand.Intn(256),
		rand.Intn(254)+1,
	)
}

// generateLocalIP generates a random IP in the 192.168.0.x range
func generateLocalIP() string {
	return fmt.Sprintf("192.168.0.%d", rand.Intn(254)+1)
}

// generateIPs generates a mix of random and local IP addresses
func generateIPs(count int, localRatio float64) []string {
	ips := make([]string, 0, count)
	localCount := int(float64(count) * localRatio)

	// Generate local IPs
	for i := 0; i < localCount; i++ {
		ips = append(ips, generateLocalIP())
	}

	// Generate random IPs
	for i := 0; i < count-localCount; i++ {
		ips = append(ips, generateRandomIP())
	}

	// Shuffle the list
	rand.Shuffle(len(ips), func(i, j int) {
		ips[i], ips[j] = ips[j], ips[i]
	})

	return ips
}

// benchmark runs benchmark with the given IPs
func benchmark(server, port string, ips []string) []float64 {
	url := fmt.Sprintf("http://%s:%s/", server, port)
	elapsedTimes := make([]float64, 0, len(ips))

	fmt.Printf("Running benchmark against %s\n", url)
	fmt.Printf("Testing with %d IP addresses...\n", len(ips))

	transport := &http.Transport{
		IdleConnTimeout: 15 * time.Second,
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}

	for i, ip := range ips {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("Error creating request for IP %s: %v\n", ip, err)
			continue
		}

		req.Header.Set("X-Forwarded-For", ip)

		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start).Seconds() * 1000 // Convert to milliseconds

		if err != nil {
			fmt.Printf("Error with IP %s: %v\n", ip, err)
			continue
		}

		// Ensure body is closed to prevent resource leaks
		defer resp.Body.Close()
		elapsedTimes = append(elapsedTimes, elapsed)

		if (i+1)%1000 == 0 {
			fmt.Printf("Progress: %d/%d\n", i+1, len(ips))
		}
	}

	return elapsedTimes
}

// calculateMean calculates the mean of a slice of floats
func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// calculateMedian calculates the median of a slice of floats
func calculateMedian(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

// calculatePercentile calculates the nth percentile of a slice of floats
func calculatePercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	index := int(math.Ceil(float64(len(sorted)) * percentile))
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

// printStatistics prints statistics from the benchmark run
func printStatistics(times []float64) {
	if len(times) == 0 {
		fmt.Println("No successful requests")
		return
	}

	mean := calculateMean(times)
	median := calculateMedian(times)
	minTime := times[0]
	maxTime := times[0]
	totalTime := 0.0

	for _, t := range times {
		totalTime += t
		if t < minTime {
			minTime = t
		}
		if t > maxTime {
			maxTime = t
		}
	}

	p99 := calculatePercentile(times, 0.99)

	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println("BENCHMARK RESULTS")
	fmt.Println("==================================================")
	fmt.Printf("Total requests:  %d\n", len(times))
	fmt.Printf("Total time:      %.2f ms (%.2f s)\n", totalTime, totalTime/1000)
	fmt.Printf("Mean:            %.2f ms\n", mean)
	fmt.Printf("Median:          %.2f ms\n", median)
	fmt.Printf("99th percentile: %.2f ms\n", p99)
	fmt.Printf("Min:             %.2f ms\n", minTime)
	fmt.Printf("Max:             %.2f ms\n", maxTime)
	fmt.Println("==================================================")
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run benchmark.go <server> <port>")
		fmt.Println("Example: go run benchmark.go localhost 8080")
		os.Exit(1)
	}

	server := os.Args[1]
	port := os.Args[2]

	// Seed random number generator
	rand.Seed(time.Now().UnixNano())

	// Generate IPs
	ips := generateIPs(10000, 0.1)

	// Run benchmark
	elapsedTimes := benchmark(server, port, ips)

	// Print statistics
	printStatistics(elapsedTimes)
}
