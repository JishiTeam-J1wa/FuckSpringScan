package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var dictionary = []string{
	"actuator",
	"actuator/auditLog",
	"actuator/auditevents",
	"actuator/autoconfig",
	"actuator/beans",
	"actuator/caches",
	"actuator/conditions",
	"actuator/configurationMetadata",
	"actuator/configprops",
	"actuator/dump",
	"actuator/env",
	"actuator/events",
	"actuator/exportRegisteredServices",
	"actuator/features",
	"actuator/flyway",
	"actuator/health",
	"actuator/heapdump",
	"actuator/healthcheck",
	"actuator/httptrace",
	"actuator/hystrix.stream",
	"actuator/info",
	"actuator/integrationgraph",
	"actuator/jolokia",
	"actuator/logfile",
	"actuator/loggers",
	"actuator/loggingConfig",
	"actuator/liquibase",
	"actuator/metrics",
	"actuator/mappings",
	"actuator/scheduledtasks",
	"actuator/swagger-ui.html",
	"actuator/prometheus",
	"actuator/refresh",
	"actuator/registeredServices",
	"actuator/releaseAttributes",
	"actuator/resolveAttributes",
	"actuator/sessions",
	"actuator/springWebflow",
	"actuator/shutdown",
	"actuator/sso",
	"actuator/ssoSessions",
	"actuator/statistics",
	"actuator/status",
	"actuator/threaddump",
	"actuator/trace",
	"auditevents",
	"autoconfig",
	"api.html",
	"api/index.html",
	"api/swagger-ui.html",
	"api/v2/api-docs",
	"api-docs",
	"beans",
	"caches",
	"cloudfoundryapplication",
	"conditions",
	"configprops",
	"distv2/index.html",
	"docs",
	"druid/index.html",
	"druid/login.html",
	"druid/websession.html",
	"dubbo-provider/distv2/index.html",
	"dump",
	"entity/all",
	"env",
	"env/(name)",
	"eureka",
	"flyway",
	"gateway/actuator",
	"gateway/actuator/auditevents",
	"gateway/actuator/beans",
	"gateway/actuator/conditions",
	"gateway/actuator/configprops",
	"gateway/actuator/env",
	"gateway/actuator/health",
	"gateway/actuator/heapdump",
	"gateway/actuator/httptrace",
	"gateway/actuator/hystrix.stream",
	"gateway/actuator/info",
	"gateway/actuator/jolokia",
	"gateway/actuator/logfile",
	"gateway/actuator/loggers",
	"gateway/actuator/mappings",
	"gateway/actuator/metrics",
	"gateway/actuator/scheduledtasks",
	"gateway/actuator/swagger-ui.html",
	"gateway/actuator/threaddump",
	"gateway/actuator/trace",
	"health",
	"heapdump.json",
	"httptrace",
	"hystrix",
	"hystrix.stream",
	"info",
	"integrationgraph",
	"jolokia",
	"jolokia/list",
	"liquibase",
	"list",
	"logfile",
	"loggers",
	"metrics",
	"mappings",
	"monitor",
	"prometheus",
	"refresh",
	"scheduledtasks",
	"sessions",
	"shutdown",
	"spring-security-oauth-resource/swagger-ui.html",
	"spring-security-rest/api/swagger-ui.html",
	"static/swagger.json",
	"sw/swagger-ui.html",
	"swagger",
	"swagger/codes",
	"swagger/index.html",
	"swagger/static/index.html",
	"swagger/swagger-ui.html",
	"swagger-dubbo/api-docs",
	"swagger-ui",
	"swagger-ui.html",
	"swagger-ui/html",
	"swagger-ui/index.html",
	"system/druid/index.html",
	"threaddump",
	"template/swagger-ui.html",
	"trace",
	"user/swagger-ui.html",
	"version",
	"v1.1/swagger-ui.html",
	"v1.2/swagger-ui.html",
	"v1.3/swagger-ui.html",
	"v1.4/swagger-ui.html",
	"v1.5/swagger-ui.html",
	"v1.6/swagger-ui.html",
	"v1.7/swagger-ui.html",
	"v1.8/swagger-ui.html",
	"v1.9/swagger-ui.html",
	"v2.0/swagger-ui.html",
	"v2.1/swagger-ui.html",
	"v2.2/swagger-ui.html",
	"v2.3/swagger-ui.html",
	"v2/swagger.json",
	"webpage/system/druid/index.html",
	"%20/swagger-ui.html",
}

var bypassPayloads = []string{
	"",        // 原始路径
	"%2e%2e/", // URL编码绕过
	"..;/",    // 分号绕过
	"../",     // 经典绕过
	";/",      // 分号结尾绕过
	"./",      // 点斜杠绕过
}

func main() {
	// 黑客风格主页
	Banner()

	// 定义命令行参数
	var baseURL string
	var bypass bool
	var outputFile string
	var maxThreads int
	var runPoC bool

	flag.StringVar(&baseURL, "u", "", "输入目标URL")
	flag.BoolVar(&bypass, "bypass", false, "启用绕过Payload")
	flag.StringVar(&outputFile, "o", "", "输出200状态的结果到指定文件")
	flag.IntVar(&maxThreads, "int", 1, "最大线程数量 (1-200)")
	flag.BoolVar(&runPoC, "poc", false, "启用漏洞检测PoC")

	// 自定义帮助信息
	flag.Usage = func() {
		printHelp()
		os.Exit(0)
	}

	// 解析命令行参数
	flag.Parse()

	// 如果没有输入URL，打印帮助信息
	if baseURL == "" {
		flag.Usage()
		return
	}

	// 确保不会同时执行目录扫描和漏洞检测
	if baseURL == "" || (runPoC && baseURL == "") {
		flag.Usage()
		return
	}

	// 确保URL以 http:// 或 https:// 开头
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		fmt.Println("请使用 http:// 或 https:// 开头的有效URL")
		return
	}

	// 确保URL以 / 结尾
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	// 检查线程数量限制
	if maxThreads < 1 {
		maxThreads = 1
	} else if maxThreads > 20 {
		maxThreads = 20
	}

	// 创建HTTP客户端，禁用TLS证书验证
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 打开输出文件（如果指定）
	var output *os.File
	var err error
	if outputFile != "" {
		output, err = os.Create(outputFile)
		if err != nil {
			fmt.Printf("无法创建输出文件: %s\n", err)
			return
		}
		defer output.Close()
	}

	if runPoC {
		runVulnerabilityPoCs(client, baseURL, output)
	}
	// 如果启用漏洞检测PoC，优先进行漏洞检测
	if runPoC {
		runVulnerabilityPoCs(client, baseURL, output)
		return
	}
	// 创建一个信号量来控制并发线程数
	sem := make(chan struct{}, maxThreads)
	var wg sync.WaitGroup

	// 扫描目录
	for _, path := range dictionary {
		// 确保路径没有 / 开头
		if strings.HasPrefix(path, "/") {
			path = strings.TrimPrefix(path, "/")
		}
		if bypass {
			for _, payload := range bypassPayloads {
				wg.Add(1)
				sem <- struct{}{}
				go func(path, payload string) {
					defer wg.Done()
					defer func() { <-sem }()
					url := fmt.Sprintf("%s%s%s", baseURL, payload, path)
					checkURL(client, url, output, true)
				}(path, payload)
			}
		} else {
			wg.Add(1)
			sem <- struct{}{}
			go func(path string) {
				defer wg.Done()
				defer func() { <-sem }()
				url := fmt.Sprintf("%s%s", baseURL, path)
				checkURL(client, url, output, false)
			}(path)
		}
	}

	wg.Wait()

}

func checkURL(client *http.Client, url string, output *os.File, isBypass bool) {
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("请求失败: %s\n", err)
		return
	}
	defer resp.Body.Close()

	var contentLength string
	if resp.ContentLength != -1 {
		contentLength = fmt.Sprintf("%d", resp.ContentLength)
	} else {
		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			contentLength = fmt.Sprintf("%d", len(body))
		} else {
			contentLength = "未知"
		}
	}

	// 设置前缀和颜色
	prefix := "+"
	if resp.StatusCode != 200 {
		prefix = "-"
	}
	if resp.StatusCode == 403 {
		color.Cyan("%s %-50s 响应包 %d   长度 %s\n", prefix, url, resp.StatusCode, contentLength)
	} else if isBypass {
		color.Red("%s %-50s 响应包 %d   长度 %s\n", prefix, url, resp.StatusCode, contentLength)
	} else {
		if resp.StatusCode == 200 {
			color.Red("%s %-50s 响应包 %d   长度 %s\n", prefix, url, resp.StatusCode, contentLength)
		} else {
			fmt.Printf("%s %-50s 响应包 %d   长度 %s\n", prefix, url, resp.StatusCode, contentLength)
		}
	}

	// 输出到文件
	if output != nil && resp.StatusCode == 200 {
		output.WriteString(fmt.Sprintf("%s 响应包 %d 长度 %s\n", url, resp.StatusCode, contentLength))
	}
}

func Banner() {
	banner := `
	/$$$$$   /$$          /$$$$$$$$                           
   |__  $$ /$$$$         |__  $$__/                           
	  | $$|_  $$    /$$$$$$$| $$  /$$$$$$   /$$$$$$  /$$$$$$$ 
	  | $$  | $$   /$$_____/| $$ /$$__  $$ |____  $$| $$__  $$
 /$$  | $$  | $$  |  $$$$$$ | $$| $$$$$$$$  /$$$$$$$| $$  \ $$
| $$  | $$  | $$   \____  $$| $$| $$_____/ /$$__  $$| $$  | $$
|  $$$$$$/ /$$$$$$ /$$$$$$$/| $$|  $$$$$$$|  $$$$$$$| $$  | $$
 \______/ |______/|_______/ |__/ \_______/ \_______/|__/  |__/
															  
															  
							SpringFcukScan           version: 1.0` + `
`
	fmt.Println(banner)
	fmt.Print("内置Spring敏感目录：")
	fmt.Print(len(dictionary))
	fmt.Print("条")
}

func printHelp() {
	help := `
使用方法: 
  -u      输入目标URL (例如: -u https://example.com)
  -bypass 启用绕过Payload
  -o      输出200状态的结果到指定文件
  -int    最大线程数量 (1-2000)
  -h      打印帮助信息

示例:
  ./SpringFcukScan -u https://example.com
  ./SpringFcukScan -u https://example.com -bypass
  ./SpringFcukScan -u https://example.com -o results.txt
  ./SpringFcukScan -u https://example.com -int 5（最大不超过20）
`
	fmt.Println(help)
}

func runVulnerabilityPoCs(client *http.Client, baseURL string, output *os.File) {
	// 添加常见的Spring漏洞检测PoC
	runSpring4ShellPoC(client, baseURL, output)
	runSSRFPoC(client, baseURL, output)
	runOpenRedirectPoC(client, baseURL, output)
	// 添加其他PoC检测
	runCVE202422233PoC(client, baseURL, output)
	runCVE202422259PoC(client, baseURL, output)
}
func runSpring4ShellPoC(client *http.Client, baseURL string, output *os.File) {
	// Spring4Shell 漏洞检测代码
	url := fmt.Sprintf("%s%s", baseURL, "vulnerable/path")
	payload := []byte("malicious payload")
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("Spring4Shell检测失败: %s\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Spring4Shell检测失败: %s\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应失败: %s\n", err)
		return
	}

	// 检测逻辑
	if resp.StatusCode == 200 && strings.Contains(string(body), "vulnerable indicator") {
		color.Red("Spring4Shell 漏洞存在: %s\n", url)
		if output != nil {
			output.WriteString(fmt.Sprintf("Spring4Shell 漏洞存在: %s\n", url))
		}
	} else {
		color.Blue("Spring4Shell 不存在: %s\n", url)
	}
}

func runSSRFPoC(client *http.Client, baseURL string, output *os.File) {
	// 示例SSRF PoC检测代码
	url := fmt.Sprintf("%s%s", baseURL, "vulnerable/path")
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("SSRF检测失败: %s\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应失败: %s\n", err)
		return
	}

	// 检测逻辑
	if resp.StatusCode == 200 && strings.Contains(string(body), "ssrf indicator") {
		color.Red("SSRF 漏洞存在: %s\n", url)
		if output != nil {
			output.WriteString(fmt.Sprintf("SSRF 漏洞存在: %s\n", url))
		}
	} else {
		color.Blue("SSRF 疑似存在: %s\n", url)
	}
}

func runOpenRedirectPoC(client *http.Client, baseURL string, output *os.File) {
	// 示例Open Redirect PoC检测代码
	url := fmt.Sprintf("%s%s", baseURL, "vulnerable/path?redirect=http://malicious.com")
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Open Redirect检测失败: %s\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应失败: %s\n", err)
		return
	}

	// 检测逻辑
	if resp.StatusCode == 200 && strings.Contains(string(body), "http://malicious.com") {
		color.Red("Open Redirect 漏洞存在: %s\n", url)
		if output != nil {
			output.WriteString(fmt.Sprintf("Open Redirect 漏洞存在: %s\n", url))
		}
	} else {
		color.Blue("Open Redirect 疑似存在: %s\n", url)
	}
}

func runCVE202422233PoC(client *http.Client, baseURL string, output *os.File) {
	// CVE-2024-22233 漏洞检测代码
	url := fmt.Sprintf("%s%s", baseURL, "vulnerable/path")
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("CVE-2024-22233检测失败: %s\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应失败: %s\n", err)
		return
	}

	// 检测逻辑
	if resp.StatusCode == 200 && strings.Contains(string(body), "DoS indicator") {
		color.Red("CVE-2024-22233 漏洞存在: %s\n", url)
		if output != nil {
			output.WriteString(fmt.Sprintf("CVE-2024-22233 漏洞存在: %s\n", url))
		}
	} else {
		color.Blue("CVE-2024-22233 疑似存在: %s\n", url)
	}
}

func runCVE202422259PoC(client *http.Client, baseURL string, output *os.File) {
	// CVE-2024-22259 漏洞检测代码
	url := fmt.Sprintf("%s%s", baseURL, "vulnerable/path")
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("CVE-2024-22259检测失败: %s\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应失败: %s\n", err)
		return
	}

	// 检测逻辑
	if resp.StatusCode == 200 && strings.Contains(string(body), "redirect indicator") {
		color.Red("CVE-2024-22259 漏洞存在: %s\n", url)
		if output != nil {
			output.WriteString(fmt.Sprintf("CVE-2024-22259 漏洞存在: %s\n", url))
		}
	} else {
		color.Blue("CVE-2024-22259 疑似存在: %s\n", url)
	}

}
