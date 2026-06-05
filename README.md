# FuckSpringScan v5.0

Spring Framework 漏洞扫描工具

## 安装

```bash
git clone https://github.com/JishiTeam-J1wa/FuckSpringScan.git
cd FuckSpringScan
go build -o FuckSpringScan main.go
```

## 使用

### 基础扫描
```bash
./FuckSpringScan -u https://target.com -poc
```

### 智能Bypass
当端点被拦截时，使用智能bypass尝试所有绕过方式：
```bash
./FuckSpringScan -u https://target.com -bypassall actuator/env
```

### 批量扫描
```bash
./FuckSpringScan -f targets.txt -poc -html report.html
```

## 输出示例

### 端点扫描
```
[Target 1/1] https://target.com/
------------------------------------------------------------
[+] Spring Application Detected
    Version: 2.3.4
    Potential CVEs: [CVE-2022-22965]

[*] Running PoC checks...

[CRITICAL] Spring4Shell RCE
    URL:     https://target.com/
    CVE:     CVE-2022-22965
    Details: class.module.classLoader accessible
    Fix:     Upgrade to Spring 5.3.18+

[*] Scanning endpoints...
[i] Endpoints: 48, Payloads: 1, Total: 48
[+] https://target.com/actuator/env [200] 15234 bytes - Env Leak
[+] https://target.com/actuator/health [200] 234 bytes
[+] https://target.com/actuator/heapdump [200] 52428800 bytes - Heapdump
[-] https://target.com/actuator/shutdown [403] 0 bytes

[i] Completed in 12.5s

============================================================
[*] Scan Summary
    Duration:   45.2s
    Targets:    1
    Requests:   48
    Success:    5
    Sensitive:  3
    Vulns:      1
```

### 智能Bypass
```
[*] Smart Bypass Mode
------------------------------------------------------------
    Target: https://target.com/
    Path:   actuator/env
    Total:  62 bypass techniques

[-] https://target.com/actuator/env [403] 1234 bytes (blocked)

[*] WAF Bypass
[+] XFF-127         https://target.com/actuator/env [200] 15234 bytes

[*] Semantic Bypass

[*] Route Bypass
[+] Semi-2          https://target.com/..;/actuator/env [200] 15234 bytes
[+] JSESSIONID      https://target.com/;jsessionid=x/actuator/env [200] 15234 bytes

============================================================
[*] Bypass Summary
    Total tested: 62
    Time elapsed: 8.5s
    Successful:   3

[+] Working bypasses:
    [WAF] XFF-127
        https://target.com/actuator/env
    [Route] Semi-2
        https://target.com/..;/actuator/env
    [Route] JSESSIONID
        https://target.com/;jsessionid=x/actuator/env
```

## 参数

| 参数 | 说明 |
|------|------|
| `-u` | 目标URL |
| `-f` | 目标文件 |
| `-poc` | 漏洞检测 |
| `-bypass` | 路由绕过 |
| `-ghost` | 幽灵字节绕过 |
| `-bypassall <path>` | 智能Bypass指定路径 |
| `-deep` | 深度扫描 |
| `-heap` | 分析Heapdump |
| `-o` | JSON报告 |
| `-html` | HTML报告 |
| `-t` | 线程数 |
| `-proxy` | 代理 |
| `-v` | 详细输出 |

## 绕过技术

- **WAF Bypass (22种)**: URL编码、Unicode、NULL字节、Header伪造
- **Semantic Bypass (18种)**: 幽灵字节、全角字符、反斜杠
- **Route Bypass (22种)**: 分号注入、JSESSIONID、伪静态后缀

## 漏洞检测

| CVE | 漏洞 | 危害 |
|-----|------|------|
| CVE-2022-22965 | Spring4Shell | CRITICAL |
| CVE-2022-22947 | Gateway RCE | CRITICAL |
| CVE-2021-29441 | Nacos Auth Bypass | CRITICAL |
| - | Jolokia RCE | CRITICAL |
| - | H2 Console RCE | CRITICAL |
| - | Actuator Env Leak | HIGH |

## License

MIT

## Author

J1sTeam
