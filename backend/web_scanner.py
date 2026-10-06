#!/usr/bin/env python3
"""
GitHub Actions web vulnerability scanner.
Runs in 6h timeout, no external services, no auth required.
Outputs JSON for GitHub Actions artifact + repo commit.
"""
import os
import json
import asyncio
import re
import ssl
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import httpx
from bs4 import BeautifulSoup

# ─── Config ───
TIMEOUT = 15
MAX_REDIRECTS = 5
CONCURRENCY = 5
USER_AGENT = "BulwarkScanner/1.0 (+https://bulwark.co.ke)"
USE_PLAYWRIGHT = os.getenv("USE_PLAYWRIGHT", "false").lower() == "true"

# Security headers to check
SECURITY_HEADERS = {
    "strict-transport-security": {"severity": "high", "desc": "HSTS missing — MITM risk"},
    "x-frame-options": {"severity": "medium", "desc": "Clickjacking protection missing"},
    "x-content-type-options": {"severity": "low", "desc": "MIME sniffing not disabled"},
    "content-security-policy": {"severity": "high", "desc": "CSP missing — XSS risk"},
    "referrer-policy": {"severity": "low", "desc": "Referrer policy not set"},
    "permissions-policy": {"severity": "low", "desc": "Permissions policy not set"},
    "cross-origin-opener-policy": {"severity": "low", "desc": "COOP not set"},
    "cross-origin-resource-policy": {"severity": "low", "desc": "CORP not set"},
}

# Cookie security flags
COOKIE_FLAGS = ["secure", "httponly", "samesite"]

# Sensitive paths to probe
SENSITIVE_PATHS = [
    "/.git/", "/.env", "/.env.production", "/config.json", "/backup.zip",
    "/backup.sql", "/database.sql", "/wp-config.php", "/.htaccess",
    "/robots.txt", "/sitemap.xml", "/phpinfo.php", "/info.php",
    "/.well-known/security.txt", "/server-status", "/actuator/health",
    "/api/docs", "/swagger.json", "/openapi.json", "/graphql",
    "/.DS_Store", "/Thumbs.db", "/composer.lock", "/package-lock.json",
    "/yarn.lock", "/.npmrc", "/docker-compose.yml", "/Dockerfile",
    "/.github/workflows/", "/.gitlab-ci.yml", "/Jenkinsfile",
]

# Technology fingerprints
TECH_FINGERPRINTS = {
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "React": ["react", "react-dom", "__REACT_DEVTOOLS_GLOBAL_HOOK__"],
    "Vue": ["vue.js", "vue.runtime", "vue-router"],
    "Angular": ["angular", "ng-version"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
    "Laravel": ["laravel_session", "X-Powered-By: Laravel"],
    "Django": ["csrftoken", "django"],
    "Express": ["x-powered-by: express"],
    "Next.js": ["__NEXT_DATA__", "next.js"],
    "Nuxt": ["nuxt", "__NUXT__"],
    "Cloudflare": ["cf-ray", "server: cloudflare"],
    "Apache": ["server: apache"],
    "Nginx": ["server: nginx"],
    "IIS": ["server: microsoft-iis"],
}

async def fetch_with_redirects(client: httpx.AsyncClient, url: str) -> List[httpx.Response]:
    """Follow redirects manually to capture chain."""
    responses = []
    current_url = url
    for _ in range(MAX_REDIRECTS):
        try:
            resp = await client.get(current_url, follow_redirects=False)
            responses.append(resp)
            if 300 <= resp.status_code < 400:
                location = resp.headers.get("location")
                if location:
                    current_url = urllib.parse.urljoin(current_url, location)
                    continue
            break
        except Exception:
            break
    return responses

def check_security_headers(headers: httpx.Headers) -> List[Dict]:
    """Check for missing security headers."""
    findings = []
    header_dict = {k.lower(): v for k, v in headers.items()}
    for header, info in SECURITY_HEADERS.items():
        if header not in header_dict:
            findings.append({
                "type": "missing_header",
                "header": header,
                "severity": info["severity"],
                "description": info["desc"],
                "evidence": f"Header '{header}' not present"
            })
    return findings

def check_cookies(headers: httpx.Headers) -> List[Dict]:
    """Check cookie security flags."""
    findings = []
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        cookies = set_cookie.split(", ")
        for cookie in cookies:
            cookie_lower = cookie.lower()
            missing = [flag for flag in COOKIE_FLAGS if flag not in cookie_lower]
            if missing:
                findings.append({
                    "type": "cookie_flags",
                    "severity": "medium" if "secure" in missing or "httponly" in missing else "low",
                    "description": f"Cookie missing flags: {', '.join(missing)}",
                    "evidence": cookie[:100]
                })
    return findings

def check_tls_cert(url: str) -> List[Dict]:
    """Check TLS certificate (basic - no full chain)."""
    findings = []
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as sock:
            sock.settimeout(10)
            sock.connect((host, port))
            cert = sock.getpeercert()
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (not_after - datetime.now(timezone.utc)).days
            if days_left < 30:
                findings.append({
                    "type": "tls_expiry",
                    "severity": "high" if days_left < 7 else "medium",
                    "description": f"TLS certificate expires in {days_left} days",
                    "evidence": f"Not after: {cert['notAfter']}"
                })
            # Check SANs
            sans = []
            for ext in cert.get("subjectAltName", []):
                if ext[0] == "DNS":
                    sans.append(ext[1])
            if len(sans) == 1 and sans[0] == host:
                findings.append({
                    "type": "tls_single_san",
                    "severity": "low",
                    "description": "Certificate only covers single domain (no www/subdomain SANs)",
                    "evidence": f"SANs: {sans}"
                })
    except Exception as e:
        findings.append({
            "type": "tls_check_failed",
            "severity": "info",
            "description": f"Could not verify TLS certificate: {e}",
            "evidence": str(e)
        })
    return findings

def fingerprint_tech(html: str, headers: httpx.Headers) -> List[str]:
    """Detect technologies from HTML and headers."""
    detected = []
    content = html.lower()
    header_str = str(headers).lower()
    for tech, patterns in TECH_FINGERPRINTS.items():
        for pattern in patterns:
            if pattern.lower() in content or pattern.lower() in header_str:
                detected.append(tech)
                break
    return list(set(detected))

async def probe_sensitive_paths(client: httpx.AsyncClient, base_url: str) -> List[Dict]:
    """Quick probe for sensitive files (HEAD requests)."""
    findings = []
    semaphore = asyncio.Semaphore(CONCURRENCY)
    
    async def probe(path: str):
        async with semaphore:
            try:
                url = urllib.parse.urljoin(base_url, path)
                resp = await client.head(url, timeout=5, follow_redirects=True)
                if resp.status_code == 200:
                    return {
                        "type": "sensitive_path",
                        "path": path,
                        "severity": "high" if path in ["/.git/", "/.env", "/backup.zip", "/.htaccess"] else "medium",
                        "description": f"Accessible sensitive path: {path}",
                        "evidence": f"HTTP 200 at {url}"
                    }
            except Exception:
                pass
        return None
    
    tasks = [probe(p) for p in SENSITIVE_PATHS]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]

async def scan_url(client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
    """Comprehensive scan of a single URL."""
    result = {
        "url": url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "status": None,
        "redirect_chain": [],
        "final_url": url,
        "technologies": [],
        "findings": [],
        "response_time_ms": 0,
        "error": None
    }
    
    start = asyncio.get_event_loop().time()
    try:
        # Follow redirects
        responses = await fetch_with_redirects(client, url)
        if not responses:
            result["error"] = "No response"
            return result
        
        final_resp = responses[-1]
        result["status"] = final_resp.status_code
        result["final_url"] = str(final_resp.url)
        result["redirect_chain"] = [
            {"url": str(r.url), "status": r.status_code} for r in responses
        ]
        result["response_time_ms"] = int((asyncio.get_event_loop().time() - start) * 1000)
        
        # Read body for analysis
        html = final_resp.text
        
        # Technology fingerprinting
        result["technologies"] = fingerprint_tech(html, final_resp.headers)
        
        # Security header checks
        result["findings"].extend(check_security_headers(final_resp.headers))
        
        # Cookie checks
        result["findings"].extend(check_cookies(final_resp.headers))
        
        # TLS certificate
        if url.startswith("https://"):
            result["findings"].extend(check_tls_cert(url))
        
        # Sensitive paths (only on base domain)
        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}/"
        result["findings"].extend(await probe_sensitive_paths(client, base))
        
        # HTML analysis
        soup = BeautifulSoup(html, "lxml")
        
        # Forms without CSRF
        for form in soup.find_all("form"):
            if form.get("method", "").lower() == "post":
                has_csrf = form.find("input", {"name": re.compile(r"csrf|token|nonce", re.I)})
                if not has_csrf:
                    result["findings"].append({
                        "type": "missing_csrf",
                        "severity": "medium",
                        "description": "POST form without apparent CSRF token",
                        "evidence": f"Form action: {form.get('action', 'current page')}"
                    })
        
        # Insecure forms (HTTP on HTTPS page)
        if url.startswith("https://"):
            for form in soup.find_all("form"):
                action = form.get("action", "")
                if action.startswith("http://"):
                    result["findings"].append({
                        "type": "mixed_content_form",
                        "severity": "high",
                        "description": "HTTPS page submits to HTTP endpoint",
                        "evidence": f"Form action: {action}"
                    })
        
        # External scripts without integrity
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if src.startswith("http") and not script.get("integrity"):
                result["findings"].append({
                    "type": "script_no_integrity",
                    "severity": "low",
                    "description": "External script without Subresource Integrity",
                    "evidence": src[:100]
                })
        
        # Version disclosure in headers
        server = final_resp.headers.get("server", "")
        x_powered = final_resp.headers.get("x-powered-by", "")
        if server and ("apache" in server.lower() or "nginx" in server.lower()):
            # Check for version disclosure
            if re.search(r"\d+\.\d+", server):
                result["findings"].append({
                    "type": "version_disclosure",
                    "severity": "low",
                    "description": "Server header discloses version",
                    "evidence": server
                })
        if x_powered:
            result["findings"].append({
                "type": "x_powered_by",
                "severity": "low",
                "description": "X-Powered-By header exposes technology",
                "evidence": x_powered
            })
        
    except httpx.TimeoutException:
        result["error"] = "Timeout"
    except httpx.TooManyRedirects:
        result["error"] = "Too many redirects"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    
    return result

# ─── Playwright-based SPA/JS scanning ───
async def scan_with_playwright(url: str) -> Dict[str, Any]:
    """Deep scan using Playwright for JS-rendered content."""
    if not USE_PLAYWRIGHT:
        return {"error": "Playwright not enabled (set USE_PLAYWRIGHT=true)"}
    
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {"error": "Playwright not installed"}
    
    result = {
        "url": url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "status": None,
        "technologies": [],
        "findings": [],
        "console_errors": [],
        "network_requests": [],
        "error": None
    }
    
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent=USER_AGENT,
                ignore_https_errors=True
            )
            page = await context.new_page()
            
            # Capture console errors
            page.on("console", lambda msg: result["console_errors"].append({
                "type": msg.type,
                "text": msg.text,
                "location": msg.location
            }) if msg.type in ("error", "warning") else None)
            
            # Capture network requests
            page.on("response", lambda resp: result["network_requests"].append({
                "url": resp.url,
                "status": resp.status,
                "headers": dict(resp.headers)
            }) if resp.status >= 400 else None)
            
            # Navigate
            response = await page.goto(url, wait_until="networkidle", timeout=30000)
            if response:
                result["status"] = response.status
            
            # Wait for dynamic content
            await page.wait_for_timeout(3000)
            
            # Get rendered HTML
            html = await page.content()
            
            # Technology detection on rendered content
            result["technologies"] = fingerprint_tech(html, {})
            
            # Check for client-side vulnerabilities
            # 1. DOM XSS sinks
            sinks = await page.evaluate("""() => {
                const sinks = [];
                const dangerous = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'document.writeln', 'eval', 'setTimeout', 'setInterval', 'Function'];
                document.querySelectorAll('*').forEach(el => {
                    dangerous.forEach(prop => {
                        if (el[prop] !== undefined) {
                            sinks.push({element: el.tagName, sink: prop, html: el.outerHTML.slice(0,200)});
                        }
                    });
                });
                return sinks;
            }""")
            for sink in sinks:
                result["findings"].append({
                    "type": "dom_xss_sink",
                    "severity": "medium",
                    "description": f"Potential DOM XSS sink: {sink['sink']} on {sink['element']}",
                    "evidence": sink['html']
                })
            
            # 2. Forms in rendered DOM
            forms = await page.evaluate("""() => {
                return Array.from(document.forms).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.elements).map(e => ({name: e.name, type: e.type, required: e.required}))
                }));
            }""")
            for form in forms:
                if form["method"].toLowerCase() == "post":
                    has_csrf = any("csrf" in i["name"].lower() or "token" in i["name"].lower() or "nonce" in i["name"].lower() for i in form["inputs"])
                    if not has_csrf:
                        result["findings"].append({
                            "type": "missing_csrf",
                            "severity": "medium",
                            "description": "POST form without apparent CSRF token (rendered DOM)",
                            "evidence": f"Action: {form['action']}, Inputs: {len(form['inputs'])}"
                        })
            
            # 3. Mixed content in rendered page
            mixed = await page.evaluate("""() => {
                const mixed = [];
                document.querySelectorAll('img, script, link[rel=stylesheet], iframe, video, audio, source').forEach(el => {
                    const src = el.src || el.href;
                    if (src && src.startsWith('http://') && window.location.protocol === 'https:') {
                        mixed.push({tag: el.tagName, src: src});
                    }
                });
                return mixed;
            }""")
            for m in mixed:
                result["findings"].append({
                    "type": "mixed_content",
                    "severity": "high",
                    "description": f"Mixed content: {m['tag']} loads HTTP resource on HTTPS page",
                    "evidence": m['src']
                })
            
            await browser.close()
            
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    
    return result

async def main():
    targets_env = os.getenv("WEB_SCAN_TARGETS", "")
    deep_scan = os.getenv("DEEP_SCAN", "false").lower() == "true"
    if not targets_env:
        print("No WEB_SCAN_TARGETS env var set")
        return
    
    targets = [t.strip() for t in targets_env.split(",") if t.strip()]
    if not targets:
        print("No valid targets")
        return
    
    print(f"Scanning {len(targets)} targets... (deep_scan={deep_scan})")
    
    # Fast scan with httpx
    limits = httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY)
    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        limits=limits,
        verify=True
    ) as client:
        semaphore = asyncio.Semaphore(CONCURRENCY)
        
        async def bounded_scan(url):
            async with semaphore:
                return await scan_url(client, url)
        
        results = await asyncio.gather(*[bounded_scan(t) for t in targets])
    
    # Deep scan with Playwright (if enabled)
    if deep_scan and USE_PLAYWRIGHT:
        print(f"Running deep Playwright scans on {len(targets)} targets...")
        pw_results = []
        for t in targets:
            pw_result = await scan_with_playwright(t)
            pw_results.append(pw_result)
        
        # Merge Playwright findings into main results
        for i, pw in enumerate(pw_results):
            if i < len(results) and "findings" in pw:
                results[i]["findings"].extend(pw["findings"])
                results[i]["console_errors"] = pw.get("console_errors", [])
                results[i]["network_errors"] = pw.get("network_requests", [])
                # Merge technologies
                results[i]["technologies"] = list(set(results[i].get("technologies", []) + pw.get("technologies", [])))
    
    # Summary
    summary = {
        "scan_id": f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "targets": targets,
        "deep_scan": deep_scan,
        "total_findings": sum(len(r.get("findings", [])) for r in results),
        "by_severity": {
            "critical": sum(1 for r in results for f in r.get("findings", []) if f.get("severity") == "critical"),
            "high": sum(1 for r in results for f in r.get("findings", []) if f.get("severity") == "high"),
            "medium": sum(1 for r in results for f in r.get("findings", []) if f.get("severity") == "medium"),
            "low": sum(1 for r in results for f in r.get("findings", []) if f.get("severity") == "low"),
            "info": sum(1 for r in results for f in r.get("findings", []) if f.get("severity") == "info"),
        },
        "results": results
    }
    
    # Output for GitHub Actions
    print(json.dumps(summary, indent=2))
    
    # Also write to file for artifact
    os.makedirs("data", exist_ok=True)
    with open("data/web_scan_latest.json", "w") as f:
        json.dump(summary, f, indent=2)

if __name__ == "__main__":
    import socket  # for TLS check
    asyncio.run(main())