$data = Get-Content 'wordlists\sqli.json' -Raw | ConvertFrom-Json
Write-Host "=== TONG KET ===" -ForegroundColor Cyan
Write-Host "Total matches: $($data.Count)"
Write-Host ""

Write-Host "=== PHAN LOAI THEO STATUS CODE ===" -ForegroundColor Yellow
$data | Group-Object StatusCode | ForEach-Object {
    Write-Host "  HTTP $($_.Name): $($_.Count) requests"
}
Write-Host ""

Write-Host "=== PHAN LOAI THEO KICH THUOC RESPONSE ===" -ForegroundColor Yellow
$data | Group-Object {
    if ($_.ContentLength -le 35)       { "tiny  (<=35 bytes)  = Empty/Error" }
    elseif ($_.ContentLength -le 200)  { "small (36-200)      = Short error msg" }
    elseif ($_.ContentLength -le 1000) { "medium(201-1000)    = Partial data" }
    else                                { "large (>1000 bytes) = Full SQLi dump" }
} | ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" }
Write-Host ""

Write-Host "=== TOP 5 PAYLOADS LON NHAT (SQLi Successful) ===" -ForegroundColor Green
$data | Sort-Object ContentLength -Descending | Select-Object -First 5 | ForEach-Object {
    Write-Host "  [$($_.StatusCode)] Size=$($_.ContentLength) | $($_.Word)"
}
Write-Host ""

Write-Host "=== TOP 5 PAYLOADS STATUS 500 (Error-based SQLi) ===" -ForegroundColor Red
$data | Where-Object { $_.StatusCode -eq 500 } | Select-Object -First 5 | ForEach-Object {
    Write-Host "  Size=$($_.ContentLength) | $($_.Word)"
    if ($_.ResponseBody) {
        Write-Host "    Body: $($_.ResponseBody.Substring(0, [Math]::Min(120, $_.ResponseBody.Length)))..."
    }
}
