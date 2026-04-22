
$e = (Get-Content 'wordlists\sqli_errors.json' -Raw | ConvertFrom-Json).results
$c = Get-Content 'wordlists\sqli.json' -Raw | ConvertFrom-Json

$e500  = $e | Where-Object { $_.status -eq 500 }
$e200  = $e | Where-Object { $_.status -eq 200 }
$c500  = $c | Where-Object { $_.StatusCode -eq 500 }
$cConf = $c | Where-Object { $_.Detection.Severity -eq 'Confirmed' }

Write-Host '=== TONG QUAN ===' -ForegroundColor Cyan
Write-Host "ffuf -mr regex   : $($e.Count) ket qua  [500: $($e500.Count) | 200: $($e200.Count)]"
Write-Host "WebFuzzer custom : $($c.Count) ket qua  [500: $($c500.Count) | CONFIRMED: $($cConf.Count)]"
Write-Host ''

$eMap = @{}; foreach ($r in $e) { $eMap[$r.input.FUZZ.Trim()] = $r }
$cMap = @{}; foreach ($r in $c) { $cMap[$r.Word.Trim()] = $r }

# ffuf 500 ma custom khong co
$miss = $e500 | Where-Object { -not $cMap.ContainsKey($_.input.FUZZ.Trim()) }
Write-Host "=== ffuf status 500 ma Custom THIEU: $($miss.Count) ===" -ForegroundColor Red
$miss | ForEach-Object { Write-Host "  $($_.input.FUZZ)" }
Write-Host ''

# ffuf 200 - false positive analysis
Write-Host '=== ffuf match 200 (phan tich FP) ===' -ForegroundColor Yellow
$e200 | ForEach-Object {
    $payload = $_.input.FUZZ
    $cEntry  = $cMap[$payload.Trim()]
    $score   = if ($cEntry) { $cEntry.Detection.Score } else { 'N/A' }
    $sev     = if ($cEntry) { $cEntry.Detection.Severity } else { 'NOT_IN_CUSTOM' }
    $size    = $_.length
    Write-Host "  [$($_.status) | $($size)B | Score=$score $sev] $payload"
}
Write-Host ''

# Custom 500 ma ffuf khong bắt
$extra = $c500 | Where-Object { -not $eMap.ContainsKey($_.Word.Trim()) }
Write-Host "=== Custom CONFIRMED 500 ma ffuf KHONG bắt: $($extra.Count) ===" -ForegroundColor Magenta
$extra | Select-Object -First 25 | ForEach-Object {
    Write-Host "  [Score:$($_.Detection.Score)] $($_.Word)"
}
if ($extra.Count -gt 25) { Write-Host "  ... va $($extra.Count - 25) payload khac" }
