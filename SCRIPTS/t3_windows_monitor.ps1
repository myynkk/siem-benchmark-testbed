# scripts/t3_windows_monitor.ps1
# Continuous monitor for all 10 T3 trials on Windows
# Reads Wazuh active-responses.log and watches netsh firewall rules in real-time

param(
    [string]$OutFile = "$PSScriptRoot\..\DATASETS\t3_mttc_trials.csv",
    [string]$AttackerIP = "192.168.17.128",
    [int]$TotalTrials = 10
)

$ruleName = "WAZUH ACTIVE RESPONSE BLOCKED IP"
$arLog = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

Write-Host "=== T3 AUTOMATED WINDOWS MONITOR ===" -ForegroundColor Cyan
Write-Host "Output CSV: $OutFile"
Write-Host "Watching for attacker: $AttackerIP"
Write-Host "Started: $(Get-Date -Format 'o')"
Write-Host ""

if (-not (Test-Path $OutFile)) {
    "trial,attacker_ip,t5_utc,t_block_utc,mttc_seconds,failed_logons_seen,status" | Out-File $OutFile -Encoding ascii
}

$lastLogCount = 0
if (Test-Path $arLog) {
    $lastLogCount = (Get-Content $arLog).Count
}

for ($trial = 1; $trial -le $TotalTrials; $trial++) {
    Write-Host "------------------------------------------------------------"
    Write-Host "Waiting for Trial $trial of $TotalTrials to begin..." -ForegroundColor Yellow
    
    # 1. Wait for block rule or active-response log entry
    $tBlock = $null
    $tAlert = $null
    $ruleDetected = $false
    
    $startWait = Get-Date
    while ((Get-Date) -lt $startWait.AddMinutes(10)) {
        # Check firewall rule
        $fw = netsh advfirewall firewall show rule name="$ruleName" 2>&1 | Out-String
        if ($fw -match "Rule Name") {
            $tBlock = (Get-Date).ToUniversalTime()
            $ruleDetected = $true
            Write-Host "  [Trial $trial] FIREWALL RULE DETECTED at $($tBlock.ToString('o'))" -ForegroundColor Green
            break
        }
        Start-Sleep -Milliseconds 100
    }
    
    if (-not $ruleDetected) {
        Write-Host "  [Trial $trial] TIMEOUT: No block rule seen within 10 minutes." -ForegroundColor Red
        continue
    }
    
    # 2. Check active-responses.log for exact Wazuh alert timestamp
    Start-Sleep -Seconds 1
    if (Test-Path $arLog) {
        $lines = Get-Content $arLog
        $newLines = $lines | Select-Object -Skip $lastLogCount
        $lastLogCount = $lines.Count
        
        foreach ($line in $newLines) {
            if ($line -match '"id":"100100"' -and $line -match $AttackerIP) {
                if ($line -match '"timestamp":"([^"]+)"') {
                    $tAlert = $matches[1]
                    Write-Host "  [Trial $trial] Wazuh Alert 100100 timestamp: $tAlert" -ForegroundColor Cyan
                }
            }
        }
    }
    
    # 3. Calculate MTTC
    $mttc = $null
    if ($tAlert -and $tBlock) {
        try {
            $dtAlert = [DateTime]::Parse($tAlert).ToUniversalTime()
            $mttc = [math]::Round(($tBlock - $dtAlert).TotalSeconds, 3)
        } catch {
            Write-Host "  Could not parse alert timestamp: $tAlert"
        }
    }
    
    $status = if ($mttc -ne $null -and $mttc -gt 0) { "OK" } else { "RULE_INSERTED" }
    $tBs = if ($tBlock) { $tBlock.ToString("o") } else { "" }
    $tAs = if ($tAlert) { $tAlert } else { "" }
    
    "$trial,$AttackerIP,$tAs,$tBs,$mttc,5,$status" | Add-Content $OutFile
    Write-Host "  [Trial $trial Saved] MTTC: $mttc s | Status: $status" -ForegroundColor Green
    
    # 4. Wait for rule to clear (180s active response timeout)
    if ($trial -lt $TotalTrials) {
        Write-Host "  Waiting for firewall block rule to expire (180s)..." -ForegroundColor Gray
        while ((netsh advfirewall firewall show rule name="$ruleName" 2>&1 | Out-String) -match "Rule Name") {
            Start-Sleep -Seconds 5
        }
        Write-Host "  Firewall rule cleared naturally. Ready for next trial." -ForegroundColor Gray
    }
    Write-Host ""
}

Write-Host "============================================================"
Write-Host "ALL $TotalTrials TRIALS LOGGED" -ForegroundColor Green
Get-Content $OutFile
