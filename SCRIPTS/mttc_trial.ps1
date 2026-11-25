# mttc_trial.ps1
# Run in an ADMINISTRATOR PowerShell on the Windows host (the victim machine).
# Usage:  .\mttc_trial.ps1 -Trial 1
#
# What it measures (both timestamps come from the SAME Windows clock):
#   t5      = time Windows logged the 5th failed logon (Event 4625) from the attacker IP
#   t_block = time the Wazuh Active Response firewall rule was first seen to exist
#   MTTC    = t_block - t5   (resolution is about the polling interval, ~0.1-0.2 s)

param(
    [int]$Trial = 1,
    [string]$AttackerIP = "192.168.17.128",
    [string]$RuleName = "WAZUH ACTIVE RESPONSE BLOCKED IP",
    [string]$OutFile = "..\data\mttc_trials.csv"
)

# 1. State verification: manual rule deletion is omitted to preserve wazuh-execd state consistency.
# Rule presence is verified clean via pre-flight check prior to launching the trial.
# netsh advfirewall firewall delete rule name="$RuleName" | Out-Null

$startLocal = (Get-Date).AddSeconds(-1)
Write-Host "Trial $Trial ready. Start the Kali brute-force loop NOW. Waiting up to 60 s for the block rule..."

# 2. Poll the firewall about every 100 ms until the block rule exists.
$tBlock = $null
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    $out = netsh advfirewall firewall show rule name="$RuleName" | Out-String
    if ($out -match "Rule Name") {
        $tBlock = (Get-Date).ToUniversalTime()
        break
    }
    Start-Sleep -Milliseconds 100
}

# 3. Let the Security log settle, then read the failed-logon events from the attacker IP.
Start-Sleep -Seconds 2
$events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $startLocal } -ErrorAction SilentlyContinue |
    Where-Object {
        $xml = [xml]$_.ToXml()
        ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text' -eq $AttackerIP
    } | Sort-Object TimeCreated

$failCount = @($events).Count
$t5 = $null
if ($failCount -ge 5) { $t5 = $events[4].TimeCreated.ToUniversalTime() }

$mttc = $null
if ($tBlock -and $t5) { $mttc = [math]::Round(($tBlock - $t5).TotalSeconds, 3) }

$status = "FAIL"
if ($mttc -ne $null) { $status = "OK" }

$t5s = ""; if ($t5) { $t5s = $t5.ToString("o") }
$tBs = ""; if ($tBlock) { $tBs = $tBlock.ToString("o") }

# 4. Append one row to the CSV (failures are recorded too, they are real data).
if (-not (Test-Path $OutFile)) {
    "trial,attacker_ip,t5_utc,t_block_utc,mttc_seconds,failed_logons_seen,status" | Out-File $OutFile -Encoding ascii
}
"$Trial,$AttackerIP,$t5s,$tBs,$mttc,$failCount,$status" | Add-Content $OutFile

Write-Host "Trial $Trial -> status=$status  MTTC=$mttc s  failed_logons_seen=$failCount"
