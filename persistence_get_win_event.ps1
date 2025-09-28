$filepath = Join-Path -Path $env:SystemDrive -ChildPath "persistence_check.txt"
$ErrorActionPreference= 'SilentlyContinue'
$startDate1 = Read-Host "Enter date of first sign of compromise (e.g. October 21, 2024 00:13:30). If no value is entered, will collect all logs."
if (-not $startDate1 ) {
        $startDate = Get-Date 'January 01, 1970 00:00:00'
} else {
$startDate = Get-Date $startDate1
}

$now = Get-Date
if ($startDate -gt $now) {
Write-Host 'Enter Valid Date!'
Exit
}


$separator = "`n================== Oldest Logs ==================`n"
$separator | Out-File $filepath -Append
Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -MaxEvents 1 -Oldest  | Select-Object ProviderName, TimeCreated | fl | Out-File -Append $filepath 
Get-WinEvent -ProviderName 'Microsoft-Windows-TaskScheduler' -MaxEvents 1 -Oldest  | Select-Object ProviderName, TimeCreated | fl | Out-File -Append $filepath
Get-WinEvent -LogName 'System' -MaxEvents 1 -Oldest | fl | Out-File -Append $filepath

$separator = "`n================== Checking if logs were cleared ==================`n"
$separator | Out-File $filepath -Append
Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -FilterXPath "*[System[EventID=1102]]" |  Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No 1102 events found" | Out-File $filepath -Append }
Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -FilterXPath "*[System[EventID=1100]]" |  Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No 1100 events found" | Out-File $filepath -Append }

$separator = "`n================== SCHEDULED TASKS ==================`n"
$separator | Out-File $filepath -Append
Get-WinEvent -ProviderName 'Microsoft-Windows-TaskScheduler' -FilterXPath "*[System[EventID=106]]"| Where-Object {$_.Timecreated -ge $startDate } |  Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No Task Scheduler provider events found" | Out-File $filepath -Append }
Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -FilterXPath "*[System[EventID=4698]]" | Where-Object {$_.Timecreated -ge $startDate } | Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No 4698 security events found" | Out-File $filepath -Append }

$separator = "`n================== USER CREATION ==================`n"
$separator | Out-File $filepath -Append
Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -FilterXPath "*[System[EventID=4720]]" | Where-Object {$_.Timecreated -ge $startDate } | Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No User creation events found" | Out-File $filepath -Append }

$separator = "`n================== USER UNLOCKS ==================`n"
$separator | Out-File $filepath -Append
Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -FilterXPath "*[System[EventID=4767]]" | Where-Object {$_.Timecreated -ge $startDate } |  Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No user unlock events found" | Out-File $filepath -Append }

$separator = "`n================== SERVICE CREATION ==================`n"
$separator | Out-File $filepath -Append
Get-WinEvent -LogName 'System' -FilterXPath "*[System[EventID=7045]]" | Where-Object {$_.Timecreated -ge $startDate } |  Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No system events found" | Out-File $filepath -Append }
Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -FilterXPath "*[System[EventID=4697]]" | Where-Object {$_.Timecreated -ge $startDate } |  Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No 4697 security events found" | Out-File $filepath -Append }

$separator = "`n================== GROUP MANIPULATION ==================`n"
$separator | Out-File $filepath -Append
Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -FilterXPath "*[System[EventID=4732]]" | Where-Object {$_.Timecreated -ge $startDate } |  Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No 4732 security events found" | Out-File $filepath -Append }
Get-WinEvent -ProviderName 'Microsoft-Windows-Security-Auditing' -FilterXPath "*[System[EventID=4728]]" | Where-Object {$_.Timecreated -ge $startDate } |  Format-List | Out-File -Append $filepath
if ($? -eq $false) { "No 4728 security events found" | Out-File $filepath -Append }

$separator = "`n================== WMI BINDS ==================`n"
$separator | Out-File $filepath -Append
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Out-File -Append $filepath
if ($? -eq $false) { "No wmi bind events found" | Out-File $filepath -Append }