# Read-only diagnostics, compatible with Windows PowerShell 5.1 and PowerShell 7.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Write-Output '=== OS ==='
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime | Format-List
Write-Output '=== Disk ==='
Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
    Select-Object DeviceID, Size, FreeSpace | Format-Table -AutoSize
Write-Output '=== Network and DNS ==='
Get-NetIPConfiguration | Format-List InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer
Write-Output '=== Infrastructure services installed on this host ==='
Get-Service | Where-Object { $_.Name -match '^(Dnscache|Dhcp|LanmanServer|W32Time|MSSQL.*)$' } |
    Select-Object Name, Status, StartType | Format-Table -AutoSize
Write-Output '=== Listening TCP sockets ==='
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort | Sort-Object LocalPort | Format-Table -AutoSize
