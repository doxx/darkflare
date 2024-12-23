# Memory execution of DarkFlare client
# Usage: .\memory-exec.ps1 -t cdn.example.com -d localhost:22

param (
    [Parameter(Mandatory=$true)]
    [string]$t,
    
    [Parameter(Mandatory=$true)]
    [string]$d,
    
    [Parameter(Mandatory=$false)]
    [string]$l = "stdin:stdout",
    
    [Parameter(Mandatory=$false)]
    [string]$p
)

$url = "https://github.com/doxx/darkflare/releases/latest/download/darkflare-client-windows-amd64.exe"

# Download binary into memory
$webClient = New-Object System.Net.WebClient
$bytes = $webClient.DownloadData($url)

# Create arguments array
$args = @("-l", $l, "-t", $t, "-d", $d)
if ($p) { $args += @("-p", $p) }

# Execute in memory
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entryPoint = $assembly.EntryPoint
$entryPoint.Invoke($null, @(,[string[]]$args))