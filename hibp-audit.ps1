param (
    $domain         = $(Get-ADDomain | Select-Object -ExpandProperty name),
    # Get the link for the HIBP hash file at https://haveibeenpwned.com/Passwords
    $hibpurl        = "https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ntlm-ordered-by-hash-v4.7z",
    $eventsource    = "HIBP-Audit",
    $workingdir     = "C:\hibp-audit"
)

$requiredmodules = @("DSInternals", "ActiveDirectory")

$downloaddir = "$($workingdir)\download"
$outputdir   = "$($workingdir)\output"
$outputfile  = "$($outputdir)\compromised-accounts-$domain.txt"
$hibpfile    = "$($workingdir)\download\pwned-passwords-ntlm-ordered-by-hash.7z"

$namingcontext  = $(Get-ADDomain $domain -ErrorAction Stop | Select-Object -ExpandProperty DistinguishedName)
$server         = $(Get-ADDomainController -Discover -Domain $domain -ErrorAction Stop | Select-Object -ExpandProperty Hostname)

function Get-FileFromURL {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [System.Uri]$URL,
        [Parameter(Mandatory, Position = 1)]
        [string]$Filename
    )

    process {
        try {
            $request = [System.Net.HttpWebRequest]::Create($URL)
            $request.set_Timeout(5000) # 5 second timeout
            $request.IfModifiedSince = ([System.IO.FileInfo]$Filename).LastWriteTime
            try {
                $response = $request.GetResponse()
            } catch [System.Net.WebException] {
		        # Check for a 304, indicating we have the latest version
		        if ($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotModified) {
			        Write-Host "  $Filename not modified, not downloading..."
                    return
		        } else {
			        #Unexpected error
			        $Status = $_.Exception.Response.StatusCode
			        $msg = $_.Exception
			        Write-Host "  Error dowloading $URL, Status code: $Status - $msg"
                    exit 1
		        }
	        }
            $total_bytes = $response.ContentLength
            $response_stream = $response.GetResponseStream()

            try {
                # 256KB works better on my machine for 1GB and 10GB files
                # See https://www.microsoft.com/en-us/research/wp-content/uploads/2004/12/tr-2004-136.pdf
                # Cf. https://stackoverflow.com/a/3034155/10504393
                $buffer = New-Object -TypeName byte[] -ArgumentList 256KB
                $target_stream = [System.IO.File]::Create($Filename)

                $timer = New-Object -TypeName timers.timer
                $timer.Interval = 1000 # Update progress every second
                $timer_event = Register-ObjectEvent -InputObject $timer -EventName Elapsed -Action {
                    $Global:update_progress = $true
                }
                $timer.Start()

                do {
                    $count = $response_stream.Read($buffer, 0, $buffer.length)
                    $target_stream.Write($buffer, 0, $count)
                    $downloaded_bytes = $downloaded_bytes + $count

                    if ($Global:update_progress) {
                        $percent = $downloaded_bytes / $total_bytes
                        $status = @{
                            completed  = "{0,6:p2} Completed" -f $percent
                            downloaded = "{0:n0} MB of {1:n0} MB" -f ($downloaded_bytes / 1MB), ($total_bytes / 1MB)
                            speed      = "{0,7:n0} KB/s" -f (($downloaded_bytes - $prev_downloaded_bytes) / 1KB)
                            eta        = "eta {0:hh\:mm\:ss}" -f (New-TimeSpan -Seconds (($total_bytes - $downloaded_bytes) / ($downloaded_bytes - $prev_downloaded_bytes)))
                        }
                        $progress_args = @{
                            Activity        = "Downloading $URL"
                            Status          = "$($status.completed) ($($status.downloaded)) $($status.speed) $($status.eta)"
                            PercentComplete = $percent * 100
                        }
                        Write-Progress @progress_args

                        $prev_downloaded_bytes = $downloaded_bytes
                        $Global:update_progress = $false
                    }
                } while ($count -gt 0)
            } finally {
                if ($timer) { $timer.Stop() }
                if ($timer_event) { Unregister-Event -SubscriptionId $timer_event.Id }
                if ($target_stream) { $target_stream.Dispose() }
                # If file exists and $count is not zero or $null, than script was interrupted by user
                if ((Test-Path $Filename) -and $count) { 
                    Remove-Item -Path $Filename 
                    $Filename = $false
                }
            }
        } finally {
            if ($response) { $response.Dispose() }
            if ($response_stream) { $response_stream.Dispose() }
        }
        return $Filename
    }
}

# See if our event log source exists
try {
    $sourceexists = [System.Diagnostics.EventLog]::SourceExists($eventsource)
} catch [System.Security.SecurityException] {

} finally {
    if (!($sourceexists)) {
        Write-Host "The $eventsource source doesn't exist yet.  Please run the following in an elevated powershell:"
        Write-Host "New-EventLog -LogName Application -Source `"$eventsource`""
        exit 1
    }
}

# Check our modules
foreach ($module in $requiredmodules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Host "$module module not installed.  Run `"Install-Module $module`" as an administrator."
        exit 1
    }
}


# Set up our directories
foreach ($d in $workingdir, $downloaddir, $outputdir) {
    If (!(Test-Path $d)) {
        [void](New-Item -ItemType Directory -Force -Path $d)
    } 
}

# Download compressed HIBP if needed
Write-Host "Starting transfer of HIBP hashes, this could take some time."
$new = Get-FileFromURL $hibpurl $hibpfile
if ($new) {
    Write-Host "Done transfering hashes."
    # Remove everything from the download directory except for the original 7z file
    Remove-Item $downloaddir -Exclude *.7z
} else {
    Write-Host "Previously downloaded file is up to date."
}

# See if 7zip is installed
If (!(Test-Path "$env:ProgramFiles\7-Zip\7z.exe")) {
    Write-Host "7zip not found.  Please install it and re-run this script."
    exit 1
}

if (!(Test-Path "$downloaddir\pwned-passwords-ntlm-ordered-by-hash-*.txt" )) {
    # Unzip our file
    $unzipcommand = '"$env:ProgramFiles\7-Zip\7z.exe" x -o"$downloaddir" "$hibpfile" -r'
    Invoke-Expression "& $unzipcommand" -ErrorAction Stop
}
$hashes = Get-ChildItem $downloaddir\*.txt -ErrorAction Stop

try {
    $results = Get-ADReplAccount -All -Server $server -NamingContext "$namingcontext" -ErrorAction Stop | 
       Test-PasswordQuality -WeakPasswordHashesSortedFile $hashes -IncludeDisabledAccounts
    $results  > $outputfile
} catch [System.UnauthorizedAccessException] {
    Write-Host "Get-ADReplAccount failed, you probably don't have the `"Replicating Directory Changes All`" right."
    exit 1
} catch {
    Write-Host "An unexpected error occurred."
    exit 1
}


# Log vulnerable users
$compromisedcount = $results | Select-Object -ExpandProperty WeakPassword | Measure-Object

Write-Host "HIBP Audit completed.  Please see $outputfile for results."
Write-EventLog -LogName Application -Source $eventsource -EntryType Information -EventId 1 -Message "HIBP Audit script completed successfully against the domain $domain."
if ($compromisedcount.count -gt 0) {
    Write-EventLog -LogName Application -Source $eventsource -EntryType Information -EventId 2 -Message "HIBP Audit found $($compromisedcount.count) compromised accounts in the $domain domain."
    Write-Host "HIBP Audit found $($compromisedcount.count) compromised accounts in the $domain domain."
}
