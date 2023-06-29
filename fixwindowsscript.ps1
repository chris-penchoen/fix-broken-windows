$ErrorActionPreference = "Stop"
$storageBlobUrl = #redacted
$outputDir = Join-Path $env:USERPROFILE "Downloads"
$wimFileName = "install.wim"
$wimFilePath = Join-Path $outputDir $wimFileName
$hashAlgorithm = "SHA256"
$expectedHash = "58C471F77EA3356B984FDAD68DAA07771490B4C8A9E8A05ECC14F16327651664"
$hashValue = $hashResult.Hash
$appsToAdd = @(
    # List of apps to install
)

$logDirectory = Join-Path $env:APPDATA "fixWindowsInstall"
$logFile = Join-Path $logDirectory "error.log"
$verboseLogFile = Join-Path $logDirectory "verbose.log"

try {
    # Create log directory if it doesn't exist
    if (-not (Test-Path $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory | Out-Null
    }

    # Function to log errors to the file
    function Write-ErrorLog {
        param([string]$ErrorMessage)
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogEntry = "[$Timestamp] ERROR: $ErrorMessage"
        Add-Content -Path $logFile -Value $LogEntry
    }

    # Function to log verbose messages to the file
    function Write-VerboseLog {
        param([string]$Message)
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogEntry = "[$Timestamp] VERBOSE: $Message"
        Add-Content -Path $verboseLogFile -Value $LogEntry
    }

    # Create the output directory if it doesn't exist
    if (!(Test-Path -Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }

    # Check if the WIM file already exists
if (Test-Path $wimFilePath -PathType Leaf) {
    Write-Output "Skipping download. WIM file already exists."
} else {
    # Download the WIM file
    Import-Module BitsTransfer
    Write-Host "Downloading the WIM file..."
    Write-VerboseLog "Downloading the WIM file..."
    Start-BitsTransfer -Source $storageBlobUrl -Destination $wimFilePath
    Write-Output "Download completed."
}

# Verify downloaded file hash
function Compare-FileHash {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash,

        [string]$HashAlgorithm = "SHA256"
    )

    # Check if the specified file exists
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        Write-Error "The file '$FilePath' does not exist."
        return
    }

    # Get the hash algorithm provider
    try {
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($HashAlgorithm)
    } catch {
        Write-Error "Invalid hash algorithm: $HashAlgorithm"
        return
    }

    # Calculate the hash of the file
    try {
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $fileHash = $hasher.ComputeHash($fileStream)
    } catch {
        Write-Error "Failed to calculate the hash of the file: $_"
        return
    } finally {
        $fileStream.Dispose()
    }

    # Convert the byte array to a hexadecimal string
    $computedHash = [System.BitConverter]::ToString($fileHash) -replace "-", ""

    # Compare the computed hash with the expected hash
    if ($computedHash -eq $expectedHash) {
        Write-Host "Hash verification succeeded. The file hash matches the expected hash."
    } else {
        Write-Host "Hash verification failed. The file hash does not match the expected hash."
        Write-Host "Expected hash: $expectedHash"
        Write-Host "Computed hash: $computedHash"

        # Remove the downloaded file and retry the download
        Write-Host "Redownloading the WIM file..."
        Remove-Item -Path $wimFilePath -Force
        $continue = $false
        $retryCount = 0
        Write-Output "Download completed."
    }
}

       
    # Remove deprovisioned apps from registry
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\DeprovisionedApps"

if (Test-Path $registryPath) {
    Write-Host "Removing registry items..."
    Write-VerboseLog "Removing registry items..."
    Remove-Item -Path $registryPath -Recurse -Force
} else {
    Write-Host "Registry path does not exist. Skipping removal of deprovisioned apps from registry."
}


    # Create the directory C:\%currentuser%\Temp if it doesn't exist
$currentUserTempPath = Join-Path $env:USERPROFILE "Temp"
if (-not (Test-Path $currentUserTempPath)) {
    New-Item -Path $currentUserTempPath -ItemType Directory | Out-Null
}

    # Mount the WIM
$mountPath = $currentUserTempPath
$imagePath = $wimFilePath
$imageIndex = 1
dism.exe /Mount-Wim /WimFile:$imagePath /Index:$imageIndex /MountDir:$mountPath /ReadOnly


    # Install Microsoft Store
Write-Host "Installing the Microsoft Store app..."
Write-VerboseLog "Installing the Microsoft Store app..."
$storeAppFolder = Get-ChildItem "$mountPath\Program Files\WindowsApps" -Filter Microsoft.WindowsStore* -Directory | Sort-Object -Property Name -Descending | Select-Object -First 1

if ($storeAppFolder) {
    $manifestPath = Join-Path $storeAppFolder.FullName "AppxManifest.xml"
    
    try {
        Add-AppxPackage -Path $manifestPath -ErrorAction Stop
        Write-Output "Microsoft Store app installed successfully."
    } catch {
        Write-Output "Failed to install the Microsoft Store app."
        Write-Output "Error: $_"
    }
} else {
    Write-Output "Failed to find the Microsoft Store app folder."
}


    # Install remaining apps
    foreach ($app in $appsToAdd) {
        $appFolder = (Get-ChildItem "$mountPath\Program Files\WindowsApps" -Filter $app* -Directory | Sort-Object -Property Name -Descending | Select-Object -First 1).FullName
        $manifestPath = "$appFolder\AppxManifest.xml"

        if (Test-Path $manifestPath) {
            Write-Host "Installing $app..."
            Write-VerboseLog "Installing $app..."
            Add-AppxPackage -Path $manifestPath -ErrorAction Stop
        }
        else {
            Write-Host "Cannot find the manifest for $app. Attempting to install from the Microsoft Store for all users..."
            Write-VerboseLog "Cannot find the manifest for $app. Attempting to install from the Microsoft Store for all users..."
            Add-AppxPackage -AllUsers -Online -Name $app -ErrorAction SilentlyContinue
        }
    }

    # Unmount the WIM
    Write-Host "Unmounting the WIM..."
    Write-VerboseLog "Unmounting the WIM..."
    DISM /Unmount-Wim /MountDir:$mountPath /Discard

    Write-Host "Script execution completed successfully."
    Write-VerboseLog "Script execution completed successfully."
}
catch {
    $errorMessage = $_.Exception.Message
    Write-ErrorLog -ErrorMessage $errorMessage
    Write-Host "An error occurred: $errorMessage"
    exit 1
}

# Need to add function to delete the WIM once script is done
