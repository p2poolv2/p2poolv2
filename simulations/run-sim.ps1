# simulations/run-sim.ps1
param (
    [string[]]$args = @()
)

$ns3Version = "3.44"
$ns3Dir = "$PSScriptRoot/ns-allinone-$ns3Version/ns-allinone-$ns3Version/ns-$ns3Version"
$ns3Url = "https://github.com/nsnam/ns-3-dev/releases/download/ns-$ns3Version/ns-allinone-$ns3Version.tar.bz2"
$ns3Archive = "ns-allinone-$ns3Version.tar.bz2"

# Download NS3 if not already present
if (-not (Test-Path $ns3Dir)) {
    Write-Host "Downloading NS3 $ns3Version..."
    Invoke-WebRequest -Uri $ns3Url -OutFile $ns3Archive
    Write-Host "Extracting NS3..."
    # Requires 7-Zip or similar for tar.bz2 extraction
    & "C:\Program Files\7-Zip\7z.exe" x $ns3Archive -o"$PSScriptRoot"
    & "C:\Program Files\7-Zip\7z.exe" x "ns-allinone-$ns3Version.tar" -o"$PSScriptRoot"
    Remove-Item $ns3Archive
    Remove-Item "ns-allinone-$ns3Version.tar"
}

# Copy simulation script to NS3 scratch directory
Copy-Item "$PSScriptRoot/p2pool-sim.cc" "$ns3Dir/scratch/"

# Build NS3 with CMake
cd "$ns3Dir"
if (-not (Test-Path "build")) {
    mkdir build
}
cd build
cmake .. -G "Visual Studio 16 2019" -A x64  # Adjust for your VS version
cmake --build .

# Run the simulation
cd "scratch/p2pool-sim"
Write-Host "Running simulation with args: $args"
.\p2pool-sim.exe $args