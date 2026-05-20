# ===== Web Threat Intelligence — Go Online =====
# Run this script to share your website with friends

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "  WTI System - Going Online" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# ─── Step 1: Check requirements ───
$ngrokPath = "$env:USERPROFILE\ngrok\ngrok.exe"
if (!(Test-Path $ngrokPath)) {
    Write-Host "[!] ngrok not found. Downloading..." -ForegroundColor Yellow
    $url = "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip"
    $out = "$env:TEMP\ngrok.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
        Expand-Archive -Path $out -DestinationPath "$env:USERPROFILE\ngrok" -Force
        Remove-Item $out -Force
        Write-Host "[+] ngrok downloaded." -ForegroundColor Green
    } catch {
        Write-Host "[!] Download failed: $_" -ForegroundColor Red
        exit 1
    }
}

# ─── Step 2: Check ngrok auth ───
$ngrokConfig = "$env:LOCALAPPDATA\ngrok\ngrok.yml"
if (!(Test-Path $ngrokConfig)) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║   ACTION REQUIRED: ngrok Auth Token             ║" -ForegroundColor Yellow
    Write-Host "╠══════════════════════════════════════════════════╣" -ForegroundColor Yellow
    Write-Host "║  1. Go to https://dashboard.ngrok.com/signup    ║" -ForegroundColor White
    Write-Host "║     (Sign up free - no credit card)             ║" -ForegroundColor White
    Write-Host "║                                                ║" -ForegroundColor White
    Write-Host "║  2. After login, go to:                        ║" -ForegroundColor White
    Write-Host "║     https://dashboard.ngrok.com/get-started    ║" -ForegroundColor White
    Write-Host "║                                                ║" -ForegroundColor White
    Write-Host "║  3. Copy your Authtoken (looks like:           ║" -ForegroundColor White
    Write-Host "║     2xABCDEF1234567890abcdef1234567890)        ║" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    $token = Read-Host "Paste your ngrok authtoken here and press Enter"
    if ($token -and $token.Length -gt 10) {
        # Create config directory
        New-Item -ItemType Directory -Path "$env:LOCALAPPDATA\ngrok" -Force | Out-Null
        # Add auth token
        & $ngrokPath config add-authtoken $token 2>&1 | Out-Null
        Write-Host "[+] Auth token saved!" -ForegroundColor Green
    } else {
        Write-Host "[!] No token entered. Exiting." -ForegroundColor Red
        exit 1
    }
}

# ─── Step 3: Kill old instances ───
Get-Process -Name "python*" -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -eq "" } | Stop-Process -Force
Get-Process -Name "ngrok*" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

# ─── Step 4: Delete old DB (fresh start) ───
$dbPath = "$projectDir\instance\wti.db"
if (Test-Path $dbPath) { Remove-Item $dbPath -Force }

# ─── Step 5: Start Flask app ───
Write-Host "[+] Starting WTI System..." -ForegroundColor Cyan
$appJob = Start-Job -ScriptBlock {
    param($dir)
    Set-Location $dir
    python app.py
} -ArgumentList $projectDir

Start-Sleep -Seconds 5

# ─── Step 6: Start ngrok tunnel ───
Write-Host "[+] Creating public HTTPS tunnel..." -ForegroundColor Cyan
$ngJob = Start-Job -ScriptBlock {
    param($exe)
    & $exe http 5000 --log=stdout
} -ArgumentList $ngrokPath

Start-Sleep -Seconds 4

# ─── Step 7: Get the public URL ───
try {
    $api = Invoke-RestMethod -Uri "http://127.0.0.1:4040/api/tunnels" -UseBasicParsing
    $url = $api.tunnels[0].public_url
} catch {
    $url = "checking..."
}

Write-Host ""
Write-Host "=======================================" -ForegroundColor Green
Write-Host "  YOUR WEBSITE IS LIVE!" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Share this link with your friend:" -ForegroundColor White
Write-Host "  $url" -ForegroundColor Cyan -BackgroundColor Black
Write-Host ""
Write-Host "  Admin account: admin" -ForegroundColor White
Write-Host "  Admin password: (you set during registration)" -ForegroundColor White
Write-Host ""
Write-Host "  Your friend can:" -ForegroundColor White
Write-Host "  1. Open the link above" -ForegroundColor White
Write-Host "  2. Click 'Get started' to register" -ForegroundColor White
Write-Host "  3. Login and scan URLs/emails/SMS" -ForegroundColor White
Write-Host ""
Write-Host "  You'll see them in your Admin panel!" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow

# Keep script alive
while ($true) { Start-Sleep -Seconds 10 }
