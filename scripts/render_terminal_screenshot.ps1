# Make terminal-style screenshots from real captured CLI output.
#
# The text in the PNG is the verbatim content of the captured session file
# (e.g. evidence/terminal/terminal_session.txt), rendered with a monospace font.
# This is a rendering of real captured output, not a re-typed transcript.
#
# Usage:
#   powershell -NoProfile -File scripts/render_terminal_screenshot.ps1 `
#     -InputFile evidence/terminal/terminal_session.txt `
#     -OutputFile docs/screenshots/terminal_session.png `
#     -Title "Windows PowerShell - exfil-guard evidence session (real CLI output)"

param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutputFile,
    [Parameter(Mandatory = $true)][string]$Title,
    [int]$MaxWidthChars = 100,
    [int]$FontSize = 12
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$raw = [System.IO.File]::ReadAllText((Resolve-Path $InputFile).Path, [System.Text.Encoding]::UTF8)
$rawLines = $raw -split "`r?`n"

# Hard-wrap long lines so the whole session fits a readable width.
$lines = New-Object System.Collections.Generic.List[string]
foreach ($line in $rawLines) {
    if ($line.Length -le $MaxWidthChars) {
        $lines.Add($line)
        continue
    }
    $rest = $line
    while ($rest.Length -gt $MaxWidthChars) {
        $cut = $rest.LastIndexOf(' ', $MaxWidthChars)
        if ($cut -lt [int]($MaxWidthChars / 2)) { $cut = $MaxWidthChars }
        $lines.Add($rest.Substring(0, $cut).TrimEnd())
        $rest = $rest.Substring($cut).TrimStart()
    }
    $lines.Add($rest)
}

$lineHeight = [int]($FontSize * 1.62)
$padding = 20
$titleHeight = 40
$width = 1240
$height = [int]($titleHeight + $padding * 2 + $lines.Count * $lineHeight + 46)

$bitmap = New-Object System.Drawing.Bitmap($width, $height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

$bg = [System.Drawing.Color]::FromArgb(12, 12, 12)
$titleBg = [System.Drawing.Color]::FromArgb(31, 41, 55)
$hitBg = [System.Drawing.Color]::FromArgb(3, 7, 18)
$graphics.Clear($bg)
$graphics.FillRectangle((New-Object System.Drawing.SolidBrush($titleBg)), 0, 0, $width, $titleHeight)
$graphics.FillRectangle((New-Object System.Drawing.SolidBrush($hitBg)), 0, $titleHeight, $width, $height - $titleHeight)

$titleFont = New-Object System.Drawing.Font('Consolas', 13, [System.Drawing.FontStyle]::Bold)
$bodyFont = New-Object System.Drawing.Font('Consolas', $FontSize, [System.Drawing.FontStyle]::Regular)
$titleBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(226, 232, 240))
$textBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(229, 231, 235))
$cmdBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(125, 211, 252))
$highBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(248, 113, 113))
$mediumBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(251, 191, 36))
$okBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(74, 222, 128))
$mutedBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(148, 163, 184))

$graphics.DrawString($Title, $titleFont, $titleBrush, 20, 9)

$y = $titleHeight + $padding
foreach ($line in $lines) {
    $brush = $textBrush
    if ($line.StartsWith('$ ')) { $brush = $cmdBrush }
    elseif ($line -match '^\s*HIGH\b' -or $line -match '^\s*\[HIGH\]' -or $line -match 'THRESHOLD REACHED' -or $line -match 'TIMEOUT') { $brush = $highBrush }
    elseif ($line -match '^\s*MEDIUM\b' -or $line -match '^\s*\[MEDIUM\]') { $brush = $mediumBrush }
    elseif ($line -match '^\s*(LOW|  \[LOW\])' -or $line -match '^\s*\[LOW\]') { $brush = $mutedBrush }
    elseif ($line -match '^\[exit code: 0\]' -or $line -match '^OK$' -or $line -match '^Ran \d+ tests' -or $line -match '^\s*SAFE\b') { $brush = $okBrush }
    elseif ($line -match '^\[exit code: 1\]') { $brush = $mediumBrush }
    elseif ($line -match '^#') { $brush = $mutedBrush }
    $graphics.DrawString($line, $bodyFont, $brush, $padding, $y)
    $y += $lineHeight
}

$caption = "Rendered from " + (Resolve-Path $InputFile).Path + "  -  pixel-identical text, no re-typing."
$graphics.DrawString($caption, $bodyFont, $mutedBrush, $padding, $y + 8)

$target = [System.IO.Path]::GetFullPath($OutputFile)
$dir = [System.IO.Path]::GetDirectoryName($target)
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
$bitmap.Save($target, [System.Drawing.Imaging.ImageFormat]::Png)

$graphics.Dispose()
$bitmap.Dispose()
Write-Output ("wrote {0} ({1}x{2}, {3} lines)" -f $target, $width, $height, $lines.Count)
