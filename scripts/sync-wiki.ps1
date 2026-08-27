# Sync the in-repo docs/wiki/ directory to the GitHub Wiki.
#
# The GitHub Wiki is a separate git repository (<owner>/<repo>.wiki.git),
# so it must be pushed to explicitly. This script clones it, mirrors
# docs/wiki/ into it, and pushes.
#
# Requirements:
#   - GitHub CLI (`gh`) installed and authenticated: `gh auth login`
#     (or set GH_TOKEN / GITHUB_TOKEN in the environment)
#
# Usage:
#   powershell -File scripts/sync-wiki.ps1
#   or simply:  .\scripts\sync-wiki.ps1
#
# Optional: pass the target as an argument, e.g.
#   .\scripts\sync-wiki.ps1 blueokanna/TypeBit

$ErrorActionPreference = "Stop"

# Resolve the owner/repo from the first `git remote` if not given.
$Target = $args[0]
if (-not $Target) {
    $remote = git remote get-url origin 2>$null
    if ($remote -match "github.com[:/]([^/]+)/([^/.]+)(\.git)?$") {
        $Target = "$($matches[1])/$($matches[2])"
    }
}
if (-not $Target) {
    Write-Error "Could not determine the GitHub repo. Pass it explicitly: sync-wiki.ps1 <owner>/<repo>"
}

# gh CLI is required for authenticated access to the wiki repository.
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Error "GitHub CLI 'gh' is required. Install it from https://cli.github.com and run: gh auth login"
}

$tmp = Join-Path $env:TEMP "typebit-wiki-sync"
if (Test-Path $tmp) {
    Remove-Item -Recurse -Force $tmp
}
Write-Host "Cloning wiki for $Target ..."
gh repo clone "$Target.wiki" $tmp -- --quiet

Write-Host "Mirroring docs/wiki -> wiki ..."
# Remove everything except the wiki's .git directory.
Get-ChildItem $tmp -Force | Where-Object { $_.Name -ne ".git" } | Remove-Item -Recurse -Force
Copy-Item -Recurse -Force (Join-Path $PWD "docs\wiki\*") $tmp

git -C $tmp add -A
if (git -C $tmp diff --cached --quiet) {
    Write-Host "No wiki changes."
} else {
    git -C $tmp commit -m "sync wiki from docs/wiki"
    git -C $tmp push
    Write-Host "Wiki synced: https://github.com/$Target/wiki"
}

Remove-Item -Recurse -Force $tmp
