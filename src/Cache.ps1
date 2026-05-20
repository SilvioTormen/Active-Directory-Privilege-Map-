# Read-only helper for Export-ADPrivilegeMap.ps1 (defensive AD audit tool).
# No AD/Registry write operations - this module handles JSON cache I/O only.
# Cache-I/O fuer Nodes/Edges + Meta.

function Resolve-PrivMapCachePath {
    param(
        [string]$CachePath,
        [string]$OutputPath
    )
    if ($CachePath) { return $CachePath }

    $candidate = Join-Path $OutputPath 'ad-priv-map-cache.json'
    if (Test-Path -LiteralPath $candidate) { return $candidate }

    $searchBase = Split-Path $OutputPath -Parent
    if (-not $searchBase -or -not (Test-Path -LiteralPath $searchBase)) {
        throw "Kein Cache und kein gueltiges Basis-Verzeichnis. Bitte -CachePath setzen."
    }
    $candidates = Get-ChildItem -Path $searchBase -Filter 'ad-priv-map-cache.json' -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if (-not $candidates -or $candidates.Count -eq 0) {
        throw "Kein Cache gefunden in '$searchBase'. Bitte erst einen normalen Lauf machen (ohne -FromCache)."
    }
    $found = $candidates[0].FullName
    Write-Host "Cache automatisch gefunden: $found" -ForegroundColor Gray
    return $found
}

function Read-PrivMapCache {
    param(
        [Parameter(Mandatory)][string]$Path
    )
    Write-Host ""
    Write-Host "Cache-Modus: lade $Path" -ForegroundColor Cyan
    try {
        $cache = Get-Content -Path $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    } catch {
        throw "Cache konnte nicht geladen werden: $_"
    }
    return $cache
}

function Write-PrivMapCache {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Nodes,
        [Parameter(Mandatory)]$Edges,
        [Parameter(Mandatory)][hashtable]$Meta
    )
    $orderedMeta = [ordered]@{}
    foreach ($k in 'Generated','Domain','Rounds','LateralCount','LatMemCount','LatParCount','DelegCount','KerbEdges','AclEdges') {
        if ($Meta.ContainsKey($k)) { $orderedMeta[$k] = $Meta[$k] }
    }
    $cacheData = [ordered]@{
        Meta  = $orderedMeta
        Nodes = @($Nodes)
        Edges = @($Edges)
    }
    try {
        $cacheData | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $Path -Encoding UTF8
        Write-Host "  Cache geschrieben: $Path" -ForegroundColor Gray
    } catch {
        Write-Warning "Cache konnte nicht geschrieben werden: $_"
    }
}
