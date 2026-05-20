# Read-only helper for Export-ADPrivilegeMap.ps1 (defensive AD audit tool).
# Pure local file I/O - reads template + vis-network lib, writes HTML + data.js.
# No AD queries.
# HTML-Export aus Template + Nodes/Edges.

function ConvertTo-PrivMapVisNode {
    param($Node)

    $color = switch ($Node.Type) {
        'User' {
            if ($Node.IsSDPropOrphan)         { '#7c2d12' }
            elseif ($Node.AdminCount)         { '#b91c1c' }
            elseif ($Node.LateralMemberOnly)  { '#bfdbfe' }
            elseif ($Node.Enabled -eq $false) { '#9ca3af' }
            else                              { '#3b82f6' }
        }
        'Group' {
            if ($Node.IsRoot)                 { '#dc2626' }
            elseif ($Node.AdminCount)         { '#ea580c' }
            elseif ($Node.LateralParentOnly)  { '#d9f99d' }
            elseif ($Node.LateralMemberOnly)  { '#fef3c7' }
            elseif ($Node.LateralOnly)        { '#fcd34d' }
            else                              { '#f59e0b' }
        }
        'Computer' {
            if ($Node.LateralMemberOnly)      { '#bbf7d0' }
            else                              { '#10b981' }
        }
        'ForeignSecurityPrincipal' {
            if ($Node.LateralMemberOnly)      { '#e9d5ff' }
            else                              { '#a855f7' }
        }
        'OU'                                  { '#64748b' }
        default                               { '#6b7280' }
    }
    $delegLine = if ($Node.HasDelegation) { "`nDelegation: $($Node.DelegationType)" } else { '' }
    $tooltip = "Type: $($Node.Type)`nSAM: $($Node.SamAccountName)`nEnabled: $($Node.Enabled)`nAdminCount: $($Node.AdminCount)`nIsRoot: $($Node.IsRoot)`nIsSDPropOrphan: $($Node.IsSDPropOrphan)`nLateralOnly: $($Node.LateralOnly)`nLateralMemberOnly: $($Node.LateralMemberOnly)`nLateralParentOnly: $($Node.LateralParentOnly)${delegLine}`nDN: $($Node.DistinguishedName)"

    [PSCustomObject]@{
        id                 = $Node.Id
        label              = $Node.DisplayName
        title              = $tooltip
        color              = $color
        shape              = if ($Node.Type -eq 'Group' -or $Node.Type -eq 'OU') { 'box' } else { 'dot' }
        nodeType           = $Node.Type
        nodeEnabled        = $Node.Enabled
        nodeAdminCount     = $Node.AdminCount
        nodeIsRoot         = $Node.IsRoot
        nodeIsOrphan       = $Node.IsSDPropOrphan
        nodeLateral        = $Node.LateralOnly
        nodeLatMember      = $Node.LateralMemberOnly
        nodeLatParent      = $Node.LateralParentOnly
        nodeHasDelegation  = $Node.HasDelegation
        nodeDelegationType = $Node.DelegationType
    }
}

function Test-PrivMapLibIntegrity {
    # Validiert eine Lib-Datei gegen die SHA256SUMS-Datei im selben Verzeichnis.
    # Wirft eine Exception bei Mismatch, fehlender SHA256SUMS oder fehlendem Eintrag -
    # bewusst hart, damit ein manipuliertes Bundle nicht stillschweigend embedded wird.
    param(
        [Parameter(Mandatory)][string]$LibPath
    )
    $libDir       = Split-Path -Parent $LibPath
    $libBaseName  = Split-Path -Leaf   $LibPath
    $sumsPath     = Join-Path $libDir 'SHA256SUMS'

    if (-not (Test-Path -LiteralPath $sumsPath)) {
        throw "SHA256SUMS fehlt unter $sumsPath. Pruefdatei fuer Lib-Integritaet wurde geloescht oder nicht ausgecheckt - Abbruch."
    }
    # Format pro Zeile: "<64-hex-hash>  <filename>" (sha256sum-Standard).
    $expected = $null
    foreach ($line in (Get-Content -LiteralPath $sumsPath -ErrorAction Stop)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') {
            $h = $Matches[1]; $f = $Matches[2]
            if ($f -eq $libBaseName) { $expected = $h.ToLowerInvariant(); break }
        }
    }
    if (-not $expected) {
        throw "SHA256SUMS hat keinen Eintrag fuer '$libBaseName'. Vermutlich nicht versionierte Lib-Datei - Abbruch."
    }
    $actual = (Get-FileHash -LiteralPath $LibPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw @"
Integritaetspruefung fehlgeschlagen fuer $libBaseName.
  Erwartet (SHA256SUMS): $expected
  Berechnet:             $actual
Die Lib-Datei wurde modifiziert. Embedding abgebrochen, damit kein potentiell
manipulierter Code in den Report gelangt. Lib aus dem Repo restaurieren oder
SHA256SUMS bewusst aktualisieren.
"@
    }
}

function Export-PrivMapHtml {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TemplatePath,
        [Parameter(Mandatory)]$Nodes,
        [Parameter(Mandatory)]$Edges,
        [Parameter(Mandatory)][string]$DomainDnsRoot,
        [int]$Rounds = 0,
        [string]$VisNetworkLibPath,
        [switch]$SkipLibIntegrityCheck   # Notausgang fuer Wartung; per Default IMMER pruefen.
    )

    if (-not (Test-Path -LiteralPath $TemplatePath)) {
        throw "HTML-Template nicht gefunden: $TemplatePath"
    }

    # vis-network-Lib: Default-Pfad ist <repo>/lib/vis-network-9.1.9.min.js,
    # relativ zum Template aufgeloest. Damit funktioniert der Export voll
    # offline - keine externe CDN-Abhaengigkeit im fertigen HTML.
    if (-not $VisNetworkLibPath) {
        $templateDir   = Split-Path -Parent $TemplatePath
        $VisNetworkLibPath = Join-Path (Split-Path -Parent $templateDir) 'lib/vis-network-9.1.9.min.js'
    }
    if (-not (Test-Path -LiteralPath $VisNetworkLibPath)) {
        throw "vis-network-Lib nicht gefunden: $VisNetworkLibPath. Repository unvollstaendig? Erwartet bei <repo>/lib/vis-network-9.1.9.min.js."
    }
    # Integritaetspruefung vor dem Embedding - schuetzt vor lokal manipulierten
    # Lib-Dateien (z.B. wenn die Datei auf dem Build-Host getauscht wurde).
    if (-not $SkipLibIntegrityCheck) {
        Test-PrivMapLibIntegrity -LibPath $VisNetworkLibPath
    } else {
        Write-Warning "Lib-Integritaetspruefung deaktiviert (-SkipLibIntegrityCheck). Embedde $VisNetworkLibPath ungeprueft."
    }
    # ReadAllText (statt Get-Content -Raw) konserviert Bytes exakt, ohne BOM/Encoding-
    # Ueberraschungen. Wichtig bei einer minifizierten ~688 KB-Library.
    $visLib = [System.IO.File]::ReadAllText($VisNetworkLibPath, [System.Text.Encoding]::UTF8)

    $visNodes = $Nodes | ForEach-Object { ConvertTo-PrivMapVisNode -Node $_ }

    $nJson = ($visNodes | ConvertTo-Json -Depth 4 -Compress)
    $eJson = ($Edges | ForEach-Object {
        [PSCustomObject]@{ from = $_.From; to = $_.To; edgeType = $_.EdgeType; label = $_.Label }
    } | ConvertTo-Json -Depth 4 -Compress)

    if (-not $nJson)               { $nJson = '[]' }
    if (-not $eJson)               { $eJson = '[]' }
    if ($nJson -notmatch '^\s*\[') { $nJson = "[$nJson]" }
    if ($eJson -notmatch '^\s*\[') { $eJson = "[$eJson]" }

    # Daten-Datei separat schreiben (JSONP-Loader). Liegt zwingend NEBEN der HTML.
    # Browser blocken fetch() auf file://, aber <script src="...js"> aus dem gleichen
    # Ordner laden problemlos - deshalb JSONP-Format mit globaler Zuweisung.
    $dataPath = Join-Path (Split-Path -Parent $Path) 'ad-priv-map-data.js'
    $meta     = [PSCustomObject]@{
        generated = (Get-Date).ToString('o')
        domain    = $DomainDnsRoot
        nodeCount = @($Nodes).Count
        edgeCount = @($Edges).Count
        rounds    = $Rounds
    }
    $metaJson = $meta | ConvertTo-Json -Compress
    $dataJs   = "window.__PRIVMAP_DATA = {`"meta`":$metaJson,`"nodes`":$nJson,`"edges`":$eJson};`n"
    [System.IO.File]::WriteAllText($dataPath, $dataJs, (New-Object System.Text.UTF8Encoding($false)))

    $html = Get-Content -Path $TemplatePath -Raw -ErrorAction Stop
    # Lib-Marker ZUERST ersetzen, damit ggf. enthaltene "$"-Sequenzen nicht mit
    # spaeteren Platzhaltern kollidieren. .Replace() ist plain-string, kein Regex,
    # also sind $1/$& im Lib-Code unschaedlich.
    $html = $html.Replace('__VIS_NETWORK_LIB__', $visLib)
    $html = $html.Replace('__DOMAIN__',    [string]$DomainDnsRoot)
    $html = $html.Replace('__TIMESTAMP__', (Get-Date).ToString('yyyy-MM-dd HH:mm'))
    $html = $html.Replace('__NODECOUNT__', [string]@($Nodes).Count)
    $html = $html.Replace('__EDGECOUNT__', [string]@($Edges).Count)
    $html = $html.Replace('__ROUNDS__',    [string]$Rounds)

    $html | Out-File -FilePath $Path -Encoding UTF8
    return [PSCustomObject]@{ HtmlPath = $Path; DataPath = $dataPath }
}
