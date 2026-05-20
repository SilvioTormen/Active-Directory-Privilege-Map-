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

function Export-PrivMapHtml {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$TemplatePath,
        [Parameter(Mandatory)]$Nodes,
        [Parameter(Mandatory)]$Edges,
        [Parameter(Mandatory)][string]$DomainDnsRoot,
        [int]$Rounds = 0,
        [string]$VisNetworkLibPath
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
    $html = $html.Replace('__NODESJSON__', $nJson)
    $html = $html.Replace('__EDGESJSON__', $eJson)

    $html | Out-File -FilePath $Path -Encoding UTF8
    return $Path
}
