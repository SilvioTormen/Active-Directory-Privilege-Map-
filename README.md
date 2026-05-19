# Active Directory Privilege Map

`Export-ADPrivilegeMap.ps1` erzeugt eine voll aufgeloeste Beziehungsmap aller
privilegierten AD-Objekte und exportiert sie als interaktive HTML-Visualisierung.

## Funktionsumfang

- **A1** Auto-Discovery aller Gruppen mit `AdminCount=1` als Tier-0-Roots
- **A2** User-Membership-Walk (per Default nur fuer `AdminCount=1`-User,
  lateral begrenzt, damit der Graph nicht explodiert)
- **A3** SDProp-Waisen (User mit `AdminCount=1` ohne Membership in Tier-0)
- **A4** PrimaryGroupID-Reverse-Lookup (nur fuer `AdminCount=1`-Gruppen)
- **A5** Iterative Konvergenz bis keine neuen Nodes mehr dazukommen
- **B6** Layout-Umschalter Physics / Hierarchisch (Tier-0 oben)
- **B7** Filter-Toolbar (Tier-0, aktive User, Computer/FSP, laterale Gruppen,
  Min-Memberships, Suche)
- **C10** `Write-Progress` fuer alle Schleifen

### Attack-Path-Computation (im HTML)

Die HTML-Visualisierung berechnet im Browser zusaetzlich:

- **Distanz zu Tier-0 pro Node** via Multi-Source-BFS von allen Tier-0-Nodes
  in Inbound-Richtung. Damit weiss jeder Node, wieviele Hops er von
  Domain-Admin-Aequivalent entfernt ist.
- **Display-Modus "Tier-0-Risiko (Distanz)"**: zeigt nur Nodes innerhalb
  einer Max-Distanz und faerbt deren Outline nach Distanz (1 rot, 2
  orange, 3 gelb, 4+ gruen). Mit Selektion wird der kuerzeste Pfad zu
  Tier-0 hervorgehoben (alle gleichlangen Pfade als Layer).
- **Display-Modus "Owned-Cone (Selektion)"**: zeigt die outbound
  transitive Huelle ab einem ausgewaehlten Node - also alle Objekte, die
  dieser Node direkt oder indirekt uebernehmen koennte.
- **Top-Pfade-Panel**: Liste der Nicht-Tier-0-Nodes mit der kuerzesten
  Distanz zu Tier-0, Klick fokussiert den Node + schaltet in den
  Risiko-Modus.

## Voraussetzungen

- Windows PowerShell 5.1 oder PowerShell 7+
- RSAT / Modul `ActiveDirectory`
- Leseberechtigung auf dem Ziel-Forest

## Verwendung

```powershell
# Standardlauf
.\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp

# A2 komplett deaktivieren
.\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp -SkipUserMembershipWalk

# A2 fuer ALLE User (Achtung: blaeht den Graph stark auf)
.\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp -FullUserMembershipWalk

# Manuelle Root-Auswahl per Out-GridView
.\Export-ADPrivilegeMap.ps1 -OutputPath C:\Temp -Pick
```

### Parameter

| Parameter | Beschreibung |
|-----------|--------------|
| `-OutputPath` | Zielordner fuer die Exporte. Default: `%TEMP%\AD-PrivMap-<Timestamp>` |
| `-MaxDepth` | Maximale Rekursionstiefe pro Richtung. Default: `12` |
| `-MaxRounds` | Maximale Konvergenzrunden. Default: `8` |
| `-Pick` | Oeffnet `Out-GridView` fuer manuelle Root-Auswahl |
| `-SkipUserMembershipWalk` | Deaktiviert A2 komplett |
| `-FullUserMembershipWalk` | A2 fuer ALLE User |
| `-Minimal` | Reduzierter Export |
| `-IncludeDelegation` | Delegations-Edges mit aufnehmen |
| `-FromCache` | Lauf aus zuvor exportiertem Cache wiederherstellen |
| `-CachePath` | Pfad zum Cache |
| `-ExtraRootGroups` | Zusaetzliche Root-Gruppen (`SAMAccountName`) |

## Repo-Struktur

```
Export-ADPrivilegeMap.ps1     # Einstiegspunkt (Orchestrierung, ~250 Zeilen)
src/
  Graph.ps1                   # Add-Node / Add-Edge
  Walks.ps1                   # Expand-Members / -MemberOf / -UserMemberships / Add-PrimaryGroupMembers
  Discovery.ps1               # A1 Root-Discovery + A3 SDProp-Waisen
  Convergence.ps1             # A5 Konvergenz + Phase 3/4 (laterale Members/Parents)
  Delegation.ps1              # Phase 5 Kerberos + Phase 6 ACL
  Cache.ps1                   # JSON-Cache lesen/schreiben
  Export-Html.ps1             # HTML-Render aus Template
templates/
  ad-priv-map.html.tmpl       # vis-network HTML-Template mit Platzhaltern
```

Die Helper unter `src/` werden vom Wrapper per Dot-Source geladen. Damit
sieht jede Funktion den State (`$Nodes`, `$Edges`, Visited-Sets,
`$MaxDepth`, ...) im aufrufenden Skript-Scope und kann ihn in-place
mutieren - das Verhalten ist identisch zum Original-Monolithen.
