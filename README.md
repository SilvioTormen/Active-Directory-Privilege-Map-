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
