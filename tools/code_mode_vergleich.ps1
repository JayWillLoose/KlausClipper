# Code-Mode-Vergleich fuer Claude Code (Windows / PowerShell)
#
# Laesst dieselbe Aufgabe mehrmals OHNE und MIT dem experimentellen Code Mode laufen
# und vergleicht die verbrauchten Tokens. Die Aufgabe ist nur lesend (nichts wird geaendert).
#
# Voraussetzungen:
#   - Claude Code >= 2.1.323 (pruefen: claude --version)
#   - Git for Windows (Bash) installiert - Code Mode braucht das unter Windows
#   - Im Repo-Ordner starten, z. B.:
#       cd C:\Pfad\zu\KlausClipper
#       powershell -ExecutionPolicy Bypass -File tools\code_mode_vergleich.ps1
#
# Optional: -Laeufe 3  (Standard 2 pro Modus)  -Aufgabe "eigener Prompt"

param(
    [int]$Laeufe = 2,
    [string]$Aufgabe = "Lies den Ordner klaushackt/ und die Tests in tests/. Erklaere in hoechstens 10 Saetzen, wie Scope-Pruefung, Drossel und Lern-Loop zusammenspielen, und nenne die drei wichtigsten Dateien. Aendere keine Dateien."
)

$ErrorActionPreference = "Continue"   # "Stop" wuerde bei Ausgaben von claude auf stderr abbrechen
$ordner = Join-Path $env:TEMP "code_mode_vergleich"
New-Item -ItemType Directory -Force -Path $ordner | Out-Null

# claude -p bekommt Code Mode NUR ueber den env-Block von --settings (so steht es in Claude Code selbst).
$settingsAn  = Join-Path $ordner "settings_an.json"
$settingsAus = Join-Path $ordner "settings_aus.json"
# Ohne BOM schreiben, damit der JSON-Parser nicht stolpert.
[IO.File]::WriteAllText($settingsAn,  '{"env":{"CLAUDE_CODE_EXPERIMENTAL_CODE_MODE":"1"}}')
[IO.File]::WriteAllText($settingsAus, '{"env":{}}')

function Starte-Lauf([string]$modus, [int]$nr) {
    $settings = if ($modus -eq "an") { $settingsAn } else { $settingsAus }
    $log = Join-Path $ordner "lauf_${modus}_${nr}.jsonl"
    Write-Host "  Lauf $nr, Code Mode $modus ..." -NoNewline
    $Aufgabe | claude -p --output-format stream-json --verbose --settings $settings > $log 2> "$log.err"

    $ergebnis = $null; $toolAnzahl = $null; $hinweis = ""
    foreach ($zeile in Get-Content $log) {
        try { $d = $zeile | ConvertFrom-Json } catch { continue }
        if ($d.type -eq "system" -and $d.subtype -eq "init") { $toolAnzahl = $d.tools.Count }
        if ($d.type -eq "system" -and $d.key -eq "code-mode-opt-in") { $hinweis = $d.text }
        if ($d.type -eq "result") { $ergebnis = $d }
    }
    if (-not $ergebnis) { Write-Host " FEHLER (siehe $log)"; return $null }
    $u = $ergebnis.usage
    $eingabe = $u.input_tokens + $u.cache_read_input_tokens + $u.cache_creation_input_tokens
    Write-Host (" {0:N0} Eingabe-Tokens, {1:N0} Ausgabe, {2:N3} USD" -f $eingabe, $u.output_tokens, $ergebnis.total_cost_usd)
    if ($hinweis) { Write-Host "    Hinweis von Claude Code: $hinweis" -ForegroundColor Yellow }
    [pscustomobject]@{
        Modus = $modus; Lauf = $nr; Tools = $toolAnzahl
        Eingabe = $eingabe; Ausgabe = $u.output_tokens
        Kosten = [math]::Round($ergebnis.total_cost_usd, 4)
        Runden = $ergebnis.num_turns; Sekunden = [math]::Round($ergebnis.duration_ms / 1000)
    }
}

Write-Host "Claude Code: $(claude --version)"
Write-Host "Aufgabe: $Aufgabe`n"
$alle = @()
# Abwechselnd laufen lassen, damit Cache-Effekte beide Modi gleich treffen.
for ($i = 1; $i -le $Laeufe; $i++) {
    $alle += Starte-Lauf "aus" $i
    $alle += Starte-Lauf "an"  $i
}
$alle = $alle | Where-Object { $_ }

Write-Host "`n=== Einzelne Laeufe ==="
$alle | Format-Table -AutoSize

Write-Host "=== Durchschnitt ==="
$zusammen = $alle | Group-Object Modus | ForEach-Object {
    [pscustomobject]@{
        Modus   = $_.Name
        Eingabe = [math]::Round(($_.Group | Measure-Object Eingabe -Average).Average)
        Ausgabe = [math]::Round(($_.Group | Measure-Object Ausgabe -Average).Average)
        Kosten  = [math]::Round(($_.Group | Measure-Object Kosten  -Average).Average, 4)
    }
}
$zusammen | Format-Table -AutoSize

$aus = $zusammen | Where-Object Modus -eq "aus"
$an  = $zusammen | Where-Object Modus -eq "an"
if ($aus -and $an -and $aus.Eingabe -gt 0) {
    $diff = [math]::Round((1 - $an.Eingabe / $aus.Eingabe) * 100, 1)
    Write-Host "Code Mode spart $diff % Eingabe-Tokens (negativ = mehr Verbrauch)." -ForegroundColor Cyan
}
Write-Host "Rohdaten: $ordner"
Write-Host "Achtung: Tauchte oben ein gelber Hinweis auf, war Code Mode in dem Lauf NICHT aktiv."
