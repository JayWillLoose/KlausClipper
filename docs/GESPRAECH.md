# Zusammenfassung des ersten Gesprächs (23.11.2026)

## Wunsch des Nutzers
- Eine Python-Software, die nach Bugs, kritischen Fehlern und Sicherheitslücken sucht
  und sie mit Schweregrad anzeigt.
- Zeitgesteuert: „Such jetzt eine Stunde“ statt ununterbrochen.
- Für die eigene Firma und gratis für andere Firmen – Erlaubnis holt der Nutzer ein.
- Das System soll mit jedem Fund besser werden („Loop“).
- Alles soll auf dem PC gespeichert sein, inkl. dieses Gesprächs.

## Was wir geklärt haben
- **Legal:** Gratis ändert nichts – ohne Erlaubnis ist Testen strafbar
  (§ 202a/202c StGB). Wege: schriftlicher Auftrag, Open-Source-Code,
  Bug-Bounty-Scope.
- **YesWeHack/Intigriti** geben meist **keinen Quellcode**, sondern Scope, Regeln,
  manchmal Testkonten. Ausnahmen: Open Source, Mobile Apps (zerlegbar),
  JavaScript im Browser, selten private Programme mit Codezugang.
- **Rate-Limits:** Programme erlauben typischerweise nur ca. 2–10 Anfragen/Sekunde;
  Überschreiten kann zur Sperre führen.
- **Chancen bei riesigen, viel getesteten Seiten:** Von außen und automatisch eher
  niedrig (leichte Bugs sind längst gemeldet). Mit Quellcode deutlich höher.
  Bugs stecken heute v. a. in neuem Code, Geschäftslogik (IDOR, Rollen),
  Kombinationen kleiner Fehler und Randfällen.
- **„Lernen“:** Das Modell selbst trainiert nicht weiter. Das System lernt über
  Wissensdatenbank, App-Karte, Variantensuche (aus jedem Bug wird eine Suchregel),
  Abdeckungsmessung, Fokus auf Änderungen, Regressionstests.
