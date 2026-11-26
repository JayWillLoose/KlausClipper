# Domain- & Hosting-Recherche – eigene Webseiten-Firma (Stand 26.11.2026)

**Ziel des Nutzers:** Mit einem Kumpel Webseiten verkaufen. Eine Hauptdomain (Marke, Arbeitstitel
„Klaus Gard“). Alle Kundenseiten laufen über **unsere** Server, alles wird über **uns** abgerechnet –
wir sind der Anbieter, nicht Wix/IONOS/Strato.

> Preise stammen teils aus Vergleichsportalen/Anbieter-Blogs → vor dem Kauf direkt beim Anbieter prüfen.
> Keine Rechts-/Steuerberatung – vor Gründung Steuerberater/IHK fragen.

---

## 1. Die Hauptdomain

Verfügbarkeit geprüft am 26.11.2026 (Vercel-Registry-Abfrage, keine Reservierung):

| Domain | frei? |
|---|---|
| klausgard.de / .com / .io / .dev | ✅ frei |
| klausclipper.de / .com | ✅ frei |
| klaushackt.de / .com | ✅ frei |
| klaushost.de, klausseiten.de | ✅ frei |
| klausweb.de, klaus-web.de | ❌ vergeben |

**Empfehlung:** `klausgard.de` **und** `klausgard.com` gleichzeitig sichern (zusammen ca. 15–25 €/Jahr),
damit niemand die zweite Endung wegschnappt. `.de` = Vertrauen bei deutschen Kunden.
Vorher kurz Markenregister prüfen (DPMA „DPMAregister“, EUIPO), dass „Klaus Gard“ nicht geschützt ist.

## 2. Wie „alles läuft über uns“ technisch aussieht

```
Kunde ──► kunde-xy.de  (Domain über uns registriert, DNS zeigt auf uns)
            │
            ▼
   unser Server (Hetzner/Netcup)  ── Coolify/Caddy: automatisches HTTPS
            │
   Kundenportal + Rechnung: portal.klausgard.de  (Blesta / Invoice Ninja)
```

Drei Stufen für Kundenseiten:
1. **Gratis-Start:** `kunde.klausgard.de` – sofort online, kostet nichts extra.
2. **Eigene Domain des Kunden:** wir registrieren sie über unseren Reseller-Account, DNS zeigt auf unseren Server.
3. **Skalierung (später, viele Kunden):** Cloudflare for SaaS – 100 Kunden-Hostnamen inklusive, danach
   ca. 0,10 $/Hostname/Monat, SSL-Zertifikate automatisch. [Quelle](https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/plans/)

## 3. Domains einkaufen – wir als Reseller

- **Eigener Registrar bei DENIC werden lohnt sich NICHT** am Anfang (Mitgliedschaft + Technik, gedacht für
  große Provider). DENICdirect kostet 116 €/Jahr pro Domain – viel zu teuer. [DENIC-Preisliste](https://denic.de/en/price-list)
- **Stattdessen Domain-Reseller-Account** bei einem Großhändler:
  - **INWX** (Berlin): API, kostenloses Testsystem (ote.inwx.ch), WHMCS-Module, Reseller-Sonderpreise.
    Endkundenpreise grob .de ~4,7 €/Jahr, .com ~13 €/Jahr. [INWX Reseller](https://www.inwx.com/en/customer-solutions/reseller), [API](https://www.inwx.de/offer/api)
  - Alternativen: InterNetX, Openprovider. [InterNetX](https://www.internetx.com/en/domain-reseller-program/)
- **Marge:** Einkauf .de ~2–5 € → Verkauf an Kunden typ. 10–15 €/Jahr, meist im Paketpreis versteckt.

**Wichtig (Fairness + Rechtssicherheit):** Domain **auf den Namen des Kunden** als Inhaber registrieren,
wir verwalten sie technisch. Sonst Ärger beim Wechsel/Streit. Auth-Code-Herausgabe im Vertrag regeln.
[Openprovider](https://www.openprovider.com/blog/who-really-controls-your-clients-domains-and-why-it-matters),
[NameSilo](https://www.namesilo.com/blog/en/domain-names/domain-management-for-agencies-best-practices-for-client-ownership-and-access)
→ Kunden bleiben trotzdem bei uns, weil Hosting, Pflege und Support bei uns liegen.

## 4. Server

| Option | Kosten | Kommentar |
|---|---|---|
| Hetzner Cloud + **Coolify** (kostenlos, selbst gehostet) | ab ~5–20 €/Monat | Coolify = eigenes „Vercel“: Git-Deploy, Auto-SSL, viele Seiten auf einem Server. [Hetzner-Blog](https://www.hetzner.com/de/blog/one-click-self-hosting-with-coolify/) |
| Reseller-Webhosting (Plesk/cPanel beim Hoster) | ab ~7–12 €/Monat | weniger Technik, aber weniger „unser Zeug“. [hosttest](https://www.hosttest.de/vergleich/webhosting-agenturen.html/order=statusprice+standort=Deutschland) |
| Managed White-Label (Duda) | ~149–199 $/Monat | Baukasten mit eigenem Logo, teuer, abhängig. [Duda Pläne](https://www.duda.co/plans) |

⚠️ **Hetzner 2026:** Zwei Preiserhöhungen (Juni 2026: CPX +144–175 %, CX +31–38 %) und zeitweise
Sperre für neue Cloud-Server bei Neukunden. → **CX/CAX-Tarife** nehmen oder Alternative (Netcup, Contabo)
vergleichen. [bitdoze](https://www.bitdoze.com/md/de/hetzner-cloud-guenstige-tarife.md),
[Betterstack](https://betterstack.com/community/guides/web-servers/hetzner-cloud-review/)

**Empfehlung Start:** 1 Server (4 vCPU / 8 GB) + Coolify + tägliches Backup auf Storage-Box/zweiten Anbieter.
Reicht für 30–80 einfache Firmenseiten. Server in Deutschland = DSGVO-Argument im Verkauf.

## 5. Abrechnung („alles über uns“)

- **Kundenportal/Abos:** Blesta (unbegrenzte Kunden, ~18 $/Monat oder Einmal-Lizenz 350–500 $) statt
  WHMCS (35–85 $/Monat, nach Kundenzahl). FOSSBilling ist gratis, aber noch Beta. [Blesta vs WHMCS](https://blesta.com/compare/blesta-vs-whmcs/),
  [PayRequest](https://payrequest.io/blog/best-whmcs-alternatives-2026)
- Ganz einfach für den Anfang: **Invoice Ninja** (Open Source) oder lexoffice/sevDesk + SEPA-Lastschrift (GoCardless/Stripe).
- **Preismodell-Idee:** Einmalig Erstellung (z. B. 490–1.500 €) + monatliches Abo „Hosting, Domain, SSL,
  Backups, Updates, kleine Änderungen“ (z. B. 19–49 €/Monat). Das Abo ist das eigentliche Geschäft.

## 6. Rechtliches & Steuern (Kurz)

- Gewerbe anmelden → Finanzamt (Fragebogen steuerliche Erfassung) → IHK. Zu zweit = automatisch **GbR**;
  schriftlichen Gesellschaftsvertrag machen (Anteile, Ausstieg, wem gehören Kunden/Domain/Code).
  [e-recht24](https://e-recht24.de/datenschutz/13122-alles-rechtliche-fuer-agenturen-und-webdesigner.html)
- **Kleinunternehmerregelung 2026:** Vorjahr ≤ 25.000 €, laufendes Jahr ≤ 100.000 € (harte Grenze seit 2025).
  [IHK München](https://www.ihk-muenchen.de/ratgeber/steuern/umsatzsteuer/kleinunternehmerregelung/)
- Als Hoster brauchen wir mit jedem Kunden einen **AVV** (Art. 28 DSGVO), eigene **AGB** mit
  Haftungsbegrenzung, und eigene Unterauftragsverarbeiter-Liste (Hetzner, INWX …).
  [Haftung Agenturen](https://www.e-recht24.de/domain-hosting/11035-haftung-agenturen-webdesigner.html),
  [IT-Recht-Kanzlei](https://www.it-recht-kanzlei.de/webdesign-vertrag.html)

## 7. „Revolutionieren“ – womit wir uns abheben

1. **Alles-aus-einer-Hand-Abo** statt Einmalprojekt: Kunde zahlt monatlich, wir kümmern uns um alles.
2. **KI-Schnellstart:** Seite in 48 h, mit Claude-Workflow (Texte, Design-Entwurf), Mensch prüft.
3. **Sicherheit als Verkaufsargument:** eigener KlausHackt-Check jeder Kundenseite (nur eigene/beauftragte Seiten,
   Scope-Datei!) → „geprüfte Sicherheit“-Siegel im Angebot.
4. **Server in Deutschland, DSGVO-fertig** (Impressum/Datenschutz/Cookie-Banner inklusive).
5. **Transparenz:** Domain gehört dem Kunden – das schafft Vertrauen, die meisten Agenturen machen es anders.

## 8. Nächste Schritte (Reihenfolge)

1. Namen festlegen → Markencheck → `klausgard.de` + `.com` registrieren (kann ich über Vercel prüfen/kaufen, **nur mit OK**).
2. GbR-Vertrag + Gewerbe + Geschäftskonto.
3. INWX-Reseller-Account (Testsystem zuerst).
4. Server + Coolify aufsetzen, Hauptseite `klausgard.de` + Portal.
5. Vorlagen: AGB, AVV, Angebot, Preisliste.
6. Erste 3 Kunden günstig als Referenz.

**Offene Fragen an den Nutzer:** Ist „Klaus Gard“ der endgültige Name? Wie viele Kunden im ersten Jahr?
Wer macht Technik / wer Vertrieb? Budget für Start?
