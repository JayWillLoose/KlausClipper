# Server, Plattform & Firmen-E-Mail – Recherche (Stand 26.11.2026)

Ergänzt `docs/DOMAIN_RECHERCHE.md`. Arbeitsname bleibt **Klaus Gard** (`klausgard.de`), änderbar.
Preise aus Anbieter-/Vergleichsseiten → vor Bestellung direkt prüfen. Keine Rechtsberatung.

**Wunsch des Nutzers:** Gratis starten → wenn Geld da ist, alle Seiten auf einen besseren Server umziehen.
Alles soll uns gehören und über uns laufen. Eine Plattform „wie Lieferando“ (*Annahme: gemeint ist das
Plattform-Prinzip – viele Firmen unter unserem Dach/unserer Domain*). Eigene Firmen-E-Mail.

---

## 1. Was „gehört uns“ wirklich heißt

| Teil | Gehört uns, wenn … |
|---|---|
| Domain `klausgard.de` | sie auf **unseren Namen** registriert ist (Inhaber = wir/GbR). Kostet immer Geld (~5–15 €/Jahr) – **gratis gibt es keine eigene Domain.** |
| DNS | wir es selbst verwalten (Cloudflare gratis) – dann können wir Server jederzeit wechseln. |
| Server | wir ihn mieten. Eigene Hardware lohnt erst bei sehr vielen Kunden. |
| Code/Seiten | in **unserem Git-Repo** liegen (GitHub privat, gratis) – damit ist ein Umzug nur „neu ausrollen“. |
| Kundendaten/Abos | in unserem Abrechnungssystem auf unserem Server. |

**Kern-Trick für den späteren Umzug:** Domain → Cloudflare-DNS → Server. Beim Wechsel ändern wir nur eine
IP-Adresse in Cloudflare, Kunden merken nichts.

## 2. Gratis-Start – was wirklich kostenlos geht

| Angebot | Was man bekommt | Gewerblich erlaubt? | Haken |
|---|---|---|---|
| **Cloudflare Pages** | Statische Seiten, statische Anfragen unbegrenzt & gratis, 100 Domains pro Projekt, 500 Builds/Monat, 20.000 Dateien/Seite | Free-Plan ist laut Suche nicht eindeutig geregelt → Cloudflare-AGB prüfen (nach meinem Wissen üblich erlaubt) | nur statisch; dynamisch über Workers (100.000 Anfragen/Tag gratis) [Limits](https://developers.cloudflare.com/pages/platform/limits) |
| **Oracle Cloud Always Free** | ARM-VM. Laut mehreren Quellen seit ~15.06.2026 nur noch **2 Kerne / 12 GB RAM** (vorher 4/24) | AGB prüfen | Ungenutzte VMs werden zurückgeholt (<20 % Auslastung über 7 Tage); oft „Out of Capacity“; Kreditkarte nötig [Oracle Doku](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm), [dev.to](https://dev.to/karthik_yk/oracles-famous-free-4-core24gb-arm-tier-is-now-2-core12gb-check-the-docs-2jln) |
| Google Cloud e2-micro | 1 Mini-VM (sehr schwach), nur US-Regionen; 300 $ Startguthaben (90 Tage) | ja | zu schwach für Kundenseiten [Google](https://cloud.google.com/free) |
| AWS Free Plan | seit 15.07.2025 bis 200 $ Guthaben, max. 6 Monate | ja | läuft ab → kein Dauer-Gratis [tech-insider](https://tech-insider.org/what-changed-in-the-aws-free-tier-for-2026/) |
| ❌ **Vercel Hobby** | – | **Nein**, nur privat/nicht-kommerziell; Kundenarbeit braucht Pro (20 $/Monat) | [Vercel](https://vercel.com/docs/plans/hobby) |

**Empfehlung Phase 0 (≈ 1 €/Monat – nur die Domain):**
- Kundenseiten als **statische Seiten** (schnell, sicher, fast null Last) auf **Cloudflare Pages**.
- DNS + SSL über **Cloudflare (gratis)**.
- Optional Oracle-Free-VM für Kundenportal/Formulare – aber **nicht** fest darauf verlassen (kann weggenommen werden).
- Alles in Git → Umzug später ohne Neubau.

## 3. Bezahlte Server (Phase 1+, wenn Geld kommt)

| Anbieter | Beispiel | Preis/Monat | Bemerkung |
|---|---|---|---|
| **Hetzner** CX23 | 2 vCPU, 4 GB, 40 GB, 20 TB Traffic | ~4,50–6,50 € | Einstieg gut; große Tarife nach Juni-2026-Erhöhung teuer (4 Kerne/8 GB CPX32 ~43 €); zeitweise Neukunden-Sperre |
| **netcup** VPS 500 G12.5 | 2 vCPU, 4 GB, 64 GB | ~6,94 € (12 Mon.) | stabil, Root-Server 4 Kerne/8 GB ~14,50–16,70 € |
| **Contabo** Cloud VPS 4 | 4 vCPU, 8 GB, 100 GB | ~5,40–6,55 € | meiste Leistung pro €, aber oft 24-Monats-Bindung, Fair-Use/Drosselung |

Quellen: [serverserver.de](https://serverserver.de/beste-vps-anbieter-deutschland/), [hostingsift Preiserhöhungen 2026](https://hostingsift.com/blog/vps-price-increases-2026-who-raised-who-held), [vpsbenchmarks](https://www.vpsbenchmarks.com/compare/hetzner_vs_netcup), [Betterstack Hetzner](https://betterstack.com/community/guides/web-servers/hetzner-cloud-review/)

**Empfehlung Phase 1:** netcup oder Hetzner mit **4–8 GB RAM** (~7–17 €/Monat), Standort Deutschland,
darauf **Coolify** (gratis): Git-Deploy, Auto-HTTPS, Backups. Coolify selbst braucht ~2–4 GB → 8 GB ist bequem.
[Coolify-Planung](https://massivegrid.com/blog/coolify-resource-planning-multiple-apps)

## 4. Reicht die Kapazität?

| Server | WordPress-Seiten | Statische Seiten |
|---|---|---|
| 2 vCPU / 4 GB | 5–15 | sehr viele (Hunderte, eigene Schätzung) |
| 4 vCPU / 8 GB | 20–80 (gecachte Visitenkarten-Seiten) | Hunderte |
| Cloudflare Pages (gratis) | – | praktisch unbegrenzt (Pro Projekt 100 Domains, beliebig viele Projekte) |

Faustregel: 7–10 einfache WP-Seiten pro GB RAM. [GridPane](https://gridpane.com/kb/what-size-servers-to-choose-for-hosting-wordpress/),
[Virtarix](https://www.virtarix.com/blog/how-many-websites-can-you-host-on-vps)
→ **Fazit:** Für die ersten 50–100 Kunden reicht ein 8-GB-Server locker, wenn die Seiten statisch/gecacht sind.

## 5. Umzugsplan „gratis → besserer Server“

1. Alle Seiten liegen in Git, Inhalte/Datenbanken haben tägliche Backups.
2. Neuen Server mieten, Coolify installieren, Repos verbinden, Backups einspielen.
3. Testen über temporäre Adresse.
4. In Cloudflare die IP umstellen (Proxy an → Wechsel in Sekunden).
5. Alten Server 1–2 Wochen behalten, dann kündigen.
Später bei vielen Kundendomains: **Cloudflare for SaaS** (100 Hostnamen inkl., dann ~0,10 $/Monat je Domain).

## 6. Plattform „wie Lieferando“ (Annahme)

Lieferando-Prinzip = alle Betriebe erscheinen **unter unserer Marke**:
- `klausgard.de/firma-xy` oder `firma-xy.klausgard.de` (Wildcard-DNS `*.klausgard.de` in Cloudflare, gratis SSL).
- Kunde kann zusätzlich eigene Domain bekommen, die auf unsere Plattform zeigt.
- Wir kassieren Abo (und evtl. Provision), Kunde verwaltet nur Inhalte im Portal.
- Technisch: eine App (Multi-Mandant) statt 100 Einzelseiten → noch weniger Serverbedarf.
👉 Bitte bestätigen, ob „Larendo“ = Lieferando gemeint war.

## 7. Eigene Firmen-E-Mail (z. B. info@klausgard.de)

| Variante | Kosten | Kommentar |
|---|---|---|
| **Cloudflare Email Routing + Gmail „Senden als“** | 0 € | Empfang: Weiterleitung an privates Gmail. Senden: Gmail-SMTP mit App-Passwort, ca. 500 Mails/Tag. Gut für den Start. [dev.to Anleitung](https://dev.to/abdiel49/configure-cloudflare-email-routing-with-gmail-to-send-and-receive-mails-382j) |
| **Zoho Mail Forever Free** | 0 € | bis 5 Nutzer, 5 GB, 1 Domain; kein IMAP/POP, nur Web/App, je nach Region [Zoho](https://www.zoho.com/mail/zohomail-pricing.html) |
| **Google Workspace Business Starter** | 6,80 €/Nutzer (Jahr) bzw. 8,10 € (monatlich) | „echtes Gmail“ mit eigener Domain + Drive, Kalender, Meet. Für 2 Personen ~14–16 €/Monat [Google](https://knowledge.workspace.google.com/admin/billing/compare-flexible-and-annual-fixed-term-payment-plans?hl=de) |

**Empfehlung:** Start mit Cloudflare-Routing (gratis) → sobald erste Kunden zahlen: Google Workspace.

### Einrichtung Google Workspace (Kurzfassung)
1. workspace.google.com → „Jetzt starten“ → „Ich habe bereits eine Domain“ → `klausgard.de`.
2. Domain bestätigen: TXT-Eintrag in Cloudflare-DNS einfügen.
3. MX-Eintrag setzen: `smtp.google.com` (Priorität 1) – alte MX löschen.
4. **SPF** (TXT): `v=spf1 include:_spf.google.com ~all` (nur EIN SPF-Eintrag pro Domain!).
5. **DKIM**: im Admin-Center erzeugen → als TXT `google._domainkey` eintragen.
6. **DMARC** (TXT `_dmarc`): `v=DMARC1; p=none; rua=mailto:dmarc@klausgard.de` – später auf `quarantine`.
7. Nutzer anlegen: `jay@`, `kumpel@`, Alias `info@`, `rechnung@`, `support@`.
Ohne SPF/DKIM/DMARC landen Mails bei Gmail/Yahoo im Spam.

## 8. Kostenfahrplan

| Phase | Was | Kosten/Monat |
|---|---|---|
| 0 – Start | Domain .de+.com, Cloudflare gratis, Pages, Mail-Routing | **~1–2 €** |
| 1 – erste Kunden | + VPS 8 GB + Coolify, Google Workspace 2 Nutzer | **~25–35 €** |
| 2 – Wachstum | + Backup-Speicher, Abrechnung (Blesta ~17 €), zweiter Server | **~60–100 €** |
| 3 – Plattform | Cloudflare for SaaS, Lastverteilung, ggf. dedizierter Server | nach Kundenzahl |

Rechnung: 20 Kunden × 29 €/Monat = 580 € Umsatz bei ~35 € Kosten.

## 9. Offene Fragen an den Nutzer
- Ist „Larendo“ = **Lieferando** (Plattform-Prinzip)? Sonst bitte Link/Schreibweise.
- Sollen Kundenseiten einfach (statisch) oder mit Shop/Buchung (dynamisch) sein? → entscheidet die Serverwahl.
- Wer bekommt welche Mailadresse?
