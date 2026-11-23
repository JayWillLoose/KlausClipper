# Tool-Recherche (Stand: November 2026)

Ziel: die besten (möglichst kostenlosen) Werkzeuge für autorisierte, rate-limitierte
Sicherheitsprüfung. Viele Quellen sind Hersteller- oder Blog-Vergleiche – die
Bewertungen sind Richtwerte, keine harten Benchmarks.

## Empfohlener Werkzeugkasten

| Bereich | Tool | Warum | Kosten |
|---|---|---|---|
| Code-Analyse, schnell | **Semgrep** (OSS) | Einfache, eigene Regeln → ideal für Variantensuche aus gefundenen Bugs | gratis |
| Code-Analyse, tief | **CodeQL** | Semantische Datenfluss-Analyse; gratis für öffentliche Repos | gratis (öffentlich) |
| Python-spezifisch | **Bandit** | Klassische Python-Sicherheitsfehler | gratis |
| Abhängigkeiten | **OSV-Scanner** + **pip-audit** | OSV mit wenigen Fehlalarmen in Tests; pip-audit schnell für Python | gratis |
| Container / IaC | **Trivy** | Images, Pakete, Fehlkonfigurationen | gratis |
| Geheimnisse im Code | **Gitleaks** / **TruffleHog** | Eingecheckte Keys/Passwörter (Vergleich noch nicht recherchiert) | gratis |
| Web-Scan (DAST) | **ZAP** Automation Framework | YAML-Pläne mit Login, Crawl, Scan, Report – gut skriptbar | gratis |
| Bekannte Lücken | **Nuclei** | Template-basiert; **unbedingt `-rate-limit` setzen** (Standard 150/s!) | gratis |
| API-Fuzzing | **Schemathesis** | Erzeugt Tests aus OpenAPI/GraphQL-Schema | gratis (MIT) |
| API-Fuzzing, zustandsbehaftet | **RESTler** | Abfolgen wie POST → GET → DELETE | gratis |
| Python-Fuzzing | **Atheris** | Coverage-gesteuertes Fuzzing von Python-Funktionen | gratis |
| Manuell / Autorisierung | **Burp Suite** Pro | Standard für manuelle Tests | ca. 400–450 $/Jahr |
| KI-Triage (Vorbild) | **GitHub seclab-taskflow-agent** | YAML-Taskflows, LLM triagiert CodeQL-Alerts | gratis |
| KI-Bugsuche (Vorbild) | **OpenAnt** (Knostic) | LLM zerlegt Code, prüft Funde gegenseitig, testet dynamisch | gratis, teils Beta |

## Wichtige Erkenntnisse

1. **Semgrep für jeden Commit, CodeQL nächtlich** – mehrere Quellen empfehlen diese
   Kombination.
2. **IDOR / Zugriffsrechte findet kein Scanner allein.** ZAP oder Burp können eine
   ID hochzählen, verstehen aber keine Rollen. Lösung: Anfragen als mehrere
   Testnutzer mit verschiedenen Rollen senden und Antworten vergleichen – genau
   hier ist ein LLM stark.
3. **Rate-Limits sind Pflicht.** Intigriti-Programme verlangen oft 2–10 Anfragen/s;
   Verstöße führen zur Sperre. Nuclei-Standard ist 150/s → immer drosseln.
   Viele Programme verlangen einen eigenen HTTP-Header zur Kennzeichnung.
4. **Häufigste Klassen:** In Bug-Bounty-Programmen ist XSS am häufigsten; unter
   den kritischen Funden stehen Fehlkonfiguration, serverseitige Injection und
   fehlerhafte Zugriffskontrolle vorn (Bugcrowd).
5. **KI-Agenten sind nützlich, aber nicht magisch:** Im CyberGym-Benchmark
   reproduzieren Spitzen-Agenten nur 17–22 % der Ziel-Lücken. Am besten wirken
   LLMs mit eingegrenzter Analyse **plus** dynamischer Bestätigung.
6. **LLM schreibt Suchregeln:** QLCoder (Forschung) lässt Claude Code aus
   CVE-Beschreibungen CodeQL-Abfragen schreiben; 53,4 % erkennen die Lücke korrekt.
   Das ist die Grundlage unserer Variantensuche.

## Quellen

- [Sourcegraph: Static Code Analysis Tools 2026](https://sourcegraph.com/blog/static-code-analysis-tools)
- [Semgrep vs CodeQL 2026 (DEV)](https://dev.to/rahulxsingh/semgrep-vs-codeql-lightweight-patterns-vs-semantic-analysis-for-sast-2026-412k)
- [Wiz: Top 28 Open-Source Code Security Tools](https://www.wiz.io/academy/application-security/open-source-code-security-tools)
- [Aikido: CodeQL-Alternativen](https://www.aikido.dev/blog/top-codeql-alternatives)
- [Intigriti: Understanding rate limiting](https://kb.intigriti.com/en/articles/5678905-understanding-rate-limiting)
- [Intigriti: Aggressive scanning in bug bounty](https://www.intigriti.com/researchers/blog/hacking-tools/aggressive-scanning-in-bug-bounty-and-how-to-avoid-it)
- [Intigriti: Rules of engagement](https://kb.intigriti.com/en/articles/5317169-rules-of-engagement-testing-requirements)
- [Automated scanning without getting banned](https://bug-bounties.as93.net/learn/automated-vulnerability-scanning-in-bounties)
- [Nuclei Docs: Running](https://docs.projectdiscovery.io/tools/nuclei/running)
- [ProjectDiscovery: Ultimate Nuclei Guide](https://projectdiscovery.io/blog/ultimate-nuclei-guide)
- [Aikido: Burp Suite vs ZAP](https://www.aikido.dev/blog/burp-suite-vs-owasp-zap)
- [DAST Testing Guide: ZAP vs Burp](https://helpmetest.com/blog/dast-testing-guide/)
- [Wiz: ZAP Overview](https://www.wiz.io/academy/zed-attack-proxy-zap-overview)
- [HackerOne Top 10](https://www.hackerone.com/top-ten-vulnerabilities)
- [Bugcrowd Top 10](https://www.bugcrowd.com/resource/top-10-vulnerabilities/)
- [Patchstack Mid-Year 2025](https://patchstack.com/whitepaper/2025-mid-year-vulnerability-report/)
- [Schemathesis (PyPI)](https://pypi.org/project/schemathesis/)
- [Schemathesis-Paper (arXiv)](https://arxiv.org/abs/2112.10328)
- [Best open-source SCA tools 2026](https://safeguard.sh/resources/blog/best-open-source-sca-tools-in-2026-tested-on-a-real-monorepo)
- [AppSecSanta: SCA tools for Python](https://appsecsanta.com/sca-tools/sca-tools-for-python)
- [GitHub Blog: seclab taskflow framework](https://github.blog/security/community-powered-security-with-ai-an-open-source-framework-for-security-research/)
- [GitHub Blog: AI-supported triage](https://github.blog/security/ai-supported-vulnerability-triage-with-the-github-security-lab-taskflow-agent/)
- [QLCoder (arXiv)](https://arxiv.org/html/2511.08462v2)
- [OpenAnt (Knostic)](https://www.knostic.ai/blog/openant)
- [OpenAnt-Paper (arXiv)](https://arxiv.org/pdf/2606.19149)
- [AppSecSanta: AI Pentesting Agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026)
- [Awesome Offensive AI Agentic Landscape](https://github.com/Yeti-791/Awesome-Offensive-AI-Agentic-Landscape)
- [Agents to the Hunt (arXiv)](https://arxiv.org/pdf/2610.14729)
