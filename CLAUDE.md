# CLAUDE.md

@standards/rules/coding-general.md
@standards/rules/skill-graphify.md

---

## fief-Fork: Ziel

Dieses Repo ist ein Fork von [fief](https://github.com/fief-dev/fief) (letzter Upstream-Commit: 2025-04-26).
Wir entwickeln fief **nicht weiter**. Erlaubt sind nur:

1. **Sicherheitsrelevante Fixes** — inkl. Updates veralteter Abhängigkeiten mit bekannten Schwachstellen.
2. **Anpassungen der Login-Seite** (Templates, Styles, Texte) an unsere Bedürfnisse.

Alles andere (Refactorings, neue Features, Aufräumarbeiten) ist außerhalb des Scopes — erst fragen.

## fief-Fork: Abweichungen vom Standard (MANDATORY)

Diese Regeln gehen den importierten dev-standards-Regeln vor:

| dev-standards-Regel | Gilt in fief | Stattdessen |
|---|---|---|
| Ratchet-Prinzip / Boy-Scout-Rule | **nein** | Minimaler Diff zum Upstream. Nur ändern, was der Fix braucht. |
| Style-Skills `/backend`, `/frontend` | **nein** | fiefs eigener Stil: umliegenden Code nachahmen. |
| Ampel-Quality-Gate (`maintain_tools.py --mode commit`) | **nein** | `hatch run lint-check` + `hatch run test` müssen grün sein, dazu ein Code-Review. |
| Node-Tools (biome, jscpd, knip, eslintcc) in `package.json` | **nein** | `package.json` / `package-lock.json` gehören zu fiefs Frontend-Build und bleiben frei von Standards-Tools. |
| Repo-Guard `.github/workflows/guard.yml` | **nein** | Nicht committen (`repo_guard: false`), er braucht Zugriff auf das private dev-standards-Repo. |

Läuft `maintain_tools.py --setup` erneut und legt eines davon wieder an (devDependencies, `guard.yml`), wird es zurückgenommen.

## fief-eigener Standard

- **Python:** `ruff format`, `ruff check` (Regeln `I`, `TRY`, `UP`) und `mypy fief/` — `hatch run lint` (fix) / `hatch run lint-check` (prüfen).
- **Tests:** `hatch run test` (pytest).
- **Frontend:** Jinja-Templates (`fief/templates/`), Tailwind + Sass (`styles/`), JS (`js/`), gebaut über `npm run build` (rollup) bzw. `hatch run static.build`.
- **Übersetzungen:** Geänderte Texte auf der Login-Seite brauchen `hatch run translations.update` und `hatch run translations.compile`.
- **Abhängigkeits-Updates:** Ein Update pro Schwachstelle bzw. Paketgruppe, jeweils mit grünen Tests. Major-Upgrades vorher absprechen.
