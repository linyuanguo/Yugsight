# Yugsight (御视) · Network Scanning & Probing Tool

**English** | [简体中文](README.md)

> This page is a brief English overview: intro, quick start and build only.
> Feature details: [README.md](README.md) (Chinese).

Yugsight is a network scanning and probing tool written in Go and shipped as a single executable with an embedded Vue3 Web UI (the browser opens automatically on startup). It runs fully offline — apart from YAML parsing (`gopkg.in/yaml.v3`, used for Nuclei templates) everything is built on the Go standard library, with no external service or runtime front-end assets.

- **Center**: one executable containing the Web UI and the full scanning capability; it works with no external engine installed.
- **Probe agent**: a separate small binary (`yugsight-agent.exe`) deployed on the machines to be scanned. It opens a single outbound connection to the center and listens on no inbound port.

> **Authorized use only.** Scan only systems you own or have written permission to test.

## Quick Start

1. Run `yugsight_windows_amd64.exe` (the first launch requests UAC elevation, so the PID changes once — this is expected).
2. The browser opens `http://<your-ip>:8420` (Vue3 UI at `/app/`; the classic single-file UI remains at `/classic/`).
3. Log in with the initial account `admin / admin123` (created on first run, configurable in the `auth` section of `settings.json`).
4. Pick a module, fill in the parameters, click **Start Scan** — results stream in live.
5. Click **Generate Report** to export an HTML report.

- The service binds `0.0.0.0:8420` by default, so both `http://127.0.0.1:8420` and `http://<your-ip>:8420` work (use `-bind-local` to bind the LAN IP only).
- The program stays resident as a **console window** (auto-minimized). Closing the window does **not** stop the service: use the "Stop service" link on the login page, the one on the License page (`/api/quit`, no login required), or press Ctrl+C in the console.
- Live packet capture requires Npcap: click the install button in the UI (it uses the official `npcap-1.86.exe` shipped next to the executable).
- External engines (nmap / trivy / ZAP / nuclei) are optional; the built-in engine works on its own. Install them from the **Engines & Rules** page.

## Build

Requires Go 1.25+; Node 20+ if you modify the front end.

```powershell
# Recommended: build script (injects icon and version, multi-platform, versioned output name)
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -OutDir dist

# Manual build (current platform only; the main package lives in app/)
go build -trimpath -ldflags "-s -w" -o yugsight_windows_amd64.exe ./app

# Probe agent = separate binary
go build -trimpath -ldflags "-s -w" -o yugsight-agent.exe ./cmd/agent
```

The front end **must be rebuilt before the back end** (its output is embedded into the executable via `go:embed`):

```bash
cd app/frontend && npm install && npm run build
cd ../.. && powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -OutDir dist
```

- `app/frontend/dist/` is committed to the repository and is the embed source; `go build` fails outright if it is missing.
- The version comes from the `VERSION` file: the build script bumps the last digit and injects it via `-ldflags -X main.appVersion=` (the linker always addresses the main package as `main`, regardless of its directory).

## License

MIT, see [LICENSE](LICENSE).
