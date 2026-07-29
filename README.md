# Link Status Checker

Link Status Checker is a light-theme Windows desktop dashboard for checking website availability, DNS resolution, HTTPS response, SSL certificate health, and IIS service status.

The app is built with Python and PySide6. The visual theme is stored in `theme_light.qss`.

## Features

- Add one website at a time or paste many websites, one per line.
- Load websites from a CSV file.
- Normalize entered `http://` or bare domains to `https://`.
- Display website cards in a fixed two-column grid.
- Show domain, IP address, DNS status, active/inactive status, HTTPS status, SSL status, certificate expiry, response time, and last checked time.
- Check all websites concurrently without freezing the GUI.
- Start and stop scheduled monitoring.
- Log website checks to `logs/checks.csv`.
- Export visible check history to CSV.
- Check, start, or restart allowlisted IIS services on Windows.
- Log IIS actions to `logs/iis_actions.csv`.
- Read Microsoft SQL Server 2025 database metadata using Windows Integrated Authentication.
- Show database size, schemas, tables, row-count metadata, and column metadata.

## Run The App

Use the packaged executable:

```text
LinkStatusChecker.exe
```

The executable version does not require Python to be installed.

## Run From Source

Python 3.10 or newer is recommended.

```powershell
py -m pip install -r requirements.txt
py main.py
```

## Adding Websites

Use the `URL` field for one website, or paste multiple websites into `Paste URLs`, one per line.

Examples:

```text
google.com
openai.com
https://example.com
http://test.com
```

The app checks them as:

```text
https://google.com
https://openai.com
https://example.com
https://test.com
```

## DNS And IP Lookup

Each check resolves the website domain using Python's `socket.getaddrinfo()` API.

The dashboard shows:

- `IP`: the first resolved IP address.
- `DNS`: `RESOLVED` or `FAILED`.
- Tooltips/logs include all resolved IPs or the DNS error.

DNS data is saved in `logs/checks.csv` with these fields:

```text
domain, primary_ip, all_resolved_ips, dns_status, dns_error
```

## HTTPS And SSL

The app sends an HTTPS request to confirm the website responds.

Availability is intentionally simple:

- `ACTIVE`: the website responded over HTTPS.
- `INACTIVE`: DNS failed, the request timed out, or the connection failed.

SSL statuses include:

- `SSL VALID`
- `SSL EXPIRES SOON`
- `SSL EXPIRED`
- `SSL NOT YET VALID`
- `SSL ERROR`

## IIS Service Control

The IIS controls are Windows-only. The app only allows fixed service names:

- `W3SVC` - World Wide Web Publishing Service
- `WAS` - Windows Process Activation Service

Start and restart actions may require running the app as administrator. The app does not accept custom commands and does not execute service actions through a command shell.

## Database Metadata

The Database Metadata section is read-only and appears directly below IIS Service Control.

It targets Microsoft SQL Server 2025 and uses the Microsoft `mssql-python` runtime package. SSMS 22 is used only for SQL Server setup, permission grants, and manual admin testing. The app does not accept, store, hash, encrypt, or log database usernames or passwords.

For local test SQL Server instances with self-signed certificates, the database panel includes a `Trust server certificate for local test` checkbox. Keep it unchecked for production unless the database administrator approves it.

The feature can show database size, schemas, tables, row-count metadata, and columns. See `DATABASE_FEATURE_IMPLEMENTATION.md` for setup, permissions, security details, and troubleshooting.

## Logs

Website checks are written to:

```text
logs/checks.csv
```

IIS actions are written to:

```text
logs/iis_actions.csv
```

Secrets are not stored in the logs.

Database metadata reads are written to:

```text
logs/database_metadata.csv
```

## Build The Executable

```powershell
py -m venv .venv
.\.venv\Scripts\activate
py -m pip install -r requirements.txt pyinstaller
py -m PyInstaller --noconfirm --clean --onefile --windowed --name LinkStatusChecker main.py
```

## Project Files

```text
LinkStatusChecker.exe
main.py
theme_light.qss
config.example.yaml
DATABASE_FEATURE_IMPLEMENTATION.md
README.md
requirements.txt
logs/
```
