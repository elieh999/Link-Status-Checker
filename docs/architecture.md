# Architecture

`main.py` stays small so old launch commands and imports keep working. The
application code lives under `src/link_status_checker`.

The domain layer owns health rules and status decisions. It does not import
PySide6, which keeps status tests fast and predictable.

The monitoring layer turns SSL and network exceptions into a `CheckProblem`.
The user sees the title, explanation, and recommended action. Technical details
are kept separately.

The storage layer owns SQLite schema setup, website records, check history,
incidents, recent latency samples, and analytics. Schema version `1` is applied
automatically on first launch. The database uses foreign keys, WAL mode, and
indexes on website, status, time, and open incidents.

The UI layer contains the clickable URL label, five state status strip,
sparkline, and metric card. The main window combines those widgets with the
existing IIS and SQL Server integrations.

Network checks run in a bounded `QThreadPool`. The UI creates at most 50 website
cards for the current page instead of building a widget for every saved
website.

Writable files are kept in `%LOCALAPPDATA%\LinkStatusChecker`. Packaged
resources are read from PyInstaller's temporary resource directory, so the
executable remains styled when copied by itself.
