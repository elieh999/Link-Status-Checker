# Changelog

## 3.0.0

* Added the Healthy, Degraded, Unhealthy, Maintenance, and Unknown status
  model.
* Added clickable website URLs with protocol validation.
* Added plain SSL and network problem explanations with recommended actions.
* Added SQLite history, versioned schema setup, uptime calculations, latency
  statistics, certificate snapshots, and incident tracking.
* Added the Overview, Websites, IIS, Database, History, and Settings pages.
* Added status filters, search, pagination, and lightweight latency sparklines.
* Changed the Websites page to one full page scroll so every card keeps its
  full height without a separate dashboard scrollbar.
* Fixed startup with monitoring history created by older versions that stored
  timestamps without timezone information.
* Removed the 50 website cap. The tested target is 2,000 saved websites with 50
  rendered cards per page.
* Moved writable data to `%LOCALAPPDATA%\LinkStatusChecker`.
* Embedded the light theme and application icon in the one file executable.
* Added a reproducible PyInstaller spec, Windows build script, frozen smoke
  test, benchmark, and GitHub Actions workflow.
* Kept CSV import, CSV export, IIS controls, SQL Server metadata, Windows
  Integrated Authentication, and the existing security restrictions.
