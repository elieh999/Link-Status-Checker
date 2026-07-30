# Release checklist

Recorded on 30 July 2026 on Windows 11 with Python 3.12.10.

## Baseline

* Existing tests: 147 passed and 1 skipped
* Ruff: passed
* Executable: 65,215,121 bytes
* Saved website limit: 50
* History: CSV plus 500 rows in memory
* Theme: external `theme_light.qss`

## Performance benchmark

Synthetic data was used so the test did not send requests to real websites.

* Saved 2,000 website records in 0.0163 seconds
* Wrote 100,000 check rows in 3.5576 seconds
* Calculated analytics over 100,000 rows in 0.8707 seconds
* Loaded and rendered 1,000 saved websites in 1.4590 seconds
* Filtered 1,000 websites in 0.3918 seconds
* Visible card limit: 50

The machine reported an Intel64 Family 6 Model 186 processor.

## Packaged checks

The executable was copied to an empty temporary folder with no QSS or project
files beside it.

* Window construction: passed
* Embedded theme: passed
* SQLite initialization: passed
* Six page navigation: passed
* SQL Server packaged read: passed against `.\test`
* Database returned: `test`, 16.00 MB, 1 table, 5 columns
* Full test collection: 182
* Tests passed: 181
* Optional tests skipped: 1
* Ruff: passed
* Formatting check: passed
* Final executable: 54,925,925 bytes
* Size reduction: 10,289,196 bytes, or 15.78%
* SHA256: `F246A31ADC53B5F8181D36FDE99151C4BE8FDCD378A490897E27BDD7270C163D`

## Known limits

* Public network behavior depends on the local DNS, proxy, firewall, and remote
  servers.
* IIS actions that change service state need the Windows permissions required
  by Service Control Manager.
* SQL Server testing used the local `.\test` instance. Other server
  configurations still depend on their certificates, network access, and
  Windows permissions.
* Custom analytics date ranges, retention cleanup, JSON response assertions,
  redirect controls, per website schedule overrides, and a dedicated last
  incident date filter remain in the backlog.
