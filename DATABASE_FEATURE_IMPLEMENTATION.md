# Database Feature Implementation

## Summary

The application now includes a secure, read-only database metadata section directly below the IIS Service Control section.

This version targets Microsoft SQL Server 2025. SQL Server Management Studio 22 is used for server setup, permission checks, and manual admin testing. The Python application itself connects through Microsoft's `mssql-python` package, not through ODBC or `pyodbc`.

The feature can read:

- database name
- SQL Server instance name, when returned by SQL Server
- database size in MB
- schemas
- tables
- row count metadata from SQL Server system catalogs
- column names
- column data types
- column lengths
- nullable status
- last successful read time
- connection or permission errors

## Files Modified

- `main.py`
  - Added SQL Server database metadata models.
  - Added a background metadata worker so the GUI does not freeze.
  - Added `mssql-python` connection logic.
  - Added Windows Integrated Authentication connection settings.
  - Added fixed read-only SQL Server metadata queries.
  - Added a Database Metadata UI section below IIS.
  - Added database metadata logging.

- `theme_light.qss`
  - Added styling for the database panel, provider label, security note, status box, summary box, and subpanels.

- `requirements.txt`
  - Added `mssql-python`.

- `config.example.yaml`
  - Added an example SQL Server 2025 configuration without usernames or passwords.

- `README.md`
  - Updated the database section and run/build instructions.

## Runtime And Admin Tools

The application uses two separate tools for two separate jobs:

- `mssql-python`: the Python runtime package used by the app to connect to SQL Server.
- SSMS 22: the admin tool used by the trainer or database admin to create users, grant permissions, and test SQL Server access.

SSMS is not embedded in the app and is not a Python driver. It is used to prepare and verify the SQL Server environment.

## Authentication Method Used

The implemented method is SQL Server Windows Integrated Authentication.

The connection string uses this pattern:

```text
Server=YOUR_SERVER_NAME;
Database=YOUR_DATABASE_NAME;
Trusted_Connection=Yes;
Encrypt=Yes;
TrustServerCertificate=No;
ApplicationIntent=ReadOnly;
```

For a local test SQL Server with a self-signed or untrusted certificate, the GUI includes a checkbox named `Trust server certificate for local test`. When checked, the app uses `TrustServerCertificate=Yes`. Leave this unchecked for production unless the database administrator approves it.

The actual timeout is passed to `mssql-python` as a connection option from the code.

No username or password fields exist in the UI.

No username or password is stored in source code, config files, logs, or environment variables.

## Why This Is Secure

Windows Integrated Authentication avoids application-managed passwords. SQL Server authenticates the Windows identity running the application.

For a desktop run, that identity is the signed-in Windows user.

For IIS or server hosting, the identity should be one of these:

- a dedicated IIS Application Pool Identity
- a dedicated domain service account
- preferably a Group Managed Service Account, if the company supports it

The app also:

- uses encrypted SQL Server connections
- does not trust invalid server certificates by default
- does not accept arbitrary SQL
- uses fixed metadata-only queries
- does not include insert, update, delete, drop, truncate, alter, or execute actions
- does not log connection strings or secrets
- validates server and database input before building the connection string

## Required Database Permissions

Grant only the minimum permissions required for metadata reading.

In SSMS 22, connect as an admin and run a script like this after replacing the account name:

```sql
USE [master];
GO

CREATE LOGIN [DOMAIN\AccountName] FROM WINDOWS;
GO

USE [YOUR_DATABASE_NAME];
GO

CREATE USER [DOMAIN\AccountName] FOR LOGIN [DOMAIN\AccountName];
GO

GRANT CONNECT TO [DOMAIN\AccountName];
GRANT VIEW DEFINITION TO [DOMAIN\AccountName];
GO
```

If row count metadata or table-level metadata is restricted in your environment, grant `SELECT` only on the specific schemas or tables that the trainer or database admin approves:

```sql
GRANT SELECT ON SCHEMA::dbo TO [DOMAIN\AccountName];
```

Avoid:

- `sysadmin`
- `db_owner`
- `db_datawriter`
- broad server-level permissions

## Setup Instructions

1. Install or use SQL Server 2025.
2. Install SSMS 22 for administration and manual testing.
3. Use SSMS 22 to create the Windows login/user and grant the permissions listed above.
4. Run the app.
5. In the Database Metadata section:
   - confirm the provider says `SQL Server 2025 / mssql-python`
   - enter server or instance name
   - enter database name
   - for a local test instance with a certificate trust error, check `Trust server certificate for local test`
   - click `Read Metadata`

## How The Database Section Works

The UI sends the server and database name to a background worker.

The worker validates those values and creates a passwordless `mssql-python` connection using Windows Integrated Authentication.

The worker reads SQL Server system catalog metadata using fixed `SELECT` queries:

- `sys.database_files`
- `sys.schemas`
- `sys.tables`
- `sys.columns`
- `sys.partitions`
- `sys.allocation_units`

The result is sent back to the GUI and displayed in:

- status box
- summary box
- tables table
- columns table

## Logs

Database metadata reads are logged to:

```text
logs/database_metadata.csv
```

The log contains:

- timestamp
- authentication method
- database name
- table count
- schema count
- database size
- result
- message

The log does not contain usernames, passwords, tokens, or connection strings.

## Testing

Tested in this implementation:

- app imports and compiles
- `mssql-python` imports successfully
- database settings validation accepts normal server and database names
- database settings validation rejects connection-string injection characters
- connection string generation contains integrated authentication and no username/password fields
- connection string generation does not include ODBC driver syntax
- local SQL Server test connection succeeds when the local certificate-trust option is enabled
- SQL metadata worker returns a clean error for invalid or unreachable database settings
- GUI starts with the Database section below IIS
- Database UI controls render correctly
- existing IIS controls still initialize
- existing website checks still work
- executable launches successfully

Live database success testing requires a real SQL Server 2025 instance and a Windows identity with the required permissions.

## Troubleshooting

### mssql-python is not installed

Install dependencies:

```powershell
py -m pip install -r requirements.txt
```

### Login failed

The Windows identity running the app does not have SQL Server access. In SSMS 22, grant `CONNECT` and `VIEW DEFINITION` to that Windows account.

### Certificate or TLS error

The app uses encrypted SQL connections and does not trust invalid server certificates by default. Install a trusted SQL Server certificate or configure the SQL Server TLS chain correctly.

### Permission denied while reading metadata

Grant the minimum metadata permission:

```sql
GRANT VIEW DEFINITION TO [DOMAIN\AccountName];
```

## Limitations And Assumptions

- The implemented database target is Microsoft SQL Server 2025.
- The Python runtime connector is `mssql-python`.
- SSMS 22 is used for SQL Server administration, not as the application runtime connector.
- Authentication is Windows Integrated Authentication.
- Azure Managed Identity is not implemented in this desktop build because it requires cloud identity configuration and Azure-specific libraries.
- The feature reads metadata only. It does not read table data.
- Row counts are metadata-based and may not always match an immediate exact `COUNT(*)`.

## Security Confirmation

- Username/password authentication was not used.
- No username/password UI fields were added.
- No credentials are stored in source code, config, environment variables, or logs.
- The feature is read-only.
- SQL statements are fixed metadata `SELECT` queries.
- The application does not expose commands that modify database data or schema.
