from __future__ import annotations

import pytest

import main


def settings(server="SQLBOX\\TEST", database="metrics", trust=False):
    return main.DatabaseConnectionSettings(server=server, database=database, trust_server_certificate=trust)


@pytest.mark.parametrize(
    "server",
    [
        "SQLBOX",
        "SQLBOX\\SQLEXPRESS",
        "sql.internal.example.com",
        "sql.internal.example.com,1433",
        "10.0.0.5,1433",
    ],
)
def test_realistic_server_names_are_accepted(server):
    assert main.validate_database_settings(settings(server=server)) == ""


@pytest.mark.parametrize(
    "server",
    [
        "",
        "SQLBOX;Trusted_Connection=No",
        "SQLBOX'DROP",
        "SQLBOX{0}",
        "SQLBOX\nSecond",
        "x" * 200,
    ],
)
def test_server_names_that_could_tamper_with_the_connection_string_are_refused(server):
    assert main.validate_database_settings(settings(server=server)) != ""


@pytest.mark.parametrize("database", ["", "metrics;x", "met\nrics", "d" * 200, "metrics{}"])
def test_bad_database_names_are_refused(database):
    assert main.validate_database_settings(settings(database=database)) != ""


def test_connection_string_is_read_only_integrated_auth_with_no_credentials():
    built = main.build_integrated_sql_server_connection_string(settings())
    assert "Trusted_Connection=Yes" in built
    assert "ApplicationIntent=ReadOnly" in built
    assert "Encrypt=Yes" in built
    assert "TrustServerCertificate=No" in built
    # The whole point of the feature: no username or password ever appears.
    lowered = built.lower()
    assert "pwd=" not in lowered
    assert "password=" not in lowered
    assert "uid=" not in lowered


def test_trust_flag_is_reflected_in_the_connection_string():
    assert "TrustServerCertificate=Yes" in main.build_integrated_sql_server_connection_string(settings(trust=True))


def test_a_rejected_server_name_never_reaches_the_driver():
    with pytest.raises(ValueError):
        main.build_integrated_sql_server_connection_string(settings(server="SQLBOX;Encrypt=No"))


def test_error_text_hides_server_and_credential_details():
    exc = Exception("Login failed. Server=SECRETBOX;Database=payroll;UID=admin;PWD=hunter2;")
    safe = main.safe_database_error(exc)
    assert "SECRETBOX" not in safe
    assert "hunter2" not in safe
    assert "payroll" not in safe
    assert "[hidden]" in safe


def test_metadata_read_reports_a_clear_message_when_the_driver_is_missing(monkeypatch):
    monkeypatch.setattr(main, "import_mssql_python", lambda: None)
    result = main.read_sql_server_metadata(settings())
    assert result.success is False
    assert "mssql-python" in result.message


def test_metadata_read_refuses_an_invalid_server_before_connecting(monkeypatch):
    def must_not_be_called():
        raise AssertionError("the driver was reached with an invalid server name")

    monkeypatch.setattr(main, "import_mssql_python", must_not_be_called)
    result = main.read_sql_server_metadata(settings(server="SQLBOX;Encrypt=No"))
    assert result.success is False


def test_db_self_test_flag_without_a_value_does_not_crash(monkeypatch, tmp_path):
    """Regression: main() did sys.argv[sys.argv.index("--server") + 1], so
    ending the command line at --server raised IndexError."""
    monkeypatch.setattr(main.sys, "argv", ["main.py", "--db-self-test", "--server"])
    monkeypatch.setattr(main, "APP_DIR", tmp_path)
    monkeypatch.setattr(
        main,
        "read_sql_server_metadata",
        lambda s: main.DatabaseMetadataResult(
            "now", False, "auth", s.database, "", "", [], [], [], "", "could not connect"
        ),
    )

    exit_code = main.main()

    assert exit_code == 2
    assert (tmp_path / "db_self_test_result.txt").exists()


def test_db_self_test_uses_the_values_it_is_given(monkeypatch, tmp_path):
    seen = {}

    def fake_read(s):
        seen["server"] = s.server
        seen["database"] = s.database
        seen["trust"] = s.trust_server_certificate
        return main.DatabaseMetadataResult("now", True, "auth", s.database, "srv", "10", [], [], [], "now", "ok")

    monkeypatch.setattr(
        main.sys,
        "argv",
        [
            "main.py",
            "--db-self-test",
            "--server",
            "SQLBOX\\TEST",
            "--database",
            "metrics",
            "--trust-server-certificate",
        ],
    )
    monkeypatch.setattr(main, "APP_DIR", tmp_path)
    monkeypatch.setattr(main, "read_sql_server_metadata", fake_read)

    assert main.main() == 0
    assert seen == {"server": "SQLBOX\\TEST", "database": "metrics", "trust": True}


def test_database_row_value_falls_back_from_name_to_index():
    class RowWithAttribute:
        database_name = "by_attribute"

    assert main.database_row_value(RowWithAttribute(), "database_name", 0) == "by_attribute"
    assert main.database_row_value({"database_name": "by_key"}, "database_name", 0) == "by_key"
    assert main.database_row_value(["by_index"], "database_name", 0) == "by_index"
    assert main.database_row_value(None, "database_name", 0) is None
