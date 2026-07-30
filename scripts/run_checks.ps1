$ErrorActionPreference = "Stop"

py -m ruff check .
py -m ruff format --check .
py -m pytest -m "not network"
