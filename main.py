from __future__ import annotations

import sys

from src.link_status_checker import application as _application

if __name__ == "__main__":
    raise SystemExit(_application.main())

# Existing integrations and tests import ``main`` directly. Returning the real
# application module keeps that public surface intact while this launcher stays
# deliberately small.
sys.modules[__name__] = _application
