#!/usr/bin/env python3
"""
Splunk custom REST bridge (stub).

Forwards authenticated Splunk session context to the agtsmith sidecar.
Expand with splunklib or cherrypy handlers as the app matures.
"""

from __future__ import annotations

SIDECAR_BASE = "http://127.0.0.1:8787"
