from __future__ import annotations

import os
import subprocess


def _hidden_process_kwargs() -> dict[str, int]:
    """Keep console-based Windows helpers invisible when called by the GUI."""

    if os.name != "nt":
        return {}
    return {"creationflags": subprocess.CREATE_NO_WINDOW}
