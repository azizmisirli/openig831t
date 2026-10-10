# SPDX-License-Identifier: Apache-2.0
"""Offline-only command wrapper; no USB or network access."""
import sys
from igbridge.cli import main
if __name__ == "__main__":
    raise SystemExit(main(["parse-qmi", *sys.argv[1:]] if len(sys.argv) > 1 else ["dry-run"]))
