#!/usr/bin/env python3
"""Run the regression suite and fail even if a blocked network call was caught."""
import pathlib
import sys
import unittest
from unittest.mock import patch


def main():
    with patch("socket.socket.connect", side_effect=OSError("network disabled in offline tests")) as connect:
        suite = unittest.defaultTestLoader.discover(str(pathlib.Path(__file__).parent))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"Real socket connection attempts: {connect.call_count}", file=sys.stderr)
    return int(not result.wasSuccessful() or connect.call_count != 0)


if __name__ == "__main__":
    sys.exit(main())
