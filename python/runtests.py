import pytest
import sys
import os

try:
    import _clippy
except ImportError:
    sys.stderr.write(
        """these tests need to be run with the _clippy C extension
module available.  Try running "clippy runtests.py ...".
"""
    )
    sys.exit(1)

os.chdir(os.path.dirname(os.path.abspath(__file__)))
raise SystemExit(pytest.main(sys.argv[1:]))
