import os
import sys

# Ensure the project root is importable when pytest is run from anywhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TARGET = os.environ.get("INFILTR_TEST_TARGET", "http://localhost:8080")
