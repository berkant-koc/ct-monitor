"""Make ct_monitor importable from the tests/ subdirectory without packaging."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
