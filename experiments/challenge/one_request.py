#!/usr/bin/env python3
"""Send one request immediately, then EOF, to a persistent adapter in a fresh process."""
import subprocess,sys
from pathlib import Path
result=subprocess.run(sys.argv[2:],input=Path(sys.argv[1]).read_bytes())
raise SystemExit(result.returncode)
