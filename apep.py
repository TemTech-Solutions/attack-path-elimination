"""Same commands as python -m pathfinder.

Example:
    python apep.py find-path path\\to\\repository --from public-endpoint --to secret
"""

from pathfinder.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
