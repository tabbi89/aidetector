"""Export the actual application contract without starting services or making requests."""
import json
import sys
from pathlib import Path

from app.main import app

if __name__ == "__main__":
    destination = Path(sys.argv[1])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(app.openapi(), indent=2) + "\n")
