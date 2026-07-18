from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import analyze


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only IAM least-privilege policy audit")
    parser.add_argument("policy", type=Path, help="Path to an AWS IAM policy JSON document")
    args = parser.parse_args()
    print(json.dumps(analyze(json.loads(args.policy.read_text(encoding="utf-8"))), indent=2))


if __name__ == "__main__":
    main()
