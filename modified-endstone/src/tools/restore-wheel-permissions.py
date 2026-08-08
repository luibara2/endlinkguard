"""Restore Unix file modes after repacking a Linux Endstone wheel on Windows."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path
from zipfile import ZipFile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("official_wheel", type=Path)
    parser.add_argument("custom_wheel", type=Path)
    args = parser.parse_args()

    with ZipFile(args.official_wheel, "r") as official:
        official_info = {item.filename: item for item in official.infolist()}

    temporary_fd, temporary_name = tempfile.mkstemp(
        prefix=args.custom_wheel.stem + "-permissions-",
        suffix=".whl",
        dir=args.custom_wheel.parent,
    )
    os.close(temporary_fd)
    temporary = Path(temporary_name)

    try:
        with ZipFile(args.custom_wheel, "r") as source, ZipFile(temporary, "w") as target:
            for item in source.infolist():
                reference = official_info.get(item.filename)
                if reference is not None:
                    item.create_system = reference.create_system
                    item.external_attr = reference.external_attr
                target.writestr(item, source.read(item.filename))

        with ZipFile(temporary, "r") as repaired:
            crashpad = repaired.getinfo("endstone/crashpad_handler")
            mode = (crashpad.external_attr >> 16) & 0xFFFF
            if crashpad.create_system != 3 or mode & 0o111 == 0:
                raise RuntimeError(
                    "endstone/crashpad_handler is not executable after permission repair"
                )

        temporary.replace(args.custom_wheel)
        print(f"Repaired {args.custom_wheel}")
        print(f"endstone/crashpad_handler mode: {mode:o}")
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
