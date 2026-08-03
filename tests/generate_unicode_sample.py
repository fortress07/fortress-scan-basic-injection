from __future__ import annotations

import io
import sys
from pathlib import Path

RLO = chr(0x202E)
PDI = chr(0x2069)
ZWSP = chr(0x200B)

TROJAN_SOURCE = (
    "def transfer(account, amount):\n"
    "    approved = False\n"
    "    if amount < 100:\n"
    "        approved = True\n"
    "    # " + RLO + " return approved " + PDI + " approved = True\n"
    "    return approved\n"
    "\n"
    "\n"
    "def check" + ZWSP + "_access(user):\n"
    "    return user.is_admin\n"
)


def write(destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with io.open(destination, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(TROJAN_SOURCE)
    return destination


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("samples/vulnerable/trojan.py")
    written = write(target)
    sys.stdout.write("wrote %s (%d bytes)\n" % (written, written.stat().st_size))
