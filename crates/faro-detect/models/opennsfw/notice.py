"""Write the OpenNSFW notice for the package, from the model manifest.

    python3 -I notice.py --license LICENSE.md --out NOTICE.txt MANIFEST...

Checks first that Yahoo's LICENSE.md is word for word the `license_text`
of every manifest given, so the text that travels with the model is the
upstream's own. The notice is the first manifest's attribution followed by
that text (which starts with the copyright notice).
"""

import argparse
import json
import sys
from pathlib import Path


def render(m):
    a = m["attribution"]
    lines = [
        f"OpenNSFW image classifier ({m['name']} {m['version']})",
        "",
        f"Faro's on-device image classifier is OpenNSFW by {a['author']}, used",
        f"under the {m['license']} licence below.",
        "",
        f"Source:  {a['source_url']}",
        f"Licence: {a['license_url']}",
        f"Changes: {a['changes']}",
        "",
        m["license_text"],
        "",
    ]
    return "\n".join(lines)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--license", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("manifests", nargs="+", type=Path)
    a = ap.parse_args(argv)
    upstream = a.license.read_text().strip()
    manifests = [json.loads(p.read_text()) for p in a.manifests]
    for p, m in zip(a.manifests, manifests):
        if m.get("license_text") != upstream:
            print(f"{p}: license_text is not the upstream LICENSE.md", file=sys.stderr)
            return 1
        if not all(c in upstream for c in m["attribution"]["copyright"]):
            print(f"{p}: a copyright line is not in the upstream LICENSE.md", file=sys.stderr)
            return 1
    a.out.write_text(render(manifests[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
