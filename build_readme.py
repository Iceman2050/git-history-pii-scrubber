#!/usr/bin/env python3
"""Regenerate README.md's Example output block from a FRESH demo run.

Machine-verification: the block between <!-- DEMO-OUTPUT-START --> and
<!-- DEMO-OUTPUT-END --> is replaced byte-for-byte with the stdout of
`python3 pii_scrubber.py demo`. The test
test_readme_example_output_matches_fresh_demo_run re-runs the demo and
diffs it against the README block, so a stale README fails CI.
"""

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
START = "<!-- DEMO-OUTPUT-START -->"
END = "<!-- DEMO-OUTPUT-END -->"


def main():
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "pii_scrubber.py"), "demo"],
        capture_output=True, text=True, cwd=HERE,
    )
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        sys.exit("demo run failed -- README not updated")
    output = proc.stdout.rstrip("\n")
    block = "%s\n```\n%s\n```\n%s" % (START, output, END)

    readme = os.path.join(HERE, "README.md")
    with open(readme) as fh:
        content = fh.read()
    pattern = re.compile(re.escape(START) + r".*?" + re.escape(END), re.DOTALL)
    new_content, n = pattern.subn(block, content)
    if n != 1:
        sys.exit("expected exactly one DEMO-OUTPUT block in README.md")
    with open(readme, "w") as fh:
        fh.write(new_content)
    print("README.md example output refreshed (%d bytes of demo output)" % len(output))


if __name__ == "__main__":
    main()
