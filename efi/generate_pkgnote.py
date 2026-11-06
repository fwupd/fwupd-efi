#!/usr/bin/env python3
#
# Copyright (C) 2026 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=missing-docstring, invalid-name

import subprocess
import sys
import argparse
import tempfile
import json


def _generate_pkgnote(args):
    """append package metadata"""

    cmd = (
        args.cc.split()
        + ["-x", "c", "-c", "-o", args.outfile, "/dev/null"]
        + args.cflags.split(" ")
    )
    subprocess.run(cmd, check=True)

    # not specified
    if not args.pkgnote:
        return

    # verify this is actually JSON
    try:
        _ = json.loads(args.pkgnote)
    except json.JSONDecodeError as e:
        print(f"Not valid JSON: {e}")
        sys.exit(1)

    with tempfile.NamedTemporaryFile() as sfd:
        sfd.write(args.pkgnote.encode() + b"\0")
        sfd.flush()

        # add a section to the object; use `objdump -s -j .pkgnote` to verify
        argv = [
            args.objcopy,
            "--add-section",
            ".pkgnote={}".format(sfd.name),
            "--set-section-flags",
            ".pkgnote=contents,alloc,load,readonly,data",
            args.outfile,
        ]
        subprocess.run(argv, check=True)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cc", default="gcc", help="Compiler to use for generating pkgnote object"
    )
    parser.add_argument("--cflags", help="C compiler flags to be used by CC")
    parser.add_argument(
        "--objcopy", default="objcopy", help="Binary file to use for objcopy"
    )
    parser.add_argument("--pkgnote", help="Package metadata in JSON format")
    parser.add_argument("outfile", help="Output file")
    _args = parser.parse_args()
    _generate_pkgnote(_args)

    sys.exit(0)
