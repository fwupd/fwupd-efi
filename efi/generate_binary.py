#!/usr/bin/python3
#
# Copyright (C) 2021 Javier Martinez Canillas <javierm@redhat.com>
# Copyright (C) 2021 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+
#
# pylint: disable=missing-docstring, invalid-name

import subprocess
import sys
import argparse


def _run_objcopy(args):

    argv = [
        args.objcopy,
        "-j",
        ".text",
        "-j",
        ".sbat",
        "-j",
        ".sdata",
        "-j",
        ".data",
        "-j",
        ".dynamic",
        "-j",
        ".rodata",
        "-j",
        ".rel*",
        args.infile,
        args.outfile,
    ]

    # aarch64 and arm32 don't have an EFI capable objcopy
    # Use 'binary' instead, and add required symbols manually
    if args.arch in ["aarch64", "arm"]:
        argv.extend(["-O", "binary"])
    elif args.os == "freebsd":
        # `--target` option is missing and --input-target doesn't recognize
        # "efi-app-*"
        argv.extend(["--output-target", "efi-app-{}".format(args.arch)])
    else:
        argv.extend(["--target", "efi-app-{}".format(args.arch)])

    try:
        subprocess.run(argv, check=True)
    except FileNotFoundError as e:
        print(str(e))
        sys.exit(1)


def _run_genpeimg(args):
    if not args.genpeimg:
        return

    argv = [args.genpeimg, "-d", "+d", "+n", "-d", "+s", args.outfile]
    try:
        subprocess.run(argv, check=True)
    except FileNotFoundError as e:
        print(str(e))
        sys.exit(1)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--objcopy", default="objcopy", help="Binary file to use for objcopy"
    )
    parser.add_argument("--genpeimg", help="Binary file to use for genpeimg")
    parser.add_argument("--arch", default="x86_64", help="EFI architecture")
    parser.add_argument("--os", help="OS type")
    parser.add_argument("infile", help="Input file")
    parser.add_argument("outfile", help="Output file")
    _args = parser.parse_args()
    _run_objcopy(_args)
    _run_genpeimg(_args)

    sys.exit(0)
