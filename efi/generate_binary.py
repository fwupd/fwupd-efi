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
        ".sbom",
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
        "--section-alignment",
        "512",
        args.infile,
        args.outfile,
    ]

    # older objcopy for Aarch64 and ARM32 are not EFI capable.
    # Use "binary" instead, and add required symbols manually.
    if args.objcopy_manualsymbols:
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

    argv = [args.genpeimg, "-d", "+d", "-d", "+n", "-d", "+s", args.outfile]
    try:
        subprocess.run(argv, check=True)
    except FileNotFoundError as e:
        print(str(e))
        sys.exit(1)


def _add_nx_pefile(args):
    # unnecessary if we have genpeimg
    if args.genpeimg:
        return
    try:
        import pefile
    except ImportError:
        print("Unable to add NX support to binaries without genpeimg or python3-pefile")
        sys.exit(1)

    pe = pefile.PE(args.outfile)
    pe.OPTIONAL_HEADER.DllCharacteristics |= pefile.DLL_CHARACTERISTICS[
        "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"
    ]
    pe.write(args.outfile)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--objcopy", default="objcopy", help="Binary file to use for objcopy"
    )
    parser.add_argument("--genpeimg", help="Binary file to use for genpeimg")
    parser.add_argument("--arch", default="x86_64", help="EFI architecture")
    parser.add_argument("--os", help="OS type")
    parser.add_argument(
        "--objcopy-manualsymbols",
        action="store_true",
        help="whether adding symbols direct to binary",
    )
    parser.add_argument("infile", help="Input file")
    parser.add_argument("outfile", help="Output file")
    _args = parser.parse_args()
    _run_objcopy(_args)
    _run_genpeimg(_args)
    _add_nx_pefile(_args)

    sys.exit(0)
