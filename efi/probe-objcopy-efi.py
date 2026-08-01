#!/usr/bin/env python3

import subprocess
import sys
import argparse
import tempfile
import pathlib

def _probe_objcopy(args) -> int:

    with tempfile.TemporaryDirectory(prefix="objcopy-efi-probe-") as tmp:
        tmpdir = pathlib.Path(tmp)
        elf_file = tmpdir / "probe.a"
        efi_file = tmpdir / "probe.efi"

        cmd = (
            args.cc.split()
            + [
                "-x", "c",
                "-nostdlib",
                "-fPIC",
                "-shared",
                "-Wl,-e,_start",
                "-o", str(elf_file),
                "-",
            ]
        )
        subprocess.run(cmd, input=b"void _start(void) {}\n", check=True)

        cmd = (
            args.objcopy.split()
            + [
                "-O", args.target,
                str(elf_file),
                str(efi_file),
            ]
        )
        objcopy_result = subprocess.run(cmd, check=False)

        return objcopy_result.returncode

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cc", default="gcc", help="Compiler to use for generating sbat object"
    )
    parser.add_argument(
        "--objcopy", default="objcopy", help="Binary file to use for objcopy"
    )
    parser.add_argument("--target", default="efi-app-x86_64", help="EFI output target")

    _args = parser.parse_args()
    res = _probe_objcopy(_args)

    sys.exit(res)