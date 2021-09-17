#!/usr/bin/env python3
import sys
import r2pipe
from logging import debug
from typing import List, Optional

Proc = r2pipe.open_sync.open


def uses_dlopen(target: Proc) -> bool:
    try:
        target.cmd("s sym.imp.dlopen")
    except Exception:
        return False
    return True


def dlopen_callsites(target: Proc) -> List[int]:
    ret = target.cmd("/r sym.imp.dlopen")
    callsites = []
    for reference in ret.split("\n"):
        if reference == "":
            break
        _, addr, reftype, *rest = reference.split(" ")
        if reftype == "[CALL]":
            callsites.append(int(addr, 16))
    return callsites


def get_libname(target: Proc, callsite: int) -> Optional[str]:
    # Seek to the call site
    path_addr = 0
    # 1. Seek one byte back at the time
    for i in range(32):
        offset = callsite - i - 1
        # 1. reset esil register
        # 2. seek to offset
        # 3. run esil emulation from current offset until callsite
        ret = target.cmd(f"ar0; s {offset}; aefa {callsite}")
        args = ret.split("\n")

        # parse first argument set at callsite
        try:
            path_addr = int(args[0].split(" ")[1], 16)
        except IndexError:
            continue
        if path_addr != 0:
            # did not found a solution
            break
    if path_addr == 0:
        return

    # resolve the address to a string
    arg = target.cmdj(f"psj @ {path_addr}")
    libname = arg["string"]
    # find the end of the string
    for strlen, c in enumerate(libname):
        if c == "\x00":
            libname = libname[:strlen]
            break
    return libname


def main() -> None:
    if len(sys.argv) < 2:
        print(f"USAGE: {sys.argv[0]} binary")
        return

    # -2 -> disable stderr
    target = r2pipe.open(sys.argv[1], flags=['-2'])
    # we don't want to have color output for easier parsing
    target.cmd("e scr.color=false")
    # timeout esil emulation after one second
    target.cmd("e esil.timeout=1")
    if not uses_dlopen(target):
        return
    callsites = dlopen_callsites(target)
    libs = set()
    for callsite in callsites:
        debug(f"analyze callsite: 0x{callsite:x}")
        lib = get_libname(target, callsite)
        if lib:
            libs.add(lib)
    for lib in libs:
        print(lib)


if __name__ == "__main__":
    main()
