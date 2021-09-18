#!/usr/bin/env python3
import sys
import r2pipe
import logging
from logging import debug
from typing import List, Optional, Iterator, Dict, Any
from intervaltree import IntervalTree, Interval

Proc = r2pipe.open_sync.open

# for debugging
#logging.basicConfig(level=logging.DEBUG)

def uses_dlopen(target: Proc) -> bool:
    try:
        # if we can seek to this symbol, it exists
        target.cmd("s sym.imp.dlopen")
    except Exception:
        return False
    return True


def dlopen_callsites(target: Proc) -> List[int]:
    # find all references to imported symbol "dlopen"
    ret = target.cmd("/r sym.imp.dlopen")
    callsites = []
    for reference in ret.split("\n"):
        if reference == "":
            break
        _, addr, reftype, *rest = reference.split(" ")
        # we are only interested in calls
        if reftype == "[CALL]":
            debug(f"found callsite at {addr}")
            callsites.append(int(addr, 16))
    return callsites


def get_libname(target: Proc, callsite: int, mappings: IntervalTree) -> Optional[str]:
    # Seek to the call site
    path_addr = 0
    # Seek one byte back at the time.
    # This might cause invalid instructions when performing emulation
    found = False
    for i in range(32):
        offset = callsite - i - 1
        # 1. reset esil register
        # 2. seek to offset
        # 3. run esil emulation from current offset until callsite
        ret = target.cmd(f"ar0; s {offset}; aefa {callsite}")
        debug(f"callsite=0x{callsite:x} offset=0x{offset}\n{ret}")
        args = ret.split("\n")

        # parse first argument set at callsite
        try:
            path_addr = int(args[0].split(" ")[1], 16)
        except IndexError:
            continue
        if mappings.at(path_addr) and path_addr != 0:
            found = True
            # found a valid address
            break
    if not found:
        return

    # resolve the address to a string
    arg = target.cmdj(f"psj @ {path_addr}")
    libname = arg["string"]
    # find the end of the string by looking for a null character
    for strlen, c in enumerate(libname):
        if c == "\x00":
            return libname[:strlen]
    # otherwise return the whole string
    return libname


def get_readable_mappings(target: Proc) -> IntervalTree:
    # returns sections of the exectuable and their load addresses + permissions
    sections = target.cmdj("iSj")

    def mapping(section: List[Dict[str, Any]]) -> Iterator[Interval]:
        for section in sections:
            start = section["vaddr"]
            vsize = section["vsize"]
            # if vaddr is 0, than this section is not mapped into memory
            if start == 0 or vsize == 0:
                continue
            # we are only interested in sections we can from in memory
            if not "r" in section["perm"]:
                continue
            yield Interval(start, start + vsize, section["name"])

    return IntervalTree(mapping(sections))


def main() -> None:
    if len(sys.argv) < 2:
        print(f"USAGE: {sys.argv[0]} binary")
        return

    # -2 -> disable stderr
    target = r2pipe.open(sys.argv[1], flags=["-2"])

    mappings = get_readable_mappings(target)

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
        lib = get_libname(target, callsite, mappings)
        if lib:
            libs.add(lib)
    for lib in libs:
        print(lib)


if __name__ == "__main__":
    main()
