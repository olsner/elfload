#!/usr/bin/env python3

import sys
import os

def dump(path, start, end):
    with open(path, "wb") as outf, open("/proc/self/mem", "rb") as inf:
        inf.seek(start)
        outf.write(inf.read(end - start))

with open("/proc/self/maps", "r") as h:
    for line in h:
        if "[vdso]" not in line:
            continue
        addrs = line.split()[0]
        start,end = [int(x,16) for x in addrs.split("-")]

        dump("vdso.so", start, end)
