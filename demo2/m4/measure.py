#!/usr/bin/env python3
import sys
import time
import csv
from tqdm import tqdm



def waitForStart(dev):
    #print("> Waiting for #", file=sys.stderr)
    x = dev.read_until(b'#')
    #sys.stdout.buffer.write(x)
    #sys.stdout.flush()

def readResponse(dev):
    x = dev.read_until(b'=')

    lines = x.decode().splitlines()

    cycles = lines[lines.index("decaps_cycles")+1]

    return ['', cycles]


def run(sk, cts, num_rept, resultFile, dev):
    assert len(sk) == 4800

    dev.write(b'#')

    waitForStart(dev)
    # print(f"> Writing sk ({len(sk)} bytes) ..", file=sys.stderr)
    dev.write(bytes.fromhex(sk))


    with open(resultFile, "w") as f:
        csvF = csv.writer(f)
        for ct in tqdm(cts):
            assert len(ct) == 2176
            waitForStart(dev)
            # print("> Writing ct ..", file=sys.stderr)
            dev.write(bytes.fromhex(ct))

            for i in range(num_rept):
                waitForStart(dev)
                csvF.writerow(readResponse(dev))