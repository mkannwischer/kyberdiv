#!/usr/bin/env python3
import sys
import time
import csv
from tqdm import tqdm


def waitForStart(dev):
    #print("> Waiting for #", file=sys.stderr)
    x = dev.read_until(b'#')
    # sys.stdout.buffer.write(x)
    # sys.stdout.flush()


def waitForVictim(dev):
    #print("> Waiting for #", file=sys.stderr)
    x = dev.read_until(b'#')
    # sys.stdout.buffer.write(x)
    # sys.stdout.flush()


def readResponse(dev):
    x = dev.read_until(b'#')
    # sys.stdout.buffer.write(x)
    # sys.stdout.flush()
    x = x.decode()
    x = x.replace("#", "").strip()
    lines = x.splitlines()
    return [[0, n] for n in lines]

def run(sk, cts, num_rept, resultFile, dev):
    assert len(sk) == 4800
    
    dev.write(b'#')

    print("waiting for attacker")
    waitForStart(dev)

    print("waiting for victim")
    waitForVictim(dev)


    print("victim online")

    waitForStart(dev)
    dev.write(bytes.fromhex(sk))

    with open(resultFile, "w") as f:
        csvF = csv.writer(f)
        for ct in tqdm(cts):
            assert len(ct) == 2176


            waitForStart(dev)
            dev.write(bytes.fromhex(ct))


            cycles = readResponse(dev)
            csvF.writerows(cycles)