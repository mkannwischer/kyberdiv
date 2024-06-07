#!/usr/bin/env python3
import shutil
import os
import random
import subprocess
import csv
import serial
import key_recovery.scripts.key_recovery as key_recovery
import m4.measure as m4measure
import m4remote.measure as m4remotemeasure
import argparse

scriptDir=os.path.dirname(os.path.abspath(__file__))
workDir = os.path.join(scriptDir, "work")

parser = argparse.ArgumentParser()

# Calls from the paper
# local: ./m4.py -i 1 -n 2
# remote: ./m4.py -i 4 -n 2 -r
parser.add_argument("-i", "--n_reps", type=int, default=1)
parser.add_argument("-n", "--n_msg", type=int, default=2)
parser.add_argument("-r", "--remote", default=False, action="store_true")
parser.add_argument("-v", "--victimUID", default="57FF70066680535043600367", help="ST-LINK UID for flashing")
parser.add_argument("-a", "--attackerUID", default="066DFF3332584B3043223317", help="ST-LINK UID for flashing")

args = parser.parse_args()


# numMessages: number of messages for distinguishing (results in 3072*numMessages ciphertexts)
numMessages = args.n_msg

# numReps: number of decapsulations for the same ciphertext (to reduce noise)
numReps = args.n_reps

# remote: False: timing performed on the target device; True: timing performed on separate M4
remote = args.remote

victimSerial = args.victimUID
attackerSerial = args.attackerUID
dev = serial.Serial("/dev/ttyUSB0", 7*115200)


if os.path.exists(workDir):
    shutil.rmtree(workDir, ignore_errors=True)
    os.mkdir(workDir)
else:
    os.mkdir(workDir)



def generateCiphertexts(seed, numMessages):
    genPath = os.path.join(workDir, "gen")
    if not os.path.exists(genPath):
        os.mkdir(genPath)
    os.chdir(genPath)

    subprocess.run(["cmake", os.path.join(scriptDir, "key_recovery/gen_challenges/")])
    subprocess.run("make")


    f = open(ciphertextFile, "w")
    print("Generating ciphertexts...")
    subprocess.call(["./gen_ciphertexts_768", str(seed), str(numMessages),"100000"], stdout=f)
    f.close()

# generate challenges
ciphertextFile = os.path.join(workDir, "ciphertexts")
regenerate = False
if os.path.exists(ciphertextFile):
    regenerate = True
else:
    regenerate = True



if regenerate:
    seed = random.randint(0, 2**31-1)
    print("seed=", seed)
    generateCiphertexts(seed, numMessages)


def loadCiphertexts():
    # extract ciphertexts
    cts = []
    with open(ciphertextFile) as f:
        lines = f.readlines()


        seed = lines[0].split("seed = ")[1].strip()

        print("seed=", seed)
        sk = lines[6].split("sk = ")[1].strip()
        assert len(sk) == 4800

        rows = csv.reader(lines[8:])

        for row in rows:
            ct = row[11]
            assert len(ct) == 2176
            cts.append(ct)

    return sk, cts, seed


sk, cts, seed = loadCiphertexts()

resultFile = os.path.join(workDir, "results")
regenerate = False
if os.path.exists(resultFile):
    regenerate = True
else:
    regenerate = True


def measure(sk, cts):
    if remote:
        # build and flash M4 binary
        m4PathAttacker = os.path.join(scriptDir, "m4remote/attacker")
        os.chdir(m4PathAttacker)
        subprocess.run(["make", "clean"])
        subprocess.run(["make", f"NUMREPS={numReps}"])
        subprocess.run(["st-flash", "--reset","--serial", attackerSerial, "write",  "test.bin", "0x8000000"])

        m4PathVictim = os.path.join(scriptDir, "m4remote/victim")
        os.chdir(m4PathVictim)
        subprocess.run(["make", "clean"])
        subprocess.run(["make", f"NUMREPS={numReps}"])
        subprocess.run(["st-flash", "--reset", "--serial", victimSerial,  "write",  "test.bin", "0x8000000"])

        m4remotemeasure.run(sk, cts, numReps, resultFile, dev)

    else:
        # build and flash M4 binary
        m4Path = os.path.join(scriptDir, "m4")
        os.chdir(m4Path)
        subprocess.run(["make", "clean"])
        subprocess.run(["make", f"NUMREPS={numReps}"])
        subprocess.run(["st-flash", "--reset", "write",  "bench.bin", "0x8000000"])

        print("Performing measurements...")
        m4measure.run(sk, cts, numReps, resultFile, dev)

# perform measurements on M4
if regenerate:
    measure(sk, cts)


# perform key recovery
print("Performing key recovery...")
success = key_recovery.test_key_recovery(resultFile, ciphertextFile, results_are_in_order=True, n_measurement_reps_to_consider=numReps)
print("Success:", success)