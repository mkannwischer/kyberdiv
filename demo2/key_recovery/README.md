
## Compiling
```
cmake -B build
make -C build
```

If you want to use a different target than Cortex-M4, you'll have to change file `gen_challenges/udiv_leakage.h` to
define the corresponding `DEVICE`.

## Generating the challenges

```
./build/gen_challenges/gen_ciphertexts_768 12301 2 100000 > challenge_info
```
This will generate a set of ciphertexts and additional information, such as sk, pk, device, estimated
leakages for kyberslash1 and kyberslash2.


## Generating the files for timing experiments in real devices

There is a simple script to break the info files in multiple pieces that are more convenient for
running experiments in real devices.

```
./scripts/prepare_timing_experiment.py m4_example_data/info m4_exemple_data/challenges
```

This will run through directory `m4_example_data/info`, find challenge information files and generate three
files per challenge, with the same prefix as the challenge info.
```
$ tree m4_example_data/challenges
m4_example_data/challenges
├── challenge_ct
├── challenge_pk
└── challenge_sk
```

## Key recovery

For key recovery, use the `./scripts/key_recovery.py` script.

```
$ ./scripts/key_recovery.py ./m4_example_data/info/challenge_info.csv ./m4_example_data/results/challenge_result.gz
Generating combined DataFrame from ./m4_example_data/results/challenge_result.gz and ./m4_example_data/info/challenge_info.csv...
True
Found that experiments were done using n_reps=3 repetitions per ciphertext
Using n_measurement_reps_to_consider = n_reps
100%|█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 6144/6144 [00:00<00:00, 11389.10it/s]
Done! First 5 rows are:
   index  block  i  t   ku   kv      time
0      0      0  0  0  207  937  713764.5
1      1      0  0  1    2  729  713603.0
2      2      0  0  2  106  521  713615.0
3      3      0  0  3  106 -728  713615.0
4      4      0  1  0  207  937  713679.0
Trying to recover key from DataFrame
Correctly guessed:  768
```

## Python dependencies

For convenience, if you don't have the plotting modules or numpy installed, I recommend using Pipenv.
```
$ # At kyberdiv/code/key_recovery
$ pipenv shell
$ pipenv install
```

Then you should be able to run the key recovery script

