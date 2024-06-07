#!/usr/bin/python3

import argparse
import os
import sys
import pandas as pd

def get_pk_from_file(fpath):
    f = open(fpath)
    mark_string = '[*] pk =  '
    for l in f:
        if l.startswith(mark_string):
            s = l[len(mark_string):-1]
            return s

    return None

def get_sk_from_file(fpath):
    f = open(fpath)
    mark_string = '[*] sk =  '
    for l in f:
        if l.startswith(mark_string):
            s = l[len(mark_string):-1]
            return s

    return None

def extract_keys_and_ciphertexts_from_info_files(dir_input, dir_output):

    os.makedirs(dir_output, exist_ok=True)

    for input_filename in os.listdir(dir_input):
        input_filepath = os.path.join(dir_input, input_filename)

        print(input_filepath)

        radix = os.path.splitext(input_filename)[0]
        print(radix)

        assert('info' in radix)

        radix = radix.replace('info', '')

        pk_file = open(os.path.join(dir_output, radix + 'pk'), 'w')
        pk = get_pk_from_file(input_filepath)
        print(pk, file=pk_file, end='')
        pk_file.close()

        sk_file = open(os.path.join(dir_output, radix + 'sk'), 'w')
        sk = get_sk_from_file(input_filepath)
        print(sk, file=sk_file, end='')
        sk_file.close()

        ct_filepath = os.path.join(dir_output, radix + 'ct')
        df = pd.read_csv(input_filepath, skiprows=7)
        df[['ciphertext']].to_csv(ct_filepath, index=False, header=False)

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('input_directory')
    parser.add_argument('output_directory')

    args = parser.parse_args()
    # print(args.input_directory, args.output_directory)

    extract_keys_and_ciphertexts_from_info_files(args.input_directory, args.output_directory)


if __name__ == '__main__':
    main()