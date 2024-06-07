#!/usr/bin/python3

import argparse

import seaborn as sns
import pandas as pd
import numpy as np
import os
import ast

import tqdm

import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn import mixture


PLAINTEXT_CHECK_KU_KV = [(207, 937), (2, 729), (106, 521), (106, -728)];
PLAINTEXT_CHECK_TEMPLATE = {
    -2: [1, 1, 1, 0],
    -1: [1, 1, 0, 0],
    0: [1, 0, 0, 0],
    1: [0, 0, 0, 0],
    2: [0, 0, 0, 1],
}

AVERAGE_WEIGHTS_KU_KV = {
    (2, 729): [526, 242],
    (106, 521): [715, 53],
    (207, 937): [225, 543],
    (106, -728): [721, 47],
}


def show_histograms(df):

    fix, axs = plt.subplots(1, 4);
    for ax, (ku, kv) in zip(axs, PLAINTEXT_CHECK_KU_KV):
        sns.histplot(data=df[(df.ku==ku) & (df.kv==kv)],  x='total_leakage',
                     palette=sns.color_palette("tab10"),
                     discrete=True, label=f'{ku}', ax=ax)
        ax.set_title(f'{ku=}, {kv=}')


def show_histograms_with_idx(df):

    fix, axs = plt.subplots(1, 4);
    for ax, (ku, kv) in zip(axs, PLAINTEXT_CHECK_KU_KV):
        sns.histplot(data=df[(df.ku==ku) & (df.kv==kv)],  x='total_leakage',
                     palette=sns.color_palette("tab10"),
                     discrete=True, hue='message', ax=ax)
        ax.set_title(f'{ku=}, {kv=}')



# Compute the expected counts for
def get_average_weights_for_ku_kv(df):

    average_weights = {}
    for (ku, kv) in PLAINTEXT_CHECK_KU_KV:
        average_weights[ku, kv] = [0, 0]

    for i, row in df.iterrows():
        key = (row.ku, row.kv)

        average_weights[key][row.idx] += 1

    return average_weights


def get_likelihoods_for_times(times, models):

    predicted_key = []

    def get_template_likelihood(k, probas):
        p = 1
        for i, ans in enumerate(PLAINTEXT_CHECK_TEMPLATE[k]):
            p *= probas[i][ans]
        return p

    for ts in times:
        probas = []
        # print("=============")
        # print(ts)
        for (ku, kv), t in zip(PLAINTEXT_CHECK_KU_KV, ts):
            predict_proba = models[ku, kv].predict_proba([[t]]).ravel()

            # OK
            if models[ku, kv].means_[1] > models[ku, kv].means_[0]:
                if (t >= models[ku, kv].means_[1]):
                    probas.append([0, 1])
                elif (t <= models[ku, kv].means_[0]):
                    probas.append([1, 0])
                else:
                    probas.append(predict_proba)
                # print(models[ku, kv].predict([[t]])[0])
            # Have to invert
            else:
                if (t >= models[ku, kv].means_[0]):
                    probas.append([0, 1])
                elif (t <= models[ku, kv].means_[1]):
                    probas.append([1, 0])
                else:
                    probas.append([predict_proba[1], predict_proba[0]])
                # print(1 - models[ku, kv].predict([[t]])[0])



        key_probs = {k: get_template_likelihood(k, probas) for k in PLAINTEXT_CHECK_TEMPLATE}

        best_fit = max(key_probs.items(), key=lambda x: x[1])
        # print(best_fit)
        predicted_key.append((best_fit[0], key_probs))

    return predicted_key


def norm(x):
    return np.array(x)/sum(np.array(x))

def get_likelihoods(df):
    weighted_mean_times = {k: 0 for k in PLAINTEXT_CHECK_KU_KV}
    models = {k: mixture.GaussianMixture(n_components=2, weights_init=norm(AVERAGE_WEIGHTS_KU_KV[k])) for k in PLAINTEXT_CHECK_KU_KV}

    classes_maps = {k: None for k in PLAINTEXT_CHECK_KU_KV}

    for ku, kv in PLAINTEXT_CHECK_KU_KV:
        df_kukv = df[(df.ku == ku) & (df.kv == kv)].copy()

        data_as_array = np.array(df_kukv.time).reshape(-1, 1)
        pred = models[ku, kv].fit_predict(data_as_array)
        df_kukv['model_preds'] = pred

        times0 = df_kukv[df_kukv.model_preds == 0].time
        times1 = df_kukv[df_kukv.model_preds == 1].time
        if (np.mean(times1) < np.mean(times0)):
            # print('ohoh')
            pred = [(b + 1) % 2 for b in pred]
            df_kukv['model_preds'] = pred

        # print(f'{ku, kv}, {len(df_kukv[df_kukv.model_preds == 1])=}')

    key_likelihoods = [None for _ in range(len(df)//4)]
    assert(len(key_likelihoods) == 768)
    key_times = [[] for _ in range(len(df)//4)]

    for i, row in df.iterrows():
        key_times[i // 4].append(row.time)

    return key_times, models

def get_key(df):
    kt, km = get_likelihoods(df)
    return get_likelihoods_for_times(kt, km)


def build_df_for_recovery_no_hash_column(result_csv, simulation_csv, n_measurement_reps_to_consider=None):
    result_df = pd.read_csv(result_csv, header=None)
    result_df.columns = ['discard', 'time']
    simulation_df = pd.read_csv(simulation_csv, skiprows=7)

    n_reps = len(result_df) // len(simulation_df)

    assert(n_reps * len(simulation_df) == len(result_df))

    print(f'Found that experiments were done using {n_reps=} repetitions per ciphertext')

    result_median_df = (result_df.groupby(result_df.index // n_reps, as_index=False)[['time']])

    if n_measurement_reps_to_consider is None:
        print('Using n_measurement_reps_to_consider = n_reps')
        n_measurement_reps_to_consider = n_reps

    leaks = []
    for i, g in tqdm.tqdm(result_median_df):
        leaks.append(np.median(g.time[:n_measurement_reps_to_consider]))

    simulation_df['time'] = leaks
    df_for_recovery = (simulation_df.groupby(['block', 'i', 't', 'ku', 'kv'], as_index=False)[['time']]).mean().reset_index()

    return df_for_recovery


def build_df_for_recovery_with_hash_column(result_csv_file, simulation_csv, n_measurement_reps_to_consider=None):
    result_df = pd.read_csv(result_csv_file, header=None)
    result_df.columns = ['hash', 'time']

    ct_hashes = result_df.hash.unique()

    # Build reverse indexes to deal with out of order results
    hash_to_ind = {}
    for i, h in enumerate(ct_hashes):
        hash_to_ind[h] = i

    # chmed = (result_df.groupby(['hash'], as_index=False)[['time']]).median().reset_index()
    hash_groups = (result_df.groupby(['hash'], as_index=False)[['time']])

    if n_measurement_reps_to_consider is None:
        print('Using n_measurement_reps_to_consider = max')

    chmed = {}
    for i, g in hash_groups:
        if (n_measurement_reps_to_consider):
            chmed[i] = np.median(g.time[:n_measurement_reps_to_consider])
        else:
            chmed[i] = np.median(g.time)

    leaks = [None] * len(ct_hashes)
    chmed_dict = {}
    for h, time in chmed.items():
        leaks[hash_to_ind[h]] = time

    df = pd.read_csv(simulation_csv, skiprows=7)
    df['time'] = leaks

    dd = (df.groupby(['block', 'i', 't', 'ku', 'kv'], as_index=False)[['idx', 'time']]).mean().reset_index()

    return dd


# The first result column is now the hash of the ciphertexts.
#   * But this is not the case for some old timing results
#   * If they are not in order, it takes a lot of time to parse them (when we need lots of challenges, such as for A55)
def build_df_for_recovery(result_csv_file, simulation_csv_file, first_result_column_is_hash=False,
                          results_are_in_order=False, n_measurement_reps_to_consider=None):

    if (not first_result_column_is_hash and not results_are_in_order):
        raise ValueError('Key recovery is not possible: either provide results in order or use first column as ciphertext hash')

    print(results_are_in_order)
    if results_are_in_order:
        return build_df_for_recovery_no_hash_column(result_csv_file, simulation_csv_file, n_measurement_reps_to_consider)

    else:
        return build_df_for_recovery_with_hash_column(result_csv_file, simulation_csv_file, n_measurement_reps_to_consider)


def test_key_recovery(result_csv_file, simulation_csv_file, first_result_column_is_hash=False,
                      results_are_in_order=False, n_measurement_reps_to_consider=None):

    real_secret_s = get_s_from_file(simulation_csv_file)

    print(f'Generating combined DataFrame from {result_csv_file} and {simulation_csv_file}...')
    df_for_recovery = build_df_for_recovery(result_csv_file, simulation_csv_file,
                                            first_result_column_is_hash, results_are_in_order,
                                            n_measurement_reps_to_consider)

    print('Done! First 5 rows are:')
    print(df_for_recovery.head())

    print('Trying to recover key from DataFrame')
    key_data = get_key(df_for_recovery)

    predicted_secret_s, probabilities = zip(*key_data)
    correctGuesses = [i == j for i, j in zip(predicted_secret_s, real_secret_s)].count(True)
    print('Correctly guessed: ', correctGuesses)
    return correctGuesses == 768



def get_s_from_file(fpath):
    f = open(fpath)
    mark_string = '[*] Target secret key coefficients s = '
    for l in f:
        if l.startswith(mark_string):
            s = ast.literal_eval(l[len(mark_string):])
            return s

    return None


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('challenge_info_file')
    parser.add_argument('timing_result_file')
    parser.add_argument('--n_reps', type=int, default=None)


    args = parser.parse_args()

    test_key_recovery(args.timing_result_file, args.challenge_info_file, results_are_in_order=True,
                      n_measurement_reps_to_consider=args.n_reps)
    # test_key_recovery(args.timing_result_file, args.challenge_info_file, first_result_column_is_hash=True)

if __name__ == '__main__':
    main()
