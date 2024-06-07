#pragma once

// TODO: define targets during execution, not with defines.

#define STM32L4R5ZI 1
#define CORTEXX1 2
#define CORTEXA55 3

#define DEVICE STM32L4R5ZI
// #define DEVICE CORTEXX1
// #define DEVICE CORTEXA55

#ifndef DEVICE
#error "DEVICE not defined"
#endif

#if DEVICE==STM32L4R5ZI

static __inline__ int get_udiv_leakage(uint32_t numerator) {
    if (numerator < 1) return 2;
    if (numerator < 2048) return 3;
    if (numerator < 32768) return 5;
    if (numerator < 524288) return 6;
    if (numerator < 8388608) return 7;
    if (numerator < 134217728) return 8;
    if (numerator < 2147483648) return 9;
    return 10;
}

#elif DEVICE==CORTEXX1

static __inline__ int get_udiv_leakage(uint32_t numerator) {
    if (numerator < 1) return 5;
    if (numerator < 3329) return 6;
    if (numerator < 524288) return 7;
    if (numerator < 8388608) return 8;
    if (numerator < 134217728) return 9;
    return 10;
}

#elif DEVICE==CORTEXA55

static __inline__ int get_udiv_leakage(uint32_t numerator) {
    if (numerator < 1) return 3;
    if (numerator < 8192) return 4;
    if (numerator < 131072) return 5;
    if (numerator < 2097152) return 6;
    if (numerator < 33554432) return 7;
    return 8;
}

#else
    #error "Unknown device"
#endif