#!/bin/sh

when=`date -Iseconds`
[ -d kyber ] || git clone https://github.com/pq-crystals/kyber
cd kyber
git checkout a621b8dde405cc507cbcfc5f794570a4f98d69cc
cd ref
cp ../../demo1-pi2.c .
gcc \
-Os -g \
-Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls -Wshadow -Wpointer-arith \
-DKYBER_K=2 \
kex.c kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c fips202.c symmetric-shake.c randombytes.c \
demo1-pi2.c -o kyberslash
time ./kyberslash > kyberslash.out.$when
tail -1 kyberslash.out.$when
