set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -g -march=native")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wno-array-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-sign-compare")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wwrite-strings -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcast-qual -Wunused-result")

set(KYBER_NAMES 512 768 1024)
set(KYBER_KS 2 3 4)

set(KYBER_SCA_SRC   kyber768/aes256ctr.c kyber768/cbd.c kyber768/fips202.c kyber768/kem.c
                    kyber768/ntt.c kyber768/poly.c kyber768/polyvec.c
                    kyber768/reduce.c kyber768/rng.c kyber768/sha256.c kyber768/sha512.c
                    kyber768/symmetric-aes.c kyber768/symmetric-shake.c
                    kyber768/verify.c
                    # File kyber768/indcpa.c is 'overwritten' by sca_indcpa.c
                    sca_indcpa.c)

include_directories("kyber768")

foreach(KYBER_NAME KYBER_K IN ZIP_LISTS KYBER_NAMES KYBER_KS)
    # add_executable(kyber_timing_attack ${KYBER_SCA_SRC} kyber_timing_attack.c)
    # # target_compile_definitions(kyber_timing_attack PUBLIC SIMULATE_TIMING_ATTACK)
    # target_link_libraries(kyber_timing_attack crypto m)

    set(KYBER_SLASH2_ATTACK gen_ciphertexts_${KYBER_NAME})
    add_executable(${KYBER_SLASH2_ATTACK} ${KYBER_SCA_SRC} gen_ciphertexts.c)
    target_link_libraries(${KYBER_SLASH2_ATTACK} crypto m)
    target_compile_definitions(${KYBER_SLASH2_ATTACK} PUBLIC KYBER_K=${KYBER_K})
endforeach()


# foreach(KYBER_NAME KYBER_K IN ZIP_LISTS KYBER_NAMES KYBER_KS)
#     # add_executable(kyber_timing_attack ${KYBER_SCA_SRC} kyber_timing_attack.c)
#     # # target_compile_definitions(kyber_timing_attack PUBLIC SIMULATE_TIMING_ATTACK)
#     # target_link_libraries(kyber_timing_attack crypto m)

#     set(KYBER_SLASH2_ATTACK kyberslashes_${KYBER_NAME})
#     add_executable(${KYBER_SLASH2_ATTACK} ${KYBER_SCA_SRC} kyberslashes.c)
#     target_link_libraries(${KYBER_SLASH2_ATTACK} crypto m)
#     target_compile_definitions(${KYBER_SLASH2_ATTACK} PUBLIC KYBER_K=${KYBER_K})
# endforeach()
