#pragma once

#include <cstddef>
#include <iostream>
#include <typeinfo>
#include <seal/seal.h>

namespace sealhelper
{
    /*
    Helper function: get a SEALContext from parameters.
    */
    std::shared_ptr<seal::SEALContext> get_seal_context(uint64_t plain_mod = 65537, uint64_t mod_degree = 16384, int seclevel = 128);

    /*
    Helper function: Prints the parameters in a SEALContext.
    */
    void print_parameters(const seal::SEALContext &context);

    /*
    Helper function: Decrypt a SEAL ciphertext and return the result as a vector of integers.
    */
    std::vector<int64_t> decrypt(const seal::Ciphertext &enc_input,
                                 const seal::SecretKey &he_sk,
                                 const seal::BatchEncoder &benc,
                                 const seal::SEALContext &context,
                                 size_t size);
}
