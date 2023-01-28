#pragma once

#include <vector>
#include <seal/seal.h>

namespace pastahelper
{
    /*
    Helper function: Create galois keys indices to create HE galois keys
    */
    std::vector<int> add_gk_indices(bool use_bsgs, const seal::BatchEncoder &benc);

    /*
    Helper function: Create the symmetric key
    */
    std::vector<uint64_t> get_symmetric_key();

    /*
    Helper function: Encrypt the symmetric key using HE
    This function is adapted from https://github.com/IAIK/hybrid-HE-framework/blob/master/ciphers/pasta_3/seal/pasta_3_seal.cpp
    */
    std::vector<seal::Ciphertext> encrypt_symmetric_key(const std::vector<uint64_t> &ssk,
                                                        bool batch_encoder,
                                                        const seal::BatchEncoder &benc,
                                                        const seal::Encryptor &enc);
}