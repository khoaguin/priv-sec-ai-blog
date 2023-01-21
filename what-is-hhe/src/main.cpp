#include <iostream>
#include <vector>

#include <seal/seal.h>

#include "../configs/config.h"
#include "utils/sealhelper.h"
#include "utils/pastahelper.h"
#include "pasta/SEAL_Cipher.h"
#include "pasta/pasta_3_plain.h"


struct Client {
    // the HE keys
    seal::PublicKey he_pk;  // HE public key
    seal::SecretKey he_sk;  // HE secret key
    seal::RelinKeys he_rk;  // HE relin key
    seal::GaloisKeys he_gk;  // HE galois key
    // the symmetric key
    std::vector<uint64_t> k;  // the secret symmetric keys
    // client's data
    std::vector<seal::Ciphertext> c_k;  // the HE encrypted symmetric keys
    std::vector<uint64_t> m {0, 5, 255, 100, 255};  // the client's secret data
    std::vector<uint64_t> c_s;  // the symmetric encrypted data
    seal::Ciphertext c_res;  // the HE encrypted result received from the server
};

struct Server {
    std::vector<seal::Ciphertext> c;  // the HE encrypted data of Client's m
};


int main() {

    std::cout << "---- Client ----" << std::endl;
    Client client;
    std::cout << "The client runs HHE.KeyGen to create the HE keys" << std::endl;
    std::shared_ptr<seal::SEALContext> context = sealhelper::get_seal_context();
    sealhelper::print_parameters(*context);
    seal::KeyGenerator keygen(*context);
    keygen.create_public_key(client.he_pk);
    client.he_sk = keygen.secret_key();
    keygen.create_relin_keys(client.he_rk);
    seal::BatchEncoder he_benc(*context);
    seal::Encryptor he_enc(*context, client.he_pk);
    seal::Evaluator he_eval(*context);
    seal::Decryptor he_dec(*context, client.he_sk);
    bool use_bsgs = false;
    std::vector<int> gk_indices = pastahelper::add_gk_indices(use_bsgs, he_benc);
    keygen.create_galois_keys(gk_indices, client.he_gk);

    std::cout << "The client runs the encryption algorithm (HHE.Enc)" << std::endl;
    client.k = pastahelper::get_symmetric_key();
    pasta::PASTA SymmetricEncryptor(client.k, configs::plain_mod);
    client.c_s = SymmetricEncryptor.encrypt(client.m);
    // std::vector<uint64_t> c_s_dec = SymmetricEncryptor.decrypt(client.c_s);
    // for (auto i : c_s_dec) {
    //     std::cout << i << " ";
    // }

    return 0;
}