#include <iostream>
#include <vector>

#include <seal/seal.h>

#include "../configs/config.h"
#include "utils/sealhelper.h"
#include "utils/pastahelper.h"
#include "utils/utils.h"
#include "pasta/SEAL_Cipher.h"
#include "pasta/pasta_3_plain.h"
#include "pasta/pasta_3_seal.h"

struct Client
{
    // the HE keys
    seal::PublicKey he_pk;  // HE public key
    seal::SecretKey he_sk;  // HE secret key
    seal::RelinKeys he_rk;  // HE relin key
    seal::GaloisKeys he_gk; // HE galois key
    // client's symmetric keys
    std::vector<uint64_t> k;           // the secret symmetric keys
    std::vector<seal::Ciphertext> c_k; // the HE encrypted symmetric keys
    // client's data
    std::vector<uint64_t> m{0, 5, 255, 100, 255}; // the client's secret data
    std::vector<uint64_t> c_s;                    // the symmetric encrypted data
    seal::Ciphertext c_res;                       // the HE encrypted result received from the server
};

struct Server
{
    std::vector<int64_t> w{-1, 2, -3, 4, 5};    // dummy weights
    std::vector<int64_t> b{-5, -5, -5, -5, -5}; // dummy biases
    std::vector<seal::Ciphertext> c;            // the HE encrypted data of Client's m
    seal::SecretKey he_sk;                      // the server's HE secret key
    seal::Ciphertext c_res;                     // the HE encrypted results that will be sent to the Analyst
};

int main()
{
    Client client;
    Server server;

    std::cout << "---- Client ----" << std::endl;
    utils::print_line(__LINE__);
    std::cout << "The client creates the HE context, keys and SEAL objects" << std::endl;
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

    utils::print_line(__LINE__);
    std::cout << "The client creates the symmetric key and encrypts his data" << std::endl;
    client.k = pastahelper::get_symmetric_key();
    pasta::PASTA SymmetricEncryptor(client.k, configs::plain_mod);
    client.c_s = SymmetricEncryptor.encrypt(client.m);
    // std::vector<uint64_t> c_s_dec = SymmetricEncryptor.decrypt(client.c_s);  // for debugging

    utils::print_line(__LINE__);
    std::cout << "The client encrypts the symmetric key using HE" << std::endl;
    client.c_k = pastahelper::encrypt_symmetric_key(client.k,
                                                    configs::USE_BATCH,
                                                    he_benc,
                                                    he_enc);
    std::cout << "The client sends the HE encrypted symmetric key, the symmetric "
                 "encrypted data and the HE evaluation key to the server"
              << std::endl;

    std::cout << "\n---- Server ----" << std::endl;
    utils::print_line(__LINE__);
    std::cout << "The server creates his own HE secret key" << std::endl;
    seal::KeyGenerator csp_keygen(*context);
    server.he_sk = csp_keygen.secret_key();

    utils::print_line(__LINE__);
    std::cout << "The server performs the HHE.Decomp algorithm" << std::endl;
    pasta::PASTA_SEAL HHE(context, client.he_pk, server.he_sk, client.he_rk, client.he_gk);
    server.c = HHE.decomposition(client.c_s, client.c_k, configs::USE_BATCH);
    utils::print_line(__LINE__);
    std::cout << "The server evaluates a linear transformation on encrypted data" << std::endl;
    // packed_enc_multiply(CSP.c_prime[0], Analyst.w_c, CSP.c_res, analyst_he_eval);
    // packed_enc_addition(CSP.c_res, Analyst.b_c, CSP.c_res, analyst_he_eval);

    return 0;
}