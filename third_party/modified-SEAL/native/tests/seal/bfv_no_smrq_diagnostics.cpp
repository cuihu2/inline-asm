// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/randomgen.h"
#include "seal/seal.h"
#include "seal/util/rns.h"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include "gtest/gtest.h"

using namespace seal;
using namespace seal::util;
using namespace std;

namespace sealtest
{
    namespace
    {
        struct DiagnosticCase
        {
            string name;
            size_t poly_modulus_degree;
            vector<int> coeff_modulus_bits;
            int plain_modulus_bits;
            size_t max_depth;
        };

        const char *diagnostic_build_mode() noexcept
        {
#if defined(SEAL_EXPERIMENTAL_BFV_NO_SMRQ) && defined(SEAL_EXPERIMENTAL_BFV_BRANCHLESS_SK)
            return "nosmrq_branchless_sk";
#elif defined(SEAL_EXPERIMENTAL_BFV_NO_SMRQ)
            return "nosmrq";
#elif defined(SEAL_EXPERIMENTAL_BFV_BRANCHLESS_SK)
            return "branchless_sk";
#else
            return "baseline";
#endif
        }

        size_t diagnostic_trial_count()
        {
            constexpr size_t default_trial_count = 2;
            const char *value = getenv("SEAL_NO_SMRQ_DIAGNOSTIC_TRIALS");
            if (!value)
            {
                return default_trial_count;
            }

            char *end = nullptr;
            unsigned long parsed = strtoul(value, &end, 10);
            if (end == value || *end != '\0' || !parsed || parsed > 1000)
            {
                return default_trial_count;
            }
            return static_cast<size_t>(parsed);
        }

        size_t diagnostic_size_from_environment(const char *name, size_t default_value, size_t maximum)
        {
            const char *value = getenv(name);
            if (!value)
            {
                return default_value;
            }

            char *end = nullptr;
            unsigned long parsed = strtoul(value, &end, 10);
            if (end == value || *end != '\0' || !parsed || parsed > maximum)
            {
                return default_value;
            }
            return static_cast<size_t>(parsed);
        }

        vector<size_t> diagnostic_k_values()
        {
            const vector<size_t> default_values{ 2, 3, 4, 5, 6, 8, 10, 12 };
            const char *value = getenv("SEAL_NO_SMRQ_N32768_K_VALUES");
            if (!value)
            {
                return default_values;
            }

            vector<size_t> result;
            string token;
            stringstream stream(value);
            while (getline(stream, token, ','))
            {
                char *end = nullptr;
                unsigned long parsed = strtoul(token.c_str(), &end, 10);
                if (end == token.c_str() || *end != '\0' || parsed < 1 || parsed > 13)
                {
                    return default_values;
                }
                result.push_back(static_cast<size_t>(parsed));
            }
            return result.empty() ? default_values : result;
        }

        vector<uint64_t> random_slots(size_t count, uint64_t modulus, mt19937_64 &random)
        {
            vector<uint64_t> result(count);
            generate(result.begin(), result.end(), [&]() { return random() % modulus; });
            return result;
        }

        void multiply_slots_inplace(vector<uint64_t> &left, const vector<uint64_t> &right, uint64_t modulus)
        {
            transform(left.begin(), left.end(), right.begin(), left.begin(), [&](uint64_t lhs, uint64_t rhs) {
                // Diagnostic plaintext moduli are at most 30 bits, so the product fits in uint64_t.
                return (lhs * rhs) % modulus;
            });
        }

        size_t mismatch_count(const vector<uint64_t> &expected, const vector<uint64_t> &actual)
        {
            return static_cast<size_t>(inner_product(
                expected.begin(), expected.end(), actual.begin(), uint64_t(0), plus<uint64_t>(),
                [](uint64_t lhs, uint64_t rhs) { return static_cast<uint64_t>(lhs != rhs); }));
        }

        void emit_diagnostic_header()
        {
            cout << "NO_SMRQ_CSV,mode,case,operation,trial,depth,n,k,q_bits,t_bits,t,base_B_size,ciphertext_size,"
                    "noise_before,noise_after,mismatches,slots,elapsed_us"
                 << endl;
        }

        void emit_diagnostic_row(
            const DiagnosticCase &diagnostic_case, const char *operation, size_t trial, size_t depth, size_t base_q_size,
            int coeff_modulus_bits, uint64_t plain_modulus, int plain_modulus_bits, size_t base_B_size,
            size_t ciphertext_size, int noise_before, int noise_after, size_t mismatches, size_t slot_count,
            int64_t elapsed_microseconds)
        {
            cout << "NO_SMRQ_CSV," << diagnostic_build_mode() << ',' << diagnostic_case.name << ',' << operation << ','
                 << trial << ',' << depth << ',' << diagnostic_case.poly_modulus_degree << ',' << base_q_size << ','
                 << coeff_modulus_bits << ',' << plain_modulus_bits << ',' << plain_modulus << ',' << base_B_size << ','
                 << ciphertext_size << ',' << noise_before << ',' << noise_after << ',' << mismatches << ',' << slot_count
                 << ',' << elapsed_microseconds << endl;
        }
    } // namespace

    TEST(BFVNoSmrqDiagnostics, AccuracyNoiseAndDepth)
    {
        const vector<DiagnosticCase> diagnostic_cases{
            { "n1024_k2_t15", 1024, { 27, 27, 27 }, 15, 3 },
            { "n2048_k3_t16", 2048, { 36, 36, 36, 36 }, 16, 3 },
            { "n2048_k3_t30", 2048, { 36, 36, 36, 36 }, 30, 2 },
            { "n4096_k4_t20", 4096, { 45, 45, 45, 45, 45 }, 20, 3 },
            { "n8192_k6_t20", 8192, { 50, 50, 50, 50, 50, 50, 50 }, 20, 3 }
        };

        emit_diagnostic_header();

        size_t trial_count = diagnostic_trial_count();
        for (size_t case_index = 0; case_index < diagnostic_cases.size(); case_index++)
        {
            const auto &diagnostic_case = diagnostic_cases[case_index];
            SCOPED_TRACE(diagnostic_case.name);

            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(diagnostic_case.poly_modulus_degree);
            parms.set_coeff_modulus(
                CoeffModulus::Create(diagnostic_case.poly_modulus_degree, diagnostic_case.coeff_modulus_bits));
            parms.set_plain_modulus(
                PlainModulus::Batching(diagnostic_case.poly_modulus_degree, diagnostic_case.plain_modulus_bits));

            prng_seed_type seed{ 0x534D5251ULL, 0x424656ULL, case_index, 1, 2, 3, 4, 5 };
            parms.set_random_generator(make_shared<Blake2xbPRNGFactory>(seed));

            SEALContext context(parms, true, sec_level_type::none);
            ASSERT_TRUE(context.parameters_set());

            auto context_data = context.first_context_data();
            const auto &data_parms = context_data->parms();
            size_t base_q_size = data_parms.coeff_modulus().size();
            int coeff_modulus_bits = context_data->total_coeff_modulus_bit_count();
            uint64_t plain_modulus = data_parms.plain_modulus().value();
            int plain_modulus_bits = data_parms.plain_modulus().bit_count();
            size_t base_B_size = context_data->rns_tool()->base_B()->size();

            KeyGenerator keygen(context);
            SecretKey secret_key = keygen.secret_key();
            PublicKey public_key;
            keygen.create_public_key(public_key);
            RelinKeys relin_keys;
            keygen.create_relin_keys(relin_keys);

            BatchEncoder encoder(context);
            Encryptor encryptor(context, public_key);
            Evaluator evaluator(context);
            Decryptor decryptor(context, secret_key);
            size_t slot_count = encoder.slot_count();
            mt19937_64 input_random(0x5EA10000ULL + case_index);

            for (size_t trial = 0; trial < trial_count; trial++)
            {
                auto left_slots = random_slots(slot_count, plain_modulus, input_random);
                auto right_slots = random_slots(slot_count, plain_modulus, input_random);
                auto expected = left_slots;
                multiply_slots_inplace(expected, right_slots, plain_modulus);

                Plaintext left_plain;
                Plaintext right_plain;
                encoder.encode(left_slots, left_plain);
                encoder.encode(right_slots, right_plain);

                Ciphertext left_encrypted;
                Ciphertext right_encrypted;
                encryptor.encrypt(left_plain, left_encrypted);
                encryptor.encrypt(right_plain, right_encrypted);
                int noise_before = min(
                    decryptor.invariant_noise_budget(left_encrypted),
                    decryptor.invariant_noise_budget(right_encrypted));

                auto start = chrono::steady_clock::now();
                evaluator.multiply_inplace(left_encrypted, right_encrypted);
                auto stop = chrono::steady_clock::now();

                int noise_after = decryptor.invariant_noise_budget(left_encrypted);
                Plaintext result_plain;
                vector<uint64_t> actual;
                decryptor.decrypt(left_encrypted, result_plain);
                encoder.decode(result_plain, actual);
                size_t mismatches = mismatch_count(expected, actual);
                auto elapsed = chrono::duration_cast<chrono::microseconds>(stop - start).count();

                emit_diagnostic_row(
                    diagnostic_case, "multiply", trial, 1, base_q_size, coeff_modulus_bits, plain_modulus,
                    plain_modulus_bits, base_B_size, left_encrypted.size(), noise_before, noise_after, mismatches,
                    slot_count, elapsed);
                EXPECT_EQ(size_t(0), mismatches) << "case=" << diagnostic_case.name << ", trial=" << trial;

                auto square_slots = random_slots(slot_count, plain_modulus, input_random);
                auto square_expected = square_slots;
                Plaintext square_plain;
                encoder.encode(square_slots, square_plain);
                Ciphertext square_encrypted;
                encryptor.encrypt(square_plain, square_encrypted);

                for (size_t depth = 1; depth <= diagnostic_case.max_depth; depth++)
                {
                    noise_before = decryptor.invariant_noise_budget(square_encrypted);
                    start = chrono::steady_clock::now();
                    evaluator.square_inplace(square_encrypted);
                    evaluator.relinearize_inplace(square_encrypted, relin_keys);
                    stop = chrono::steady_clock::now();
                    multiply_slots_inplace(square_expected, square_expected, plain_modulus);

                    noise_after = decryptor.invariant_noise_budget(square_encrypted);
                    decryptor.decrypt(square_encrypted, result_plain);
                    encoder.decode(result_plain, actual);
                    mismatches = mismatch_count(square_expected, actual);
                    elapsed = chrono::duration_cast<chrono::microseconds>(stop - start).count();

                    emit_diagnostic_row(
                        diagnostic_case, "square_relinearize", trial, depth, base_q_size, coeff_modulus_bits,
                        plain_modulus, plain_modulus_bits, base_B_size, square_encrypted.size(), noise_before,
                        noise_after, mismatches, slot_count, elapsed);
                    if (mismatches)
                    {
                        break;
                    }
                }

                auto chain_slots = random_slots(slot_count, plain_modulus, input_random);
                auto factor_slots = random_slots(slot_count, plain_modulus, input_random);
                auto chain_expected = chain_slots;
                Plaintext chain_plain;
                Plaintext factor_plain;
                encoder.encode(chain_slots, chain_plain);
                encoder.encode(factor_slots, factor_plain);
                Ciphertext chain_encrypted;
                Ciphertext factor_encrypted;
                encryptor.encrypt(chain_plain, chain_encrypted);
                encryptor.encrypt(factor_plain, factor_encrypted);

                for (size_t depth = 1; depth <= diagnostic_case.max_depth; depth++)
                {
                    noise_before = decryptor.invariant_noise_budget(chain_encrypted);
                    start = chrono::steady_clock::now();
                    evaluator.multiply_inplace(chain_encrypted, factor_encrypted);
                    stop = chrono::steady_clock::now();
                    multiply_slots_inplace(chain_expected, factor_slots, plain_modulus);

                    noise_after = decryptor.invariant_noise_budget(chain_encrypted);
                    decryptor.decrypt(chain_encrypted, result_plain);
                    encoder.decode(result_plain, actual);
                    mismatches = mismatch_count(chain_expected, actual);
                    elapsed = chrono::duration_cast<chrono::microseconds>(stop - start).count();

                    emit_diagnostic_row(
                        diagnostic_case, "multiply_chain", trial, depth, base_q_size, coeff_modulus_bits,
                        plain_modulus, plain_modulus_bits, base_B_size, chain_encrypted.size(), noise_before, noise_after,
                        mismatches, slot_count, elapsed);
                    if (mismatches)
                    {
                        break;
                    }
                }
            }
        }
    }

    TEST(BFVNoSmrqDiagnostics, N32768BatchingDepthSweep)
    {
        const char *enabled = getenv("SEAL_NO_SMRQ_RUN_N32768_SWEEP");
        if (!enabled || string(enabled) != "1")
        {
            return;
        }

        constexpr size_t poly_modulus_degree = 32768;
        size_t max_depth = diagnostic_size_from_environment("SEAL_NO_SMRQ_N32768_MAX_DEPTH", 12, 20);
        size_t prime_bit_count = diagnostic_size_from_environment("SEAL_NO_SMRQ_N32768_PRIME_BITS", 60, 60);
        size_t requested_plain_modulus_bits =
            diagnostic_size_from_environment("SEAL_NO_SMRQ_N32768_T_BITS", 17, 30);
        if (prime_bit_count < 20)
        {
            prime_bit_count = 20;
        }
        if (requested_plain_modulus_bits < 3)
        {
            requested_plain_modulus_bits = 3;
        }

        Modulus plain_modulus_object =
            PlainModulus::Batching(poly_modulus_degree, safe_cast<int>(requested_plain_modulus_bits));
        uint64_t plain_modulus = plain_modulus_object.value();
        int plain_modulus_bit_count = plain_modulus_object.bit_count();

        emit_diagnostic_header();
        auto k_values = diagnostic_k_values();
        size_t trial_count = diagnostic_trial_count();
        for (size_t k_index = 0; k_index < k_values.size(); k_index++)
        {
            size_t requested_base_q_size = k_values[k_index];
            vector<int> coeff_modulus_bits(requested_base_q_size + size_t(1), safe_cast<int>(prime_bit_count));
            string case_name = "n32768_k" + to_string(requested_base_q_size) + "_p" + to_string(prime_bit_count) +
                               "_t" + to_string(plain_modulus_bit_count);
            DiagnosticCase diagnostic_case{
                case_name, poly_modulus_degree, coeff_modulus_bits, plain_modulus_bit_count, max_depth
            };
            SCOPED_TRACE(case_name);

            EncryptionParameters parms(scheme_type::bfv);
            parms.set_poly_modulus_degree(poly_modulus_degree);
            parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, coeff_modulus_bits));
            parms.set_plain_modulus(plain_modulus_object);
            prng_seed_type seed{ 0x4E3332373638ULL, 0x534D5251ULL, requested_base_q_size, prime_bit_count,
                                 requested_plain_modulus_bits, 1, 2, 3 };
            parms.set_random_generator(make_shared<Blake2xbPRNGFactory>(seed));

            SEALContext context(parms, true, sec_level_type::tc128);
            ASSERT_TRUE(context.parameters_set());
            auto context_data = context.first_context_data();
            const auto &data_parms = context_data->parms();
            size_t base_q_size = data_parms.coeff_modulus().size();
            int coeff_modulus_bit_count = context_data->total_coeff_modulus_bit_count();
            size_t base_B_size = context_data->rns_tool()->base_B()->size();
            ASSERT_EQ(requested_base_q_size, base_q_size);

            KeyGenerator keygen(context);
            SecretKey secret_key = keygen.secret_key();
            PublicKey public_key;
            keygen.create_public_key(public_key);
            RelinKeys relin_keys;
            keygen.create_relin_keys(relin_keys);
            Encryptor encryptor(context, public_key);
            Evaluator evaluator(context);
            Decryptor decryptor(context, secret_key);
            BatchEncoder encoder(context);
            size_t slot_count = encoder.slot_count();
            mt19937_64 input_random(0x32768000ULL + k_index);

            for (size_t trial = 0; trial < trial_count; trial++)
            {
                vector<uint64_t> input_slots(slot_count);
                if (trial)
                {
                    input_slots = random_slots(slot_count, plain_modulus, input_random);
                }
                else
                {
                    fill(input_slots.begin(), input_slots.end(), plain_modulus / 2);
                }
                Plaintext input_plain;
                encoder.encode(input_slots, input_plain);

                Ciphertext square_encrypted;
                encryptor.encrypt(input_plain, square_encrypted);
                auto square_expected = input_slots;
                for (size_t depth = 1; depth <= max_depth; depth++)
                {
                    int noise_before = decryptor.invariant_noise_budget(square_encrypted);
                    auto start = chrono::steady_clock::now();
                    evaluator.square_inplace(square_encrypted);
                    evaluator.relinearize_inplace(square_encrypted, relin_keys);
                    auto stop = chrono::steady_clock::now();

                    multiply_slots_inplace(square_expected, square_expected, plain_modulus);
                    Plaintext actual_plain;
                    vector<uint64_t> actual_slots;
                    decryptor.decrypt(square_encrypted, actual_plain);
                    encoder.decode(actual_plain, actual_slots);
                    size_t mismatches = mismatch_count(square_expected, actual_slots);
                    int noise_after = decryptor.invariant_noise_budget(square_encrypted);
                    auto elapsed = chrono::duration_cast<chrono::microseconds>(stop - start).count();

                    emit_diagnostic_row(
                        diagnostic_case, "n32768_square_relinearize", trial, depth, base_q_size,
                        coeff_modulus_bit_count, plain_modulus, plain_modulus_bit_count, base_B_size,
                        square_encrypted.size(), noise_before, noise_after, mismatches, slot_count, elapsed);
                    if (mismatches)
                    {
                        break;
                    }
                }

                Ciphertext chain_encrypted;
                Ciphertext factor_encrypted;
                encryptor.encrypt(input_plain, chain_encrypted);
                encryptor.encrypt(input_plain, factor_encrypted);
                auto chain_expected = input_slots;
                for (size_t depth = 1; depth <= max_depth; depth++)
                {
                    int noise_before = decryptor.invariant_noise_budget(chain_encrypted);
                    auto start = chrono::steady_clock::now();
                    evaluator.multiply_inplace(chain_encrypted, factor_encrypted);
                    evaluator.relinearize_inplace(chain_encrypted, relin_keys);
                    auto stop = chrono::steady_clock::now();

                    multiply_slots_inplace(chain_expected, input_slots, plain_modulus);
                    Plaintext actual_plain;
                    vector<uint64_t> actual_slots;
                    decryptor.decrypt(chain_encrypted, actual_plain);
                    encoder.decode(actual_plain, actual_slots);
                    size_t mismatches = mismatch_count(chain_expected, actual_slots);
                    int noise_after = decryptor.invariant_noise_budget(chain_encrypted);
                    auto elapsed = chrono::duration_cast<chrono::microseconds>(stop - start).count();

                    emit_diagnostic_row(
                        diagnostic_case, "n32768_multiply_relinearize", trial, depth, base_q_size,
                        coeff_modulus_bit_count, plain_modulus, plain_modulus_bit_count, base_B_size,
                        chain_encrypted.size(), noise_before, noise_after, mismatches, slot_count, elapsed);
                    if (mismatches)
                    {
                        break;
                    }
                }
            }
        }
    }
} // namespace sealtest
