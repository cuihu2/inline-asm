#include <seal/seal.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

int main()
{
    using namespace seal;

    constexpr std::size_t kN = 4096;
    constexpr std::uint64_t kT = 65537;
    EncryptionParameters parameters(scheme_type::bfv);
    parameters.set_poly_modulus_degree(kN);
    parameters.set_coeff_modulus(CoeffModulus::BFVDefault(kN));
    parameters.set_plain_modulus(kT);
    SEALContext context(parameters);
    if (!context.parameters_set()) {
        throw std::runtime_error("modified SEAL rejected the BFV oracle parameters");
    }

    KeyGenerator key_generator(context);
    const SecretKey secret_key = key_generator.secret_key();
    PublicKey public_key;
    RelinKeys relin_keys;
    key_generator.create_public_key(public_key);
    key_generator.create_relin_keys(relin_keys);

    BatchEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    const std::size_t slots = encoder.slot_count();
    std::vector<std::uint64_t> left(slots);
    std::vector<std::uint64_t> right(slots);
    std::vector<std::uint64_t> expected(slots);
    for (std::size_t slot = 0; slot < slots; ++slot) {
        const std::int64_t centered_left =
            static_cast<std::int64_t>((3 * slot + 1) % 17) - 8;
        const std::int64_t centered_right =
            static_cast<std::int64_t>((5 * slot + 2) % 19) - 9;
        left[slot] = centered_left >= 0
            ? static_cast<std::uint64_t>(centered_left)
            : kT - static_cast<std::uint64_t>(-centered_left);
        right[slot] = centered_right >= 0
            ? static_cast<std::uint64_t>(centered_right)
            : kT - static_cast<std::uint64_t>(-centered_right);
        expected[slot] = (left[slot] * right[slot]) % kT;
    }

    Plaintext left_plain;
    Plaintext right_plain;
    encoder.encode(left, left_plain);
    encoder.encode(right, right_plain);
    Ciphertext left_cipher;
    Ciphertext right_cipher;
    encryptor.encrypt(left_plain, left_cipher);
    encryptor.encrypt(right_plain, right_cipher);

    evaluator.multiply_inplace(left_cipher, right_cipher);
    evaluator.relinearize_inplace(left_cipher, relin_keys);
    evaluator.mod_switch_to_next_inplace(left_cipher);

    Plaintext result_plain;
    decryptor.decrypt(left_cipher, result_plain);
    std::vector<std::uint64_t> actual;
    encoder.decode(result_plain, actual);
    if (actual != expected) {
        throw std::runtime_error(
            "modified SEAL no-SMRQ/branchless-SK BFV oracle mismatch");
    }

    std::cout << "Modified SEAL BFV oracle: PASS\n";
    return 0;
}
