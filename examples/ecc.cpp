#include <secp256k1.h>
#include <sodium.h>
#include <sys/random.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>

typedef std::array<unsigned char, 32> seckey;

seckey seckey_from_num(std::uint64_t x) {
	seckey k;
	std::fill(k.begin(), k.end(), 0);
	for (int i = 0; x && i < k.size(); i++) {
		k[i] = x & 0xff;
		x >>= 8;
	}
	std::reverse(k.begin(), k.end());
	return k;
}

int main(void) {
	int return_val;

	// initialize cryptographic libraries
	std::array<unsigned char, 32> randomize;
	getrandom(randomize.data(), randomize.size(), 0);

	secp256k1_context *ctx =
	    secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (!secp256k1_context_randomize(ctx, randomize.data())) {
		std::cerr << "Failed to inizialize libsecp256k1" << std::endl;
		return 1;
	}

	if (sodium_init() < 0) {
		std::cerr << "Failed to inizialize libsodium" << std::endl;
		return 1;
	}

	std::array<unsigned char, 32> k = seckey_from_num(5001);
	if (!secp256k1_ec_seckey_verify(ctx, k.data())) {
		std::cerr << "Bad secret key" << std::endl;
		return 1;
	}

	secp256k1_pubkey pk;
	if (!secp256k1_ec_pubkey_create(ctx, &pk, k.data())) {
		std::cerr << "Failed to create pubkey" << std::endl;
		return 1;
	}
	std::array<unsigned char, 65> compressed_pubkey;
	size_t compressed_pubkey_len = compressed_pubkey.size();
	if (!secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey.data(),
					   &compressed_pubkey_len, &pk,
					   SECP256K1_EC_COMPRESSED)) {
		std::cerr << "Failed to serialize pubkey" << std::endl;
		return 1;
	}

	// print it in hex
	std::array<char, 2 * compressed_pubkey.size() + 1>
	    compressed_pubkey_hex;
	sodium_bin2hex(compressed_pubkey_hex.data(),
		       compressed_pubkey_hex.size(), compressed_pubkey.data(),
		       compressed_pubkey_len);
	assert(std::string(compressed_pubkey_hex.data()) ==
	       "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e5"
	       "3d1");
	return 0;
}

