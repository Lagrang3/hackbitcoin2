#include <sys/random.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

#include "base58.h"
#include "hash.h"
#include "secp256k1.h"
#include "util/strencodings.h"

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
	std::vector<unsigned char> randomize(32);
	getrandom(randomize.data(), randomize.size(), 0);

	secp256k1_context *ctx =
	    secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (!secp256k1_context_randomize(ctx, randomize.data())) {
		std::cerr << "Failed to inizialize libsecp256k1" << std::endl;
		return 1;
	}

	seckey k = seckey_from_num(1);
	if (!secp256k1_ec_seckey_verify(ctx, k.data())) {
		std::cerr << "Bad secret key" << std::endl;
		return 1;
	}

	secp256k1_pubkey pk;
	if (!secp256k1_ec_pubkey_create(ctx, &pk, k.data())) {
		std::cerr << "Failed to create pubkey" << std::endl;
		return 1;
	}
	std::array<unsigned char, 33> compressed_pubkey;
	size_t compressed_pubkey_len = compressed_pubkey.size();
	if (!secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey.data(),
					   &compressed_pubkey_len, &pk,
					   SECP256K1_EC_COMPRESSED)) {
		std::cerr << "Failed to serialize pubkey" << std::endl;
		return 1;
	}
	std::array<unsigned char, 21> keyhash;
	keyhash[0] = 0x00;
	CHash160()
	    .Write(compressed_pubkey)
	    .Finalize(Span(keyhash.begin() + 1, keyhash.end()));
	std::string address = EncodeBase58Check(keyhash);
	std::cout << "address: " << address << std::endl;
	return 0;
}

