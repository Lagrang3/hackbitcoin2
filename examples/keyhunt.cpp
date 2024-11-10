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
#include "uint256.h"
#include "util/strencodings.h"

secp256k1_context *ctx;

typedef uint256 seckey;

seckey seckey_from_num(std::uint64_t x) {
	seckey k;
	std::fill(k.begin(), k.end(), 0);
	for (int i = 0; x && i < k.size(); i++) {
		k.data()[i] = x & 0xff;
		x >>= 8;
	}
	std::reverse(k.begin(), k.end());
	return k;
}

std::string address(const secp256k1_pubkey &pk) {
	std::array<unsigned char, 33> compressed_pubkey;
	size_t compressed_pubkey_len = compressed_pubkey.size();
	secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey.data(),
				      &compressed_pubkey_len, &pk,
				      SECP256K1_EC_COMPRESSED);

	std::array<unsigned char, 21> keyhash;
	keyhash[0] = 0x00;
	CHash160()
	    .Write(compressed_pubkey)
	    .Finalize(Span(keyhash.begin() + 1, keyhash.end()));
	return EncodeBase58Check(keyhash);
}

void describe_key(const seckey &k) {
	secp256k1_pubkey pk;
	if (!secp256k1_ec_pubkey_create(ctx, &pk, k.data())) {
		return;
	}
	std::cout << "priv key: " << HexStr(k) << "\n"
		  << "WIF: "
		  << "..."
		  << "\n"
		  << "address: " << address(pk) << std::endl;
}

bool khash_equal(Span<unsigned char> s1, Span<unsigned char> s2) {
	size_t n = s1.size();
	if (n != s2.size()) return false;
	for (size_t i = 0; i < n; i++)
		if (s1[i] != s2[i]) return false;
	return true;
}

seckey &operator++(seckey &k) {
	int carry = 1;
	for (int i = k.size() - 1; i >= 0 && carry; i--) {
		k.data()[i] += carry;
		carry = k.data()[i] ? 0 : 1;
	}
	return k;
}

int main(void) {
	// initialize cryptographic libraries
	seckey randomize;
	getrandom(randomize.data(), randomize.size(), 0);

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (!secp256k1_context_randomize(ctx, randomize.data())) {
		std::cerr << "Failed to inizialize libsecp256k1" << std::endl;
		return 1;
	}

	std::string address = "1PgQVLmst3Z314JrQn5TNiys8Hc38TcXJu";
	std::vector<unsigned char> target_keyhash(21);
	if (!DecodeBase58Check(address, target_keyhash,
			       target_keyhash.size())) {
		std::cerr << "panic: could not decode address to keyhash"
			  << std::endl;
		return 1;
	}

	const int search_bits = 11;
	seckey keymask;

	{
		int bits = search_bits;
		for (int i = keymask.size() - 1; i >= 0; i--) {
			unsigned char val = 0;
			if (bits >= 8) {
				val = 0xff;
				bits -= 8;
			} else if (bits == 0) {
				val = 0x00;
			} else {
				val = (1 << (bits)) - 1;
				bits = 0;
			}
			keymask.data()[i] = val;
		}
	}
	std::cout << "my mask: " << HexStr(keymask) << std::endl;

	seckey k = seckey::ONE;
	secp256k1_pubkey pk;
	std::array<unsigned char, 33> compressed_pubkey;
	size_t pubkey_len = compressed_pubkey.size();
	std::array<unsigned char, 21> keyhash;
	keyhash[0] = 0x00;
	for (size_t i = 0;; i++) {
		// new "random number"
		++randomize;

		// apply mask
		std::transform(
		    randomize.begin(), randomize.end(), keymask.begin(),
		    k.begin(),
		    [](unsigned char a, unsigned char b) { return a & b; });

		if (!secp256k1_ec_pubkey_create(ctx, &pk, k.data())) {
			// std::cerr << "panic: invalid private key" <<
			// std::endl; return 1;
			continue;
		}
		// std::cout << "testing key: " << HexStr(k) << std::endl;

		secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey.data(),
					      &pubkey_len, &pk,
					      SECP256K1_EC_COMPRESSED);
		CHash160()
		    .Write(compressed_pubkey)
		    .Finalize(Span(keyhash.begin() + 1, keyhash.end()));

		if (khash_equal(keyhash, target_keyhash)) {
			std::cout << "found key!\n";
			describe_key(k);
			break;
		}
	}
	return 0;
}
