#include <sodium.h>

#include <array>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

int main(void) {
	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized; it is not safe to
		 * use */
		exit(1);
	}
	// read a text from stdin
	std::string s = "hello!";
	std::vector<unsigned char> s_data(s.begin(), s.end());

	// hash it
	std::array<unsigned char, crypto_hash_sha256_BYTES> s_hash;
	crypto_hash_sha256(s_hash.data(), s_data.data(), s.size());

	// print it in hex
	std::array<char, 2 * crypto_hash_sha256_BYTES + 1> s_hash_hex;
	sodium_bin2hex(s_hash_hex.data(), s_hash_hex.size(), s_hash.data(),
		       s_hash.size());
	assert(
	    std::string(s_hash_hex.data()) ==
	    "ce06092fb948d9ffac7d1a376e404b26b7575bcc11ee05a4615fef4fec3a308b");
	return 0;
}
