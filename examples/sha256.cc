#include <sodium.h>

#include <array>
#include <iostream>
#include <string>
#include <vector>

int main(void) {
	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized; it is not safe to
		 * use */
		exit(1);
	}
	std::string s;
	// read a text from stdin
	std::cin >> s;
	std::vector<unsigned char> s_data(s.begin(), s.end());
	
	// hash it
	std::array<unsigned char, crypto_hash_sha256_BYTES> s_hash;
	crypto_hash_sha256(s_hash.data(), s_data.data(), s.size());
	
	// print it in hex
	std::array<char, 2 * crypto_hash_sha256_BYTES + 1> s_hash_hex;
	sodium_bin2hex(s_hash_hex.data(), s_hash_hex.size(), s_hash.data(),
		       s_hash.size());
	std::cout << s_hash_hex.data() << std::endl;
	return 0;
}
