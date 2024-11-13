#include <sys/random.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
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

std::string wif(const seckey &k) {
	std::array<unsigned char, 34> rawkey;
	rawkey[0] = 0x80;
	rawkey[rawkey.size() - 1] = 0x01;
	std::copy(k.begin(), k.end(), rawkey.data() + 1);
	return EncodeBase58Check(rawkey);
}

void describe_key(const seckey &k) {
	secp256k1_pubkey pk;
	if (!secp256k1_ec_pubkey_create(ctx, &pk, k.data())) {
		return;
	}
	std::cout << "priv key: " << HexStr(k) << "\n"
		  << "wif: " << wif(k) << "\n"
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
seckey &operator+=(seckey &k, int x) {
	for (int i = k.size() - 1; i >= 0 && x; i--) {
		x += k.data()[i];
		k.data()[i] = x & 0xff;
		x >>= 8;
	}
	return k;
}

void build_masks(seckey &mask, int bits) {
	for (int i = mask.size() - 1; i >= 0; i--) {
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
		mask.data()[i] = val;
	}
}

auto read_puzzle(std::string fname) {
	std::ifstream ifs(fname);
	std::vector<std::string> v;
	std::string s;
	while (ifs >> s) {
		v.push_back(s);
	}
	return v;
}

void show_help() {
	std::cerr << "Usage:"
		  << " keyhunt num_puzze [num_threads]" << std::endl;
}

std::mutex write_solution;
bool solution_found;
seckey solution;
size_t global_iteration;

std::string thread_log(int thread_idx) {
	std::stringstream s;

	time_t t = time(NULL);
	struct tm gm = *gmtime(&t);
	std::array<char, 256> buff;
	strftime(buff.data(), buff.size(), "%F %T", &gm);

	s << "[" << buff.data() << "] "
	  << "thread " << thread_idx << ": ";
	return s.str();
}

void solve(seckey mask, seckey kinit, std::vector<unsigned char> target_keyhash,
	   int thread_idx) {
	// {
	// 	std::lock_guard<std::mutex> guard(write_solution);
	// 	std::cout << "Initial seed: " << HexStr(kinit) << std::endl;
	// }

	seckey k;
	seckey mask2 = mask;
	++mask2;  // mask2 = 1+ mask, eg. if mask=0xff, then mask2=0x0100

	std::array<unsigned char, 21> keyhash;
	keyhash[0] = 0x00;

	secp256k1_pubkey pk;
	std::array<unsigned char, 33> compressed_pubkey;
	size_t pubkey_len = compressed_pubkey.size();
	const size_t log_step = 1000000;
	const size_t suffle_step = log_step * 10;

	for (size_t i = 0;; i++) {
		if (solution_found) return;

		// new "random number"
		if (i % suffle_step == 0 && i)
			CSHA256()
			    .Write(kinit.data(), kinit.size())
			    .Finalize(kinit.data());
		else
			++kinit;

		// apply mask
		std::transform(
		    kinit.begin(), kinit.end(), mask.begin(), k.begin(),
		    [](unsigned char a, unsigned char b) { return a & b; });
		std::transform(
		    k.begin(), k.end(), mask2.begin(), k.begin(),
		    [](unsigned char a, unsigned char b) { return a | b; });

		if (i % log_step == 0 && i) {
			std::lock_guard<std::mutex> guard(write_solution);
			global_iteration++;
			std::cout << thread_log(thread_idx) << "iteration "
				  << global_iteration << "M, key " << HexStr(k)
				  << std::endl;
		}

		if (!secp256k1_ec_pubkey_create(ctx, &pk, k.data())) {
			std::lock_guard<std::mutex> guard(write_solution);
			std::cerr << "invalid private key\n";
			continue;
		}
		secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey.data(),
					      &pubkey_len, &pk,
					      SECP256K1_EC_COMPRESSED);
		CHash160()
		    .Write(compressed_pubkey)
		    .Finalize(Span(keyhash.begin() + 1, keyhash.end()));

		if (khash_equal(keyhash, target_keyhash)) {
			std::lock_guard<std::mutex> guard(write_solution);
			std::cout << thread_log(thread_idx) << "found key!\n";
			solution = k;
			solution_found = true;
			return;
		}
	}
}

int main(int argc, char *argv[]) {
	// initialize cryptographic libraries
	seckey randomize;
	getrandom(randomize.data(), randomize.size(), 0);

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (!secp256k1_context_randomize(ctx, randomize.data())) {
		std::cerr << "Failed to inizialize libsecp256k1" << std::endl;
		return 1;
	}

	if (argc < 2) {
		show_help();
		return 1;
	}
	int num_threads = 1;
	int npuzzle = std::atoi(argv[1]);
	auto puzzle = read_puzzle("puzzle.txt");
	std::string target_address = puzzle[npuzzle];

	if (argc == 3) num_threads = std::atoi(argv[2]);

	if (argc > 3) {
		show_help();
		return 1;
	}

	std::cout << "solving puzzle: " << target_address << "\n"
		  << "num bits: " << npuzzle << std::endl;

	std::vector<unsigned char> target_keyhash(21);
	if (!DecodeBase58Check(target_address, target_keyhash,
			       target_keyhash.size())) {
		std::cerr << "panic: could not decode address to keyhash"
			  << std::endl;
		return 1;
	}

	seckey keymask;
	build_masks(keymask, npuzzle);

	solution_found = false;
	std::vector<std::thread> t(num_threads);
	for (int i = 0; i < num_threads; i++) {
		seckey kinit;  // initial key is different for every thread
		getrandom(kinit.data(), kinit.size(), 0);
		t[i] = std::thread(solve, keymask, kinit, target_keyhash, i);
	}
	for (int i = 0; i < num_threads; i++) t[i].join();
	describe_key(solution);
	return 0;
}
