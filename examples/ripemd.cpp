#include "crypto/ripemd160.h"
#include "util/strencodings.h"

#include <iostream>
#include <string>
#include <vector>

int main(void) {
	std::string s = "Hello!";
	std::vector<unsigned char> input(s.begin(),s.end());
	std::vector<unsigned char> result(20);
	CRIPEMD160().Write(input.data(), input.size()).Finalize(result.data());

	// should print "9bceee7d9f02b24fc0115d96d3fc89b5a2ded213"
	std::cout << HexStr(result) << std::endl;
	return 0;
}
