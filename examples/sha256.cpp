#include "crypto/sha256.h"
#include "util/strencodings.h"

#include <iostream>
#include <string>
#include <vector>

int main(void) {
	std::string s = "Hello!";
	std::vector<unsigned char> input(s.begin(),s.end());
	std::vector<unsigned char> result(32);
	CSHA256().Write(input.data(), input.size()).Finalize(result.data());

	// should print "334d016f755cd6dc58c53a86e183882f8ec14f52fb05345887c8a5edd42c87b7"
	std::cout << HexStr(result) << std::endl;
	return 0;
}
