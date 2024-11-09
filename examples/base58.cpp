#include "base58.h"

#include <vector>
#include <iostream>
#include <string>

int main(){
	std::vector<unsigned char> input({0xf0, 0x0b, 0xa4});
	// should print "2PdTq"
	std::cout << EncodeBase58(input) << std::endl;
	return 0;
}
