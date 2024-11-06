#include <sodium.h>

#include <iostream>

int main(void) {
	std::cout << "hello world" << std::endl;
	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized; it is not safe to
		 * use */
		exit(1);
	}
	std::cout << "started sodium" << std::endl;
	return 0;
}
