cmake_minimum_required(VERSION 3.10)
project(hackbitcoin
	VERSION 2.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

configure_file(config.h.in config.h)

find_library(sodium sodium)

add_custom_target(secp256k1_build ALL
	COMMAND mkdir -p "${CMAKE_CURRENT_BINARY_DIR}/secp256k1_build" &&
		cd "${CMAKE_CURRENT_SOURCE_DIR}/external/secp256k1" &&
		./autogen.sh &&
		./configure --prefix="${CMAKE_CURRENT_BINARY_DIR}/secp256k1_build" &&
		make &&
		make install
)
add_library(secp256k1 STATIC IMPORTED)
add_dependencies(secp256k1 secp256k1_build)
set_target_properties(secp256k1
	PROPERTIES
	IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/secp256k1_build/lib/libsecp256k1.a"
	INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/external/secp256k1/include"
)

add_subdirectory(examples)
