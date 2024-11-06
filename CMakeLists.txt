cmake_minimum_required(VERSION 3.10)
project(hackbitcoin
	VERSION 2.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

configure_file(config.h.in config.h)

add_custom_target(libsodium_build ALL
	COMMAND mkdir -p "${CMAKE_CURRENT_BINARY_DIR}/libsodium_build" &&
		cd "${CMAKE_CURRENT_SOURCE_DIR}/external/libsodium" &&
		./autogen.sh -s &&
		./configure --prefix="${CMAKE_CURRENT_BINARY_DIR}/libsodium_build" &&
		make &&
		make install
)
add_library(libsodium STATIC IMPORTED)
set_target_properties(libsodium
	PROPERTIES
	IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/libsodium_build/lib/libsodium.a"
	INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_BINARY_DIR}/libsodium_build/include"
)
add_dependencies(libsodium libsodium_build)
add_subdirectory(examples)
