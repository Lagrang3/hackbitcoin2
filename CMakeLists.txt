cmake_minimum_required(VERSION 3.10)
project(hackbitcoin
	VERSION 2.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

configure_file(config.h.in config.h)

add_subdirectory(src)
add_subdirectory(examples)
