cmake_minimum_required(VERSION 3.10)
project(hackbitcoin
	VERSION 2.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

configure_file(config.h.in config.h)

find_library(sodium sodium)

add_subdirectory(examples)
