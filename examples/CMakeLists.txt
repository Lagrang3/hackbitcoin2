add_executable(sha256 sha256.cc)
target_link_libraries(sha256 PUBLIC libsodium)
