add_executable(sha256 sha256.cc)
target_link_libraries(sha256 sodium)

add_executable(ecc ecc.cc)
target_link_libraries(ecc secp256k1 sodium)
