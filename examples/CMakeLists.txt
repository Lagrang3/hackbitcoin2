add_executable(sha256 sha256.cpp)
target_link_libraries(sha256 bitcoin)

add_executable(ecc ecc.cpp)
target_link_libraries(ecc bitcoin secp256k1)

# add_executable(keyhunt keyhunt.cpp)
# target_link_libraries(keyhunt bitcoin)

add_executable(base58 base58.cpp)
target_link_libraries(base58 bitcoin)

add_executable(ripemd ripemd.cpp)
target_link_libraries(ripemd bitcoin)

add_executable(p2pkh-address p2pkh-address.cpp)
target_link_libraries(p2pkh-address bitcoin secp256k1)

add_executable(keyhunt keyhunt.cpp)
target_link_libraries(keyhunt bitcoin secp256k1)
