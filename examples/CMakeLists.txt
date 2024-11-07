add_executable(sha256 sha256.cpp)
target_link_libraries(sha256 bitcoin)

add_executable(ecc ecc.cpp)
target_link_libraries(ecc bitcoin)

add_executable(keyhunt keyhunt.cpp)
target_link_libraries(keyhunt bitcoin)
