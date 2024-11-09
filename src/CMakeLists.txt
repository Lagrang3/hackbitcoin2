add_library(bitcoin
	    base58.cpp
	    hash.cpp
	    uint256.cpp
	    crypto/hmac_sha512.cpp
	    crypto/ripemd160.cpp
	    crypto/sha256.cpp
	    crypto/sha512.cpp
	    util/spanparsing.cpp
	    util/strencodings.cpp
	    util/string.cpp
)
target_include_directories(bitcoin PUBLIC "${CMAKE_SOURCE_DIR}/src")
set_target_properties(bitcoin
	PROPERTIES
	INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/src"
)
