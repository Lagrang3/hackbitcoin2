add_library(bitcoin
	    crypto/ripemd160.cpp
	    util/spanparsing.cpp
	    util/strencodings.cpp
	    util/string.cpp
)
target_include_directories(bitcoin PUBLIC "${CMAKE_SOURCE_DIR}/src")
set_target_properties(bitcoin
	PROPERTIES
	INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/src"
)
