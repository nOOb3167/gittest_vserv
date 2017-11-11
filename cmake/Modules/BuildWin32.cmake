# other platform headers and sources (for dummylib)

SET(GITTEST_PLAT_HEADERS_NIX
  include/gittest/vserv_net.h
  ${GITTEST_COMMON_HEADERS_NIX}
)
SET(GITTEST_PLAT_SOURCES_NIX
  src/vserv_net_nix.cpp
  src/vserv_net_main.cpp
  src/vserv_crank0.cpp
  ${GITTEST_COMMON_SOURCES_NIX}
)

# search for all needed packages

SET(GITTEST_DEP_INCLUDE_DIRS
)
SET (GITTEST_DEP_LIBRARIES
)

SET(GITTEST_SELFUP_INCLUDE_DIRS
  ${CMAKE_SOURCE_DIR}/include
  ${GITTEST_COMMON_PREFIX}/include
  ${GITTEST_DEP_INCLUDE_DIRS}
)

# define targets

ADD_LIBRARY(dummy_lib STATIC EXCLUDE_FROM_ALL ${GITTEST_PLAT_HEADERS_NIX} ${GITTEST_PLAT_SOURCES_NIX})

TARGET_INCLUDE_DIRECTORIES(dummy_lib PUBLIC ${GITTEST_SELFUP_INCLUDE_DIRS})

# cruft

#### dummy_lib sources should be marked for no compilation

SET_SOURCE_FILES_PROPERTIES(${GITTEST_PLAT_HEADERS_NIX} ${GITTEST_PLAT_SOURCES_NIX} PROPERTIES HEADER_FILE_ONLY TRUE)
