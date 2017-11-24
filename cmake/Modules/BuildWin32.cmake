# other platform headers and sources (for dummylib)

SET(GITTEST_PLAT_HEADERS_NIX
  ${GITTEST_COMMON_HEADERS_NIX}
)
SET(GITTEST_PLAT_SOURCES_NIX
  src/vserv_net_nix.cpp
  src/vserv_enet.cpp
  src/vserv_net_main.cpp
  src/vserv_crank0.cpp
  ${GITTEST_COMMON_SOURCES_NIX}
)

SET(GITTEST_VSERV_CLNT_TEST_HEADERS
  include/gittest/vserv_net.h
  include/gittest/vserv_record.h
  include/gittest/vserv_playback.h
  include/gittest/vserv_clnt.h
  include/gittest/vserv_helpers.h
  include/gittest/UDPSocket.hpp
  ${GITTEST_LIB_HEADERS}
)
SET(GITTEST_VSERV_CLNT_TEST_SOURCES
  src/vserv_record.cpp
  src/vserv_playback.cpp
  src/vserv_clnt.cpp
  src/vserv_helpers.cpp
  src/vserv_clnt_test.cpp
  ${GITTEST_LIB_SOURCES}
)

# search for all needed packages

FIND_PACKAGE(ENet REQUIRED)
FIND_PACKAGE(OpenAL REQUIRED)

SET(GITTEST_DEP_INCLUDE_DIRS
  ${ENET_INCLUDE_DIR}
  ${OPENAL_INCLUDE_DIR}
)
SET (GITTEST_DEP_LIBRARIES
  ${ENET_LIBRARIES}
  ${OPENAL_LIBRARY}
)

SET(GITTEST_VSERV_INCLUDE_DIRS
  ${CMAKE_SOURCE_DIR}/include
  ${GITTEST_COMMON_PREFIX}/include
  ${GITTEST_DEP_INCLUDE_DIRS}
)

# define targets

ADD_EXECUTABLE(gittest_vserv_clnt_test ${GITTEST_VSERV_CLNT_TEST_HEADERS} ${GITTEST_VSERV_CLNT_TEST_SOURCES})
ADD_LIBRARY(dummy_lib STATIC EXCLUDE_FROM_ALL ${GITTEST_PLAT_HEADERS_NIX} ${GITTEST_PLAT_SOURCES_NIX})

SET_PROPERTY(TARGET gittest_vserv_clnt_test PROPERTY SUFFIX ".exe")

TARGET_LINK_LIBRARIES(gittest_vserv_clnt_test gittest_common ${GITTEST_DEP_LIBRARIES})

TARGET_INCLUDE_DIRECTORIES(gittest_vserv_clnt_test PUBLIC ${GITTEST_VSERV_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(dummy_lib PUBLIC ${GITTEST_VSERV_INCLUDE_DIRS})

### AL_LIBTYPE_STATIC defined for static linking with OpenAL (msvc quirk)
TARGET_COMPILE_DEFINITIONS(gittest_vserv_clnt_test PUBLIC "-DAL_LIBTYPE_STATIC")

# cruft

#### dummy_lib sources should be marked for no compilation

SET_SOURCE_FILES_PROPERTIES(${GITTEST_PLAT_HEADERS_NIX} ${GITTEST_PLAT_SOURCES_NIX} PROPERTIES HEADER_FILE_ONLY TRUE)
