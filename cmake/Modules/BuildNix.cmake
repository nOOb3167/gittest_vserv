# gittest_vserv

SET(GITTEST_VSERV_HEADERS
  include/gittest/vserv_net.h
  include/gittest/vserv_helpers.h
  ${GITTEST_LIB_HEADERS}
)
SET(GITTEST_VSERV_SOURCES
  src/vserv_net_nix.cpp
  src/vserv_enet.cpp
  src/vserv_net_main.cpp
  src/vserv_crank0.cpp
  src/vserv_helpers.cpp
  ${GITTEST_LIB_SOURCES}
)

SET(GITTEST_VSERV_CLNT_TEST_HEADERS
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
  src/vserv_clnt_test.cpp
  src/vserv_helpers.cpp
  ${GITTEST_LIB_SOURCES}
)

# search for all needed packages

FIND_PACKAGE(ENet REQUIRED)

## http://stackoverflow.com/questions/1620918/cmake-and-libpthread/29871891#29871891
## https://cmake.org/cmake/help/v3.6/module/FindThreads.html
##   extra magic for gcc linking with pthreads (-pthread)

SET(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)

SET(GITTEST_DEP_INCLUDE_DIRS
  ${ENET_INCLUDE_DIR}
)
SET (GITTEST_DEP_LIBRARIES
  ${ENET_LIBRARIES}
  Threads::Threads
)

SET(GITTEST_VSERV_INCLUDE_DIRS
  ${CMAKE_SOURCE_DIR}/include
  ${GITTEST_COMMON_PREFIX}/include
  ${GITTEST_DEP_INCLUDE_DIRS}
)

# define targets

ADD_EXECUTABLE(gittest_vserv ${GITTEST_VSERV_HEADERS} ${GITTEST_VSERV_SOURCES})
#ADD_EXECUTABLE(gittest_vserv_clnt_test ${GITTEST_VSERV_CLNT_TEST_HEADERS} ${GITTEST_VSERV_CLNT_TEST_SOURCES})

SET_PROPERTY(TARGET gittest_vserv PROPERTY SUFFIX ".exe")
#SET_PROPERTY(TARGET gittest_vserv_clnt_test PROPERTY SUFFIX ".exe")

TARGET_LINK_LIBRARIES(gittest_vserv gittest_common ${GITTEST_DEP_LIBRARIES})
#TARGET_LINK_LIBRARIES(gittest_vserv_clnt_test gittest_common ${GITTEST_DEP_LIBRARIES})

TARGET_INCLUDE_DIRECTORIES(gittest_vserv PUBLIC ${GITTEST_VSERV_INCLUDE_DIRS})
#TARGET_INCLUDE_DIRECTORIES(gittest_vserv_clnt_test PUBLIC ${GITTEST_VSERV_INCLUDE_DIRS})
