# gittest_vserv

SET(GITTEST_VSERV_HEADERS
  include/gittest/vserv_net.h
  ${GITTEST_LIB_HEADERS}
)
SET(GITTEST_VSERV_SOURCES
  src/vserv_net_nix.cpp
  ${GITTEST_LIB_SOURCES}
)

# search for all needed packages

## http://stackoverflow.com/questions/1620918/cmake-and-libpthread/29871891#29871891
## https://cmake.org/cmake/help/v3.6/module/FindThreads.html
##   extra magic for gcc linking with pthreads (-pthread)

SET(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)

SET(GITTEST_DEP_INCLUDE_DIRS
)
SET (GITTEST_DEP_LIBRARIES
  Threads::Threads
)

SET(GITTEST_SELFUP_INCLUDE_DIRS
  ${CMAKE_SOURCE_DIR}/include
  ${GITTEST_COMMON_PREFIX}/include
  ${GITTEST_DEP_INCLUDE_DIRS}
)

# define targets

ADD_EXECUTABLE(gittest_vserv ${GITTEST_VSERV_HEADERS} ${GITTEST_VSERV_SOURCES})

SET_PROPERTY(TARGET gittest_vserv PROPERTY SUFFIX ".exe")

TARGET_LINK_LIBRARIES(gittest_vserv gittest_common ${GITTEST_DEP_LIBRARIES})

TARGET_INCLUDE_DIRECTORIES(gittest_vserv PUBLIC ${GITTEST_SELFUP_INCLUDE_DIRS})
