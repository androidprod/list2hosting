cmake_minimum_required(VERSION 3.10)
project(list2hosting LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(list2hosting main.cpp)

if(WIN32)
  target_link_libraries(list2hosting PRIVATE ws2_32 crypt32 advapi32)
else()
  find_package(OpenSSL REQUIRED)
  if(OpenSSL_FOUND)
    target_link_libraries(list2hosting PRIVATE OpenSSL::Crypto pthread)
  else()
    message(FATAL_ERROR "OpenSSL not found - install libssl-dev or equivalent")
  endif()
endif()
