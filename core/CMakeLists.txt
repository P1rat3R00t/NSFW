cmake_minimum_required(VERSION 3.10)
project(NSFWCore LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source and header files
set(SOURCES
    nsfw.cpp
)
set(HEADERS
    nsfw.h
)

add_executable(nsfw_core ${SOURCES} ${HEADERS})

# If you have include directories, uncomment and adjust the following line:
# target_include_directories(nsfw_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
