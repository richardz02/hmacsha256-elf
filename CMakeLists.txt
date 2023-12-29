cmake_minimum_required(VERSION 3.12)
project(arc-readelf)

# Add your source files
add_executable(main main.cpp)

# Find the elfio package
find_package(elfio REQUIRED)

# Include Crypto++ headers
target_include_directories(main PRIVATE ${CRYPTOPP_INCLUDE_DIR})

# Link your executable with elfio
target_link_libraries(main PRIVATE elfio::elfio ${CRYPTOPP_LIBRARIES})
