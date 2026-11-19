cmake_minimum_required(VERSION 3.22.1)
project(mobshieldcore)

# mobshield_buildinfo.h comes from the generated directory when Gradle passes one, otherwise from
# stub/. It is kept out of this directory because a quoted #include searches the including file's
# directory first, so a copy here would always shadow the generated header.
set(MOBSHIELD_GENERATED_INCLUDE_DIR "" CACHE STRING "Generated headers directory")
if (MOBSHIELD_GENERATED_INCLUDE_DIR STREQUAL "")
    set(MOBSHIELD_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/stub")
endif()

add_library(mobshieldcore SHARED
    mobshield_jni.cpp
    mobshield_native.cpp
)

target_include_directories(mobshieldcore PRIVATE
    ${MOBSHIELD_GENERATED_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(mobshieldcore PRIVATE cxx_std_17)

find_library(log-lib log)
target_link_libraries(mobshieldcore ${log-lib})

include(${CMAKE_CURRENT_LIST_DIR}/../../../../native/cmake/MobShield16kPages.cmake)
mobshield_enable_16k_pages(mobshieldcore)
