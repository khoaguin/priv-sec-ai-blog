cmake_minimum_required(VERSION 3.13)

set(PROJECT_NAME
    pastaLib
)

set(LIBRARY_NAME
    pasta
)

set(LIBRARY_HEADERS_DIR
    include/${LIBRARY_NAME}
)

set(LIBRARY_HEADERS
    ${LIBRARY_HEADERS_DIR}/pasta.h
    # ${LIBRARY_HEADERS_DIR}/pasta_3_plain.h
)

set(LIBRARY_SOURCE_DIR
    src
)

set(LIBRARY_SOURCE
    ${LIBRARY_SOURCE_DIR}/pasta.cpp
    # ${LIBRARY_SOURCE_DIR}/pasta_3_plain.cpp
)

project(${PROJECT_NAME})

add_library(${LIBRARY_NAME} STATIC
    ${LIBRARY_HEADERS}
    ${LIBRARY_SOURCE}
)

target_include_directories(${LIBRARY_NAME} PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/${LIBRARY_NAME}>
    $<INSTALL_INTERFACE:include/${LIBRARY_NAME}>
)

target_include_directories(${LIBRARY_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)