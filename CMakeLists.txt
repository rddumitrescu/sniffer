cmake_minimum_required(VERSION 3.0)

set(CMAKE_BUILD_TYPE Debug)

project(sniffer)

add_executable(
	sniffer
	sniffer.c
)