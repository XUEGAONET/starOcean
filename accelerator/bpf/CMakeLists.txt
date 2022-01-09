cmake_minimum_required(VERSION 3.20)
set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_C_COMPILER "clang")
add_compile_options(-O2 -target bpf)
project(starOcean_bpf C)

add_library(underlay OBJECT underlay.c)
