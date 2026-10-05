cmake_minimum_required(VERSION 3.10)

# ltlfuzz-solver：LTL-Fuzzer（ICSE'22）框架 + 求解引擎（静态分析+Z3+智能体）
# 框架/monitor/前缀池/调度 = 论文原样（Apache 2.0）；搜索引擎替换 AFLGo。
set(This ltlfuzz-solver)
project(${This} C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(-Wall -g -MMD -MP)
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
set(CMAKE_INSTALL_RPATH "$ENV{HOME}/spot-rebuild/lib")

include_directories(${CMAKE_SOURCE_DIR}/include)
# spot 为本地安装（~/spot，与插桩/求解共享同一 spot）
include_directories($ENV{HOME}/spot-rebuild/include)
link_directories($ENV{HOME}/spot-rebuild/lib)

add_subdirectory(src)
