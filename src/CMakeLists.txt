set(This fuzzer)
set(Entry ltlfuzz-solver)

set(Sources
    LTLFuzzer.cc
    PathStore.cc
    TargetsStore.cc
    RandomStrategy.cc
    utils.cc
    AutomataHandler.cc
    solver/SolverEngine.cc
    solver/AgentLoop.cc
    solver/Z3Solver.cc
    solver/SourceAnalyzer.cc
    solver/AnalysisTools.cc
    solver/Executor.cc
)

add_library(${This} STATIC ${Sources})
target_include_directories(${This} PUBLIC ${CMAKE_SOURCE_DIR}/include
                                          $ENV{HOME}/spot-rebuild/include)
add_executable(${Entry} main.cc)
target_link_directories(${Entry} PUBLIC $ENV{HOME}/spot-rebuild/lib)
target_link_libraries(${Entry} PUBLIC
    ${This}
    pthread
    automata
    instrumentation
    spot
    bddx
    rt
    z3
)

add_subdirectory(automata)
add_subdirectory(instrumentation)
