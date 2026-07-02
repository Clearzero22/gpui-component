cmake_minimum_required(VERSION 3.20)
project(hideproc-demo
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# HideProc.exe - Injects stealth.dll into Task Manager to hide a process
add_executable(HideProc HideProc.cpp)
target_link_libraries(HideProc PRIVATE psapi)

# stealth.dll - Inline Hook DLL (static CRT for self-containment)
# /MT ensures no dependency on msvcp140*.dll in the target process
add_library(stealth SHARED stealth.cpp)
set_target_properties(stealth PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded"
)

set_target_properties(HideProc stealth PROPERTIES
    WIN32_EXECUTABLE FALSE
)
