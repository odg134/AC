#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <vector>
#include <functional>
#include <cstdio>
#include <cstring>
#include <algorithm>

#pragma comment( lib, "winhttp.lib" )
#pragma comment( lib, "user32.lib" )
#pragma comment( lib, "gdi32.lib" )
