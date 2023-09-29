#pragma once

#include <Windows.h>
#include <iostream>
#include <intrin.h>
#include <vector>
#include <inttypes.h>
#include <thread>
#include <Psapi.h>
#include <TlHelp32.h>
#include <unordered_set>

#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#include "tinyformat.h"
#include "definitions.h"
#include "unwind.h"
#include "util.h"
#include "spoof.h"