#pragma once

#include <ntifs.h>
#include <stdarg.h> // for va_list

// function prototype
VOID log_message(PCSTR format, ...);