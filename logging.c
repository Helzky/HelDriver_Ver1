#include "logging.h"

VOID log_message(PCSTR format, ...) {
    va_list args;
    va_start(args, format);
    vDbgPrintExWithPrefix("[MyDriver] ", DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, format, args); // Added prefix for easier filtering
    va_end(args);
}