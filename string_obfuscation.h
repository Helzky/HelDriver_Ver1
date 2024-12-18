#pragma once

#include <ntifs.h>

// function prototypes
VOID encrypt_string(PCHAR str, SIZE_T size);
VOID decrypt_string(PCHAR str, SIZE_T size);