#include "string_obfuscation.h"
#include "driver_defs.h" //  For ENCRYPTION_KEY (insecure; needs improvement).



#define ENCRYPTION_KEY 0x5A // this is an example key - DO NOT USE THIS IN PRODUCTION

VOID encrypt_string(PCHAR str, SIZE_T size) {
    if (!str || size == 0) {
        return;
    }

    for (SIZE_T i = 0; i < size; ++i) {
        str[i] ^= ENCRYPTION_KEY;  // Weak XOR encryption - replace in a real driver.
    }
}

VOID decrypt_string(PCHAR str, SIZE_T size) {
    encrypt_string(str, size); // Same as encryption for simple XOR.
}