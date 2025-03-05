#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define BUFFER_SIZE 1024

extern int encrypt_file(FILE* input, FILE* output, char* password);
extern int decrypt_file(FILE* input, FILE* output, char* password);
extern int copy_file(FILE* input, FILE* output);

#endif