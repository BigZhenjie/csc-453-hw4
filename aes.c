#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

static int initialize_cipher(EVP_CIPHER_CTX *ctx, int mode, char *password, unsigned char *key, unsigned char *iv) {
    int rounds = 5;
    int key_length = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                                    (unsigned char*)password, strlen(password), rounds, key, iv);
    if (key_length != 32) {
        fprintf(stderr, "Error: Invalid key size\n");
        return 0;
    }
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, mode);
    return 1;
}

int encrypt_file(FILE* input, FILE* output, char* password) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32], iv[16];
    if (!initialize_cipher(ctx, 1, password, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    unsigned char input_buffer[BUFFER_SIZE];
    unsigned char output_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int input_length, output_length;
    
    while ((input_length = fread(input_buffer, 1, BUFFER_SIZE, input)) > 0) {
        if (!EVP_CipherUpdate(ctx, output_buffer, &output_length, input_buffer, input_length)) {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(output_buffer, 1, output_length, output);
    }
    
    if (!EVP_CipherFinal_ex(ctx, output_buffer, &output_length)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(output_buffer, 1, output_length, output);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int decrypt_file(FILE* input, FILE* output, char* password) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32], iv[16];
    if (!initialize_cipher(ctx, 0, password, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    unsigned char input_buffer[BUFFER_SIZE];
    unsigned char output_buffer[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int input_length, output_length;
    
    while ((input_length = fread(input_buffer, 1, BUFFER_SIZE, input)) > 0) {
        if (!EVP_CipherUpdate(ctx, output_buffer, &output_length, input_buffer, input_length)) {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(output_buffer, 1, output_length, output);
    }
    
    if (!EVP_CipherFinal_ex(ctx, output_buffer, &output_length)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(output_buffer, 1, output_length, output);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int copy_file(FILE* input, FILE* output) {
    unsigned char buffer[BUFFER_SIZE];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input)) > 0) {
        fwrite(buffer, 1, bytes_read, output);
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <mode> <password> <input_file> <output_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int mode = -1;
    char *password = NULL;
    int input_arg, output_arg;

    if (strcmp(argv[1], "-e") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s -e <password> <input_file> <output_file>\n", argv[0]);
            return EXIT_FAILURE;
        }
        mode = 1;
        password = argv[2];
        input_arg = 3;
        output_arg = 4;
    } else if (strcmp(argv[1], "-d") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s -d <password> <input_file> <output_file>\n", argv[0]);
            return EXIT_FAILURE;
        }
        mode = 0;
        password = argv[2];
        input_arg = 3;
        output_arg = 4;
    } else if (strcmp(argv[1], "-c") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s -c <input_file> <output_file>\n", argv[0]);
            return EXIT_FAILURE;
        }
        mode = -1;
        input_arg = 2;
        output_arg = 3;
    } else {
        fprintf(stderr, "Error: Unknown mode\n");
        return EXIT_FAILURE;
    }

    FILE *input = fopen(argv[input_arg], "rb");
    if (!input) {
        perror("Error opening input file");
        return EXIT_FAILURE;
    }
    FILE *output = fopen(argv[output_arg], "wb");
    if (!output) {
        perror("Error opening output file");
        fclose(input);
        return EXIT_FAILURE;
    }

    int result = (mode == 1) ? encrypt_file(input, output, password) : 
                 (mode == 0) ? decrypt_file(input, output, password) : 
                 copy_file(input, output);
     
    if (!result) {
        fprintf(stderr, "Error processing file\n");
    }

    fclose(output);
    fclose(input);
    return EXIT_SUCCESS;
}
