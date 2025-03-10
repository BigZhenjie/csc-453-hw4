#define FUSE_USE_VERSION 26

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "aes.h"

// please dont have a long ass path
int PATH_MAX_LENGTH = 500;
struct context
{
    char *rootdir;
    char passphrase[256];
    unsigned char key[32];
    unsigned char iv[16];
};
#define ROOT_DIR ((struct context *)fuse_get_context()->private_data)

static void fullpath(char fpath[PATH_MAX_LENGTH], const char *path)
{
    strcpy(fpath, ROOT_DIR->rootdir);
    strncat(fpath, path, PATH_MAX_LENGTH); // ridiculously long paths will
                                    // break here
}

// Store IV in a separate metadata file
static void store_file_iv(const char *path, unsigned char *iv)
{
    char meta_path[PATH_MAX_LENGTH + 8];
    snprintf(meta_path, sizeof(meta_path), "%s.iv", path);

    FILE *meta_file = fopen(meta_path, "wb");
    if (meta_file)
    {
        fwrite(iv, 1, 16, meta_file);
        fclose(meta_file);
    }
}

// Get IV from metadata file
static int get_file_iv(const char *path, unsigned char *iv)
{
    char meta_path[PATH_MAX_LENGTH + 8];
    snprintf(meta_path, sizeof(meta_path), "%s.iv", path);

    FILE *meta_file = fopen(meta_path, "rb");
    if (!meta_file)
    {
        // If no IV file exists, file is not encrypted
        return 0;
    }

    size_t read_size = fread(iv, 1, 16, meta_file);
    fclose(meta_file);

    return (read_size == 16);
}

// Determine if a file should be encrypted
// In this implementation, we'll encrypt everything except .iv files
static int should_encrypt_file(const char *path)
{
    size_t len = strlen(path);
    if (len > 3 && strcmp(path + len - 3, ".iv") == 0)
        return 0; // Don't encrypt IV files
    return 1;     // Encrypt everything else
}

// Check if a file is already encrypted
static int is_encrypted_file(const char *path)
{
    unsigned char test_iv[16];
    return get_file_iv(path, test_iv);
}

// need this
static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    res = lstat(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

//----------------------------------KEEP----------------------------------
static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;
    char fpath[PATH_MAX_LENGTH];

    (void)offset;
    (void)fi;

    fullpath(fpath, path);
    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL)
    {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

//----------------------------------KEEP----------------------------------
static int xmp_mkdir(const char *path, mode_t mode)
{
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    res = mkdir(fpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

//----------------------------------KEEP----------------------------------
static int xmp_rmdir(const char *path)
{
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    res = rmdir(fpath);
    if (res == -1)
        return -errno;

    return 0;
}

//----------------------------------KEEP----------------------------------
static int xmp_rename(const char *from, const char *to)
{
    int res;
    char fpath_from[PATH_MAX_LENGTH];
    char fpath_to[PATH_MAX_LENGTH];

    fullpath(fpath_from, from);
    fullpath(fpath_to, to);

    res = rename(fpath_from, fpath_to);
    if (res == -1)
        return -errno;

    return 0;
}

//----------------------------------KEEP----------------------------------
static int xmp_chmod(const char *path, mode_t mode)
{
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    res = chmod(fpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

//----------------------------------KEEP----------------------------------
static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    res = lchown(fpath, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

//----------------------------------KEEP----------------------------------
static int xmp_truncate(const char *path, off_t size)
{
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    res = truncate(fpath, size);
    if (res == -1)
        return -errno;

    return 0;
}

//----------------------------------KEEP----------------------------------
static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    res = open(fpath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

//----------------------------------KEEP----------------------------------
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    int fd;
    int res;
    unsigned char *temp_buf;

    (void)fi;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    // Allocate buffer for reading (possibly encrypted) data
    temp_buf = malloc(size);
    if (!temp_buf)
    {
        close(fd);
        return -ENOMEM;
    }

    res = pread(fd, temp_buf, size, offset);
    if (res == -1)
    {
        res = -errno;
        free(temp_buf);
        close(fd);
        return res;
    }

    // Check if the file is encrypted
    unsigned char iv[16];
    if (is_encrypted_file(fpath))
    {
        // Get the IV for this file
        if (!get_file_iv(fpath, iv))
        {
            free(temp_buf);
            close(fd);
            return -EIO; // I/O error
        }

        // Create a temporary file for decryption
        FILE *input_tmp = tmpfile();
        FILE *output_tmp = tmpfile();
        if (!input_tmp || !output_tmp)
        {
            free(temp_buf);
            close(fd);
            if (input_tmp)
                fclose(input_tmp);
            if (output_tmp)
                fclose(output_tmp);
            return -EIO;
        }

        // Write encrypted data to temp file
        fwrite(temp_buf, 1, res, input_tmp);
        rewind(input_tmp);

        // Decrypt using your existing function
        if (!decrypt_file(input_tmp, output_tmp, ROOT_DIR->passphrase))
        {
            free(temp_buf);
            close(fd);
            fclose(input_tmp);
            fclose(output_tmp);
            return -EIO;
        }

        // Read decrypted data
        rewind(output_tmp);
        res = fread(buf, 1, size, output_tmp);

        fclose(input_tmp);
        fclose(output_tmp);
    }
    else
    {
        // Not encrypted, just copy the data
        memcpy(buf, temp_buf, res);
    }

    free(temp_buf);
    close(fd);
    return res;
}

//----------------------------------KEEP----------------------------------
static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    // Check if we should encrypt this file
    if (should_encrypt_file(fpath))
    {
        // Create a unique IV for this file if it doesn't exist
        unsigned char iv[16];
        if (!is_encrypted_file(fpath))
        {
            RAND_bytes(iv, 16);
            store_file_iv(fpath, iv);
        }
        else
        {
            get_file_iv(fpath, iv);
        }

        // Create temporary files for encryption
        FILE *input_tmp = tmpfile();
        FILE *output_tmp = tmpfile();
        if (!input_tmp || !output_tmp)
        {
            if (input_tmp)
                fclose(input_tmp);
            if (output_tmp)
                fclose(output_tmp);
            return -EIO;
        }

        // Write plaintext data to temp file
        fwrite(buf, 1, size, input_tmp);
        rewind(input_tmp);

        // Encrypt the data
        if (!encrypt_file(input_tmp, output_tmp, ROOT_DIR->passphrase))
        {
            fclose(input_tmp);
            fclose(output_tmp);
            return -EIO;
        }

        // Get the encrypted data
        unsigned char *encrypted_buf = malloc(size + EVP_MAX_BLOCK_LENGTH);
        if (!encrypted_buf)
        {
            fclose(input_tmp);
            fclose(output_tmp);
            return -ENOMEM;
        }

        rewind(output_tmp);
        int encrypted_size = fread(encrypted_buf, 1, size + EVP_MAX_BLOCK_LENGTH, output_tmp);

        // Write the encrypted data
        fd = open(fpath, O_WRONLY);
        if (fd == -1)
        {
            free(encrypted_buf);
            fclose(input_tmp);
            fclose(output_tmp);
            return -errno;
        }

        res = pwrite(fd, encrypted_buf, encrypted_size, offset);

        free(encrypted_buf);
        fclose(input_tmp);
        fclose(output_tmp);
    }
    else
    {
        // Not encrypting, just write directly
        fd = open(fpath, O_WRONLY);
        if (fd == -1)
            return -errno;
        res = pwrite(fd, buf, size, offset);
    }

    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}
//----------------------------------KEEP----------------------------------
static int xmp_unlink(const char *path)
{
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    res = unlink(fpath);
    if (res == -1)
        return -errno;

    return 0;
};

static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int fd;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    fd = open(fpath, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd == -1)
        return -errno;

    // If this file should be encrypted, generate an IV
    if (should_encrypt_file(fpath))
    {
        unsigned char iv[16];
        RAND_bytes(iv, 16);
        store_file_iv(fpath, iv);
    }

    close(fd);
    return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    /* Don't use utimensat since it might not be available everywhere */
    struct timeval tv[2];
    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(fpath, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    // Nothing to do since we don't keep files open
    (void)path;
    (void)fi;
    return 0;
}

static int xmp_append(const char *path, const char *buf, size_t size,
                      struct fuse_file_info *fi)
{
    int fd;
    int res;
    char fpath[PATH_MAX_LENGTH];
    fullpath(fpath, path);

    // Check if we should encrypt this file
    if (should_encrypt_file(fpath))
    {
        // For encrypted files, we need to:
        // 1. Read the entire file
        // 2. Decrypt it
        // 3. Append new data
        // 4. Re-encrypt the whole thing

        // Get file size
        struct stat st;
        if (lstat(fpath, &st) == -1)
            return -errno;

        // Read the existing encrypted content
        unsigned char *encrypted_content = malloc(st.st_size);
        if (!encrypted_content)
            return -ENOMEM;

        fd = open(fpath, O_RDONLY);
        if (fd == -1)
        {
            free(encrypted_content);
            return -errno;
        }

        ssize_t bytes_read = read(fd, encrypted_content, st.st_size);
        close(fd);

        if (bytes_read != st.st_size)
        {
            free(encrypted_content);
            return -EIO;
        }

        // Decrypt the content
        FILE *temp_in = tmpfile();
        FILE *temp_out = tmpfile();
        if (!temp_in || !temp_out)
        {
            free(encrypted_content);
            if (temp_in)
                fclose(temp_in);
            if (temp_out)
                fclose(temp_out);
            return -EIO;
        }

        fwrite(encrypted_content, 1, bytes_read, temp_in);
        rewind(temp_in);
        free(encrypted_content);

        if (!decrypt_file(temp_in, temp_out, ROOT_DIR->passphrase))
        {
            fclose(temp_in);
            fclose(temp_out);
            return -EIO;
        }

        // Read decrypted content
        rewind(temp_out);
        char *decrypted_content = malloc(st.st_size + size); // Space for original + new
        if (!decrypted_content)
        {
            fclose(temp_in);
            fclose(temp_out);
            return -ENOMEM;
        }

        size_t dec_size = fread(decrypted_content, 1, st.st_size, temp_out);
        fclose(temp_in);
        fclose(temp_out);

        // Append new data
        memcpy(decrypted_content + dec_size, buf, size);

        // Re-encrypt everything
        temp_in = tmpfile();
        temp_out = tmpfile();
        if (!temp_in || !temp_out)
        {
            free(decrypted_content);
            if (temp_in)
                fclose(temp_in);
            if (temp_out)
                fclose(temp_out);
            return -EIO;
        }

        fwrite(decrypted_content, 1, dec_size + size, temp_in);
        rewind(temp_in);
        free(decrypted_content);

        if (!encrypt_file(temp_in, temp_out, ROOT_DIR->passphrase))
        {
            fclose(temp_in);
            fclose(temp_out);
            return -EIO;
        }

        // Write new encrypted content
        rewind(temp_out);
        fseek(temp_out, 0, SEEK_END);
        long new_size = ftell(temp_out);
        rewind(temp_out);

        unsigned char *new_encrypted = malloc(new_size);
        if (!new_encrypted)
        {
            fclose(temp_in);
            fclose(temp_out);
            return -ENOMEM;
        }

        size_t enc_bytes_read = fread(new_encrypted, 1, new_size, temp_out);
        fclose(temp_in);
        fclose(temp_out);

        // Write to file
        fd = open(fpath, O_WRONLY | O_TRUNC);
        if (fd == -1)
        {
            free(new_encrypted);
            return -errno;
        }

        res = write(fd, new_encrypted, enc_bytes_read);
        free(new_encrypted);
    }
    else
    {
        // Not encrypting, use normal append
        fd = open(fpath, O_WRONLY | O_APPEND);
        if (fd == -1)
            return -errno;

        res = write(fd, buf, size);
    }

    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static struct fuse_operations xmp_oper = {
    .getattr = xmp_getattr, // Most important!
    .readdir = xmp_readdir,
    .mkdir = xmp_mkdir,
    .rmdir = xmp_rmdir,
    .unlink = xmp_unlink,
    .rename = xmp_rename,
    .chmod = xmp_chmod,
    .chown = xmp_chown,
    .truncate = xmp_truncate,
    .open = xmp_open,
    .create = xmp_create, // Important for file creation
    .read = xmp_read,
    .write = xmp_write,
    .release = xmp_release,
    .utimens = xmp_utimens, // Important for timestamp updates
};

int main(int argc, char *argv[])
{
    struct context *context;
    char passphrase[256];

    if (argc < 3) {
        fprintf(stderr, "Usage: %s [FUSE options] <mountpoint> <directory to mirror>\n", argv[0]);
        return 1;
    }

    context = malloc(sizeof(struct context));
    if (!context) {
        perror("Failed to allocate memory");
        return 1;
    }

    context->rootdir = realpath(argv[argc - 1], NULL);  // Mirror directory
    if (!context->rootdir) {
        perror("Error resolving root directory");
        free(context);
        return 1;
    }

    // Ask for passphrase
    printf("Enter passphrase: ");
    if (fgets(passphrase, sizeof(passphrase), stdin) == NULL) {
        perror("Failed to read passphrase");
        free(context);
        return 1;
    }

    // Remove trailing newline
    size_t len = strlen(passphrase);
    if (len > 0 && passphrase[len - 1] == '\n')
        passphrase[len - 1] = '\0';

    strncpy(context->passphrase, passphrase, sizeof(context->passphrase) - 1);
    
    // Derive the encryption key
    int rounds = 5;
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                 (unsigned char*)context->passphrase, strlen(context->passphrase),
                 rounds, context->key, context->iv);

    printf("Mounting %s to %s\n", context->rootdir, argv[argc - 2]);
    
    // Shift arguments for FUSE
    argv[argc - 1] = NULL;
    argc--;

    umask(0);
    return fuse_main(argc, argv, &xmp_oper, context);
}
