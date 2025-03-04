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

//please dont have a long ass path
int PATH_MAX = 500;
struct root_dir{
    char *rootdir;
};
#define ROOT_DIR ((struct root_dir *) fuse_get_context()->private_data)



static void fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, ROOT_DIR->rootdir);
    strncat(fpath, path, PATH_MAX); // ridiculously long paths will
                    // break here
}

//need this
static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char fpath[PATH_MAX];
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
    char fpath[PATH_MAX];
    
    (void) offset;
    (void) fi;
    
    fullpath(fpath, path);
    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
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
    char fpath[PATH_MAX];
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
    char fpath[PATH_MAX];
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
    char fpath_from[PATH_MAX];
    char fpath_to[PATH_MAX];
    
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
    char fpath[PATH_MAX];
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
    char fpath[PATH_MAX];
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
    char fpath[PATH_MAX];
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
    char fpath[PATH_MAX];
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

    (void) fi;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

//----------------------------------KEEP----------------------------------
static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;

    (void) fi;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    fd = open(fpath, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}
//----------------------------------KEEP----------------------------------
static int xmp_unlink(const char *path)
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = unlink(fpath);
    if (res == -1)
        return -errno;

    return 0;
};

static int xmp_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int fd;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    fd = open(fpath, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd == -1)
        return -errno;

    close(fd);
    return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    /* Don't use utimensat since it might not be available everywhere */
    struct timeval tv[2];
    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = lutimes(fpath, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    // Nothing to do since we don't keep files open
    (void) path;
    (void) fi;
    return 0;
}

static int xmp_append(const char *path, const char *buf, size_t size,
                     struct fuse_file_info *fi)
{
    int fd;
    int res;
    char fpath[PATH_MAX];
    
    // Always open the file for append
    fullpath(fpath, path);
    fd = open(fpath, O_WRONLY | O_APPEND);
    if (fd == -1)
        return -errno;
    
    // Write at the end (O_APPEND ensures this)
    res = write(fd, buf, size);
    if (res == -1)
        res = -errno;
    
    // Always close since we opened it here
    close(fd);
    return res;
}

static struct fuse_operations xmp_oper = {
    .getattr    = xmp_getattr,    // Most important!
    .readdir    = xmp_readdir,
    .mkdir      = xmp_mkdir,
    .rmdir      = xmp_rmdir,
    .unlink     = xmp_unlink,
    .rename     = xmp_rename,
    .chmod      = xmp_chmod,
    .chown      = xmp_chown,
    .truncate   = xmp_truncate,
    .open       = xmp_open,
    .create     = xmp_create,     // Important for file creation
    .read       = xmp_read,
    .write      = xmp_write,
    .release    = xmp_release,
    .utimens    = xmp_utimens,    // Important for timestamp updates
};




int main(int argc, char *argv[])
{
    //something to store rootdir
    struct root_dir *root_directory;

    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')){
        perror("invalid args");
    }

    root_directory = malloc(sizeof(struct root_dir));

    root_directory->rootdir = realpath(argv[argc-2], NULL);
    printf("ROOT: %s", root_directory->rootdir);
    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;

    umask(0);
    //gotta pass in the root dir struct for the fuse to keep track of root directory
    return fuse_main(argc, argv, &xmp_oper, root_directory);
}