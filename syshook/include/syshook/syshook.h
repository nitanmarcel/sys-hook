#ifndef SYSHOOK_SYSHOOK_H
#define SYSHOOK_SYSHOOK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYSHOOK_VERSION_MAJOR 1
#define SYSHOOK_VERSION_MINOR 0

typedef struct {
    long        nr;
    long        args[6];
    const void *pc;
} syshook_ctx;

typedef enum {
    SYSHOOK_CONTINUE = 0,
    SYSHOOK_BYPASS = 1,
} syshook_action;

typedef syshook_action (*syshook_fn)(syshook_ctx *ctx, long *result, void *user);

typedef enum {
    SYSHOOK_OK               =  0,
    SYSHOOK_ERR_UNSUPPORTED  = -1,
    SYSHOOK_ERR_STATE        = -2,
    SYSHOOK_ERR_LIMIT        = -3,
    SYSHOOK_ERR_INVALID      = -4,
    SYSHOOK_ERR_NO_NEW_PRIVS = -5,
    SYSHOOK_ERR_SIGNAL       = -6,
    SYSHOOK_ERR_SECCOMP      = -7,
} syshook_status;

typedef enum {
    SYSHOOK_ALL_THREADS  = 0,
    SYSHOOK_THIS_THREAD  = 1,
} syshook_scope;

syshook_status syshook_init(void);

syshook_status syshook_add(long nr, syshook_fn cb, void *user);

syshook_status syshook_install(void);

syshook_status syshook_install_scoped(syshook_scope scope);

syshook_status syshook_hook(long nr, syshook_fn cb, void *user);

const char *syshook_strstatus(syshook_status s);

#ifdef __cplusplus
}
#endif

#endif
