
#ifndef LOG_KESTREL_H_
#define LOG_KESTREL_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* single log target */
typedef struct {
    char *uri;
    char *host;
    int port;
    char *category;
    int connectTimeout;

    const char *fallbackURI;
    int fallingback;
    int retryTimeout;

    int localonly; /* this store is not a kestrel store */
    void *normal_handle; /* apache mod_log_config handle */
} kestrel_log_t;

#ifdef __cplusplus
}
#endif

#endif // LOG_KESTREL_H_
