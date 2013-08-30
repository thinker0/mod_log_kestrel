#include "apr.h"
#include "apr_pools.h"
#include "log_kestrel.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

apr_status_t kestrel_write(apr_pool_t *pool, kestrel_log_t *kestrel_log, struct iovec *uio, int uio_len);


#ifdef __cplusplus
}
#endif
