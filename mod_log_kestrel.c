/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_optional.h"
#include "apr_file_io.h"

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#define APR_WANT_STDIO
#define APR_WANT_IOVEC
#define APR_WANT_BYTEFUNC
#define APR_WANT_IOVEC
#define APR_IOVEC_DEFINED
#include "apr_want.h"

#include "ap_config.h"
#include "mod_log_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "util_time.h"

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif


#include "log_kestrel.h"

module AP_MODULE_DECLARE_DATA log_kestrel_module;

static apr_hash_t *kestrel_hash;
static ap_log_writer_init *normal_log_writer_init = NULL;
static ap_log_writer *normal_log_writer = NULL;

/* kestrel log config */
typedef struct {
  const char *fallbackURI;
  int timeoutInterval;
  int retryInterval;
  int logLocally;
} kestrel_log_config;


/* setup a new log target, called from mod_log_config */
static void *kestrel_log_writer_init(apr_pool_t *p, server_rec *s, const char* name)
{
    kestrel_log_t *k_log;
    char *uri;
    char *c = NULL;
    //    apr_status_t as;
    kestrel_log_config *conf = ap_get_module_config(s->module_config,
                                                   &log_kestrel_module);

    int kestrelWriter = 1;
    // TODO Zookeeper, Multiple host
    if(name != NULL && strstr(name, "kestrel") == NULL)
      kestrelWriter = 0;

    if(!kestrelWriter && conf->logLocally == 0)
      return NULL;

    if (! (k_log = apr_hash_get(kestrel_hash, name, APR_HASH_KEY_STRING))) {
        k_log = apr_palloc(p, sizeof(kestrel_log_t));
        k_log->uri = apr_pstrdup(p, name); /* keep our full name */
        uri = apr_pstrdup(p,name);     /* keep a copy for config */

        k_log->host = "defaulthost";
        k_log->port = 1463;
        k_log->category = "default";
        k_log->connectTimeout = conf->timeoutInterval;
        k_log->retryTimeout = conf->retryInterval;

        if(kestrelWriter != 0) {
          c = ap_strrchr(uri, ':');
          if(c != NULL) {
            if(c != uri+6) {
              k_log->port = apr_atoi64(c+1);
              *c = '\0';
            }
          } else {
            k_log->port = 1463;
          }

          c = ap_strrchr(uri, '@');
          if(c != NULL) {
            *c++ = '\0';
            k_log->host = c;
          }

          c = ap_strrchr(uri, ':');
          if(c != NULL) {
            *c++ = '\0';
            k_log->category = c;
          }
          k_log->localonly = 0;
        } else {
          k_log->localonly = 1;
          k_log->normal_handle = normal_log_writer_init(p, s, name);
        }
        apr_hash_set(kestrel_hash, name, APR_HASH_KEY_STRING, k_log);
    }

    return k_log;
}
/* log a request */
static apr_status_t kestrel_log_writer(request_rec *r,
                                      void *handle,
                                      const char **strs,
                                      int *strl,
                                      int nelts,
                                      apr_size_t len)
{
    kestrel_log_t *kestrel_log = (kestrel_log_t*)handle;
    //    kestrel_log_config *conf;

    if(kestrel_log->localonly != 0 && kestrel_log->normal_handle) {
      fprintf(stderr, "calling normal log writer\n");
      apr_status_t result = normal_log_writer(r, kestrel_log->normal_handle, strs, strl, nelts, len);
      fprintf(stderr, "called normal log writer\n");
      return result;
    }

    {
		char *str;
		char *s;
		int i;
		apr_status_t rv;
	    struct iovec logs[APR_MAX_IOVEC_SIZE];
	    
		for (i = 0, s = str; i < nelts; ++i) {
			logs[i].iov_base = (void *) strs[i];
			logs[i].iov_len = strl[i];
		}
		rv = kestrel_write(r->pool, kestrel_log, logs, i);
    }

    return OK;
}

static void *make_log_kestrel_config(apr_pool_t *p, server_rec *s)
{
    kestrel_log_config *conf =
      (kestrel_log_config *)apr_palloc(p, sizeof(kestrel_log_config));

    conf->fallbackURI = NULL;     /* secondary kestrel host */
    conf->logLocally = 1;         /* allow normal apache logging */
    conf->timeoutInterval = 2000; /* 2 seconds */
    conf->retryInterval = 5000;   /* 5 seconds */

    return conf;
}

static const char *logkestrel_timeout(cmd_parms *cmd, void *dcfg, const char *arg)
{
    kestrel_log_config *conf = ap_get_module_config(cmd->server->module_config,
                                                   &log_kestrel_module);

    if(arg)
      conf->timeoutInterval = apr_atoi64(arg);

    return OK;
}

static const char *logkestrel_retry(cmd_parms *cmd, void *dcfg, const char *arg)
{
    kestrel_log_config *conf = ap_get_module_config(cmd->server->module_config,
                                                   &log_kestrel_module);

    conf->retryInterval = apr_atoi64(arg);

    return OK;
}

static const command_rec log_kestrel_cmds[] =
  {
    AP_INIT_TAKE1("KestrelTimeoutInterval", logkestrel_timeout, NULL, RSRC_CONF,
                  "Kestrel connection timeout in milliseconds"),
    AP_INIT_TAKE1("KestrelRetryInterval", logkestrel_retry, NULL, RSRC_CONF,
                  "Time between retries connecting to primary kestrel store, "
                  "in milliseconds"),
    {NULL}
  };


static int log_kestrel_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
  static APR_OPTIONAL_FN_TYPE(ap_log_set_writer_init) *log_set_writer_init_fn = NULL;
  static APR_OPTIONAL_FN_TYPE(ap_log_set_writer) *log_set_writer_fn = NULL;

  log_set_writer_init_fn = APR_RETRIEVE_OPTIONAL_FN(ap_log_set_writer_init);
  log_set_writer_fn = APR_RETRIEVE_OPTIONAL_FN(ap_log_set_writer);

  if(log_set_writer_init_fn && log_set_writer_fn) {
    if (!normal_log_writer_init) {
      // FIXME: [emaland] add some error here if we can't load mod_log_config
      // Or maybe just warn and turn off local logging by default.  ???
      module *mod_log_config = ap_find_linked_module("mod_log_config.c");
      (void)mod_log_config; /* avoid annoying compiler warning */
      normal_log_writer_init = log_set_writer_init_fn(kestrel_log_writer_init);
      normal_log_writer = log_set_writer_fn(kestrel_log_writer);
    }
  }

  return OK;
}

static apr_status_t log_kestrel_child_exit(void *data)
{
    apr_pool_t *p = data;
    apr_hash_index_t *i;
    kestrel_log_t *l;

    for (i = apr_hash_first(p, kestrel_hash); i; i = apr_hash_next(i)) {
        apr_hash_this(i, NULL, NULL, (void*) &l);
    }
    return OK;
}

static void log_kestrel_child_init(apr_pool_t *p, server_rec *s)
{
}

static void register_hooks(apr_pool_t *p)
{
    /* register our log writer before mod_log_config starts */
    static const char *pre[] = { "mod_log_config.c", NULL };
    kestrel_hash = apr_hash_make(p);
    ap_hook_pre_config(log_kestrel_pre_config, pre, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_child_init(log_kestrel_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}


/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA log_kestrel_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  		/* create per-dir    config structures */
    NULL,                  		/* merge  per-dir    config structures */
    make_log_kestrel_config,    /* create per-server config structures */
    NULL,                  		/* merge  per-server config structures */
    log_kestrel_cmds,           /* table of config file commands       */
    register_hooks         		/* register hooks                      */
};

