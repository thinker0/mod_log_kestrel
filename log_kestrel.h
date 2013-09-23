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

#include "apr.h"
#include "apr_pools.h"
#include "apr_tables.h"

#ifndef LOG_KESTREL_H_
#define LOG_KESTREL_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
  
  typedef struct {
    struct addrinfo *addr;
    char *host;
    int port;
  } host_port_info_t;
  
  /* single log target */
  typedef struct {
    char *uri;
    char *host;
    char *port;
    apr_array_header_t *host_infos_arr;
    char *category;
    int connectTimeout;
    
    const char *fallbackURI;
    int fallingback;
    int retry;
    int retryTimeout;
    
    int localonly; /* this store is not a kestrel store */
    void *normal_handle; /* apache mod_log_config handle */
  } kestrel_log_t;
  
#ifdef __cplusplus
}
#endif

#endif // LOG_KESTREL_H_
