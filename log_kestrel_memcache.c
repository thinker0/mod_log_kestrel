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

#include <sys/uio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/select.h>

#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#define APR_WANT_STDIO
#define APR_WANT_IOVEC
#define APR_WANT_BYTEFUNC
#define APR_WANT_IOVEC
#define APR_IOVEC_DEFINED
#include "apr_want.h"

#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_optional.h"
#include "apr_file_io.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_date.h"
#include "apr_tables.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_log.h"

#include "log_kestrel.h"

static struct addrinfo *get_random_addr(struct addrinfo *addr) {
	int dns_size, dns_rand;
	struct addrinfo *pt = NULL;

	if (!addr) {
		return NULL;
    }
	pt = addr;
	dns_size = 0;
	while (pt != NULL) {
		dns_size++;
		pt = pt->ai_next;
	}
	if (dns_size == 0)
		return NULL;

	dns_rand = rand() % dns_size;

	pt = addr;
	dns_size = 0;
	while (dns_size != dns_rand) {
		dns_size++;
		pt = pt->ai_next;
	}
	return pt;
}

static int set_sock_linger(int sock) {
	struct linger ln;
	ln.l_onoff = 1;
	ln.l_linger = 0;
	return setsockopt(sock, SOL_SOCKET, SO_LINGER, (const void *) &ln, sizeof(ln));
}

static int get_sock_flags(int sock) {
	return fcntl(sock, F_GETFL, 0);
}

static int set_sock_flags(int sock, int flags) {
	return fcntl(sock, F_SETFL, flags);
}

static int set_sock_nonblock(int sock) {
	int flags = get_sock_flags(sock);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	return flags; /* return original flags */
}

static int connect_nonb_with_timeout(int sockfd, const struct sockaddr *saptr, socklen_t salen, apr_time_t usec) {
	int ori_flags, n, error;
	socklen_t len;
	fd_set rset, wset;
	struct timeval tval;

	ori_flags = set_sock_nonblock(sockfd);

	if ((n = connect(sockfd, saptr, salen)) < 0) {
		if (errno != EINPROGRESS) /* we MUST compile with -D_REENTERANT for thread-safe using errno */
			return (-1);
	}

	if (n == 0) { /* connect completed immediately */
		set_sock_flags(sockfd, ori_flags);
		return (0);
	}

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	wset = rset;
	tval.tv_sec = 0;
	tval.tv_usec = usec;

	if ((n = select(sockfd + 1, &rset, &wset, NULL, (usec ? &tval : NULL))) == 0) {
		set_sock_flags(sockfd, ori_flags);
		return (ETIMEDOUT);
	}

	error = 0;
	if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
		len = sizeof(error);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) { /* pending error */
			set_sock_flags(sockfd, ori_flags);
			return (-1);
		}
	} else { /* select error */
		set_sock_flags(sockfd, ori_flags);
		return (-1);
	}

	set_sock_flags(sockfd, ori_flags);

	return error; /* if connect completed, error is 0, else error returned */
}

static int send_with_timeout(int sockfd, apr_time_t usec, struct iovec *uio, int uio_len) {
	int n;
	struct timeval tval;
	fd_set wset;

	FD_ZERO(&wset);
	FD_SET(sockfd, &wset);
	tval.tv_sec = 0;
	tval.tv_usec = usec;

	if ((n = select(sockfd + 1, NULL, &wset, NULL, (usec ? &tval : NULL))) == 0) {
		return (ETIMEDOUT);
	}

	if (FD_ISSET(sockfd, &wset)) {
		int error = 0;
		socklen_t len = sizeof(error);
		if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) { /* pending error */
			return (-1);
		}
		if (writev(sockfd, uio, uio_len) != uio_len) { /* send error */
			return (-1);
		} else {
			return (0);
		}
	}

	/* select error */
	return (-1);
}

static int recv_with_timeout(int sockfd, apr_time_t usec, apr_pool_t *pool, char **recvstr) {
	int n, result;
	fd_set rset;
	struct timeval tval;

	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);
	tval.tv_sec = 0;
	tval.tv_usec = usec;

	if (!recvstr) {
		return (-1);
    }
	*recvstr = NULL;

	do {
		char buf[2048] = { 0, };
		int nbuf = sizeof(buf) - 1;

		if ((n = select(sockfd + 1, &rset, NULL, NULL, (usec ? &tval : NULL))) == 0) {
			return (ETIMEDOUT);
		}

		if (FD_ISSET(sockfd, &rset)) {
			int error = 0;
			socklen_t len = sizeof(error);
			if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) { /* pending error */
				return (-1);
			}
			if ((result = recv(sockfd, buf, nbuf, 0)) < 0) { /* recv error */
				return (-1);
			}
			if (result == 0) { /* EOF */
				return (0);
            }
			if (*recvstr == NULL) {
				*recvstr = apr_pstrdup(pool, buf);
			} else {
				*recvstr = apr_pstrcat(pool, *recvstr, buf, NULL);
            }
		}

	} while (1);

	/* select error */
	return (-1);
}

static apr_status_t addrinfo_cleanup(void *data) {
	if (data) {
		struct addrinfo *addr = (struct addrinfo *) data;
		if (addr) {
			freeaddrinfo(addr);
		}
	}
    return (APR_SUCCESS);
}

/**
 *
 */
struct addrinfo *socket_addrinfo_make(request_rec *r, char *hostname, char *port_str) {
	// apr_socket_t *sock = NULL; // TODO ipv6
	struct addrinfo hints;
	struct addrinfo *addr;
    int re = 0;
	if (!hostname || !port_str) {
		return NULL;
    }
	memset(&hints, 0x00, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;            /* Allow IPv4 or IPv6 */
    // hints.ai_family = AF_INET;           /* Allow IPv4 */
	hints.ai_socktype = SOCK_STREAM;

	/* DON'T use apr_getaddrinfo(), because some version multiple address can not be handled */
	/* DON'T use gethostbyname(), because it uses a static storage, so it's not thread-safe */
	/* Be careful in using getaddrinfo(), because it allocates memory internal, so it need to call freeaddrinfo(); */
	if ((re = getaddrinfo(hostname, port_str, &hints, &addr)) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "getaddrinfo %s", gai_strerror(re));
		return NULL;
	}
	apr_pool_cleanup_register(r->pool, (void *) addr, addrinfo_cleanup, apr_pool_cleanup_null);
	return addr;
}

apr_status_t kestrel_write(request_rec *r, kestrel_log_t *kestrel_log, struct iovec *uio, int uio_len) {
	struct addrinfo *addr = NULL;
	char *response = NULL;
	apr_status_t rv = 0;
	apr_time_t timeout;
	int socket_descriptor = -1;
	int retry_counter = 0;

	if (!uio || uio_len == 0) {
		return (-1);
	}
    /* kestrel_log->connectTimeout : mili-second */
    timeout = kestrel_log->connectTimeout * 1000; /* make form as microseconds */
    for (retry_counter = 0; retry_counter < kestrel_log->retry; retry_counter++) {
		addr = socket_addrinfo_make(r, kestrel_log->host, kestrel_log->port);
        if (addr == NULL) {            
			continue;
        }
		addr = get_random_addr(addr);
		if ((socket_descriptor = socket(AF_UNSPEC, SOCK_STREAM, 0)) == -1) {     // AF_UNSPEC(ipv4, ipv6), AF_INET(ipv4)
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "apr_socket_create fail (%s:%s%s) r:%d",
                          kestrel_log->host, kestrel_log->port, kestrel_log->category, retry_counter);
			continue;
		}
		set_sock_linger(socket_descriptor);

		/* connect socket with non-block with timeout */
		if ((rv = connect_nonb_with_timeout(socket_descriptor, (struct sockaddr *) (addr->ai_addr), addr->ai_addrlen, timeout)) != 0) {
			close(socket_descriptor);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "_connect_nonb_with_timeout fail (%s:%s%s) r:%d",
							kestrel_log->host, kestrel_log->port, kestrel_log->category, retry_counter);
			continue;
		}

		/* send */
		if ((rv = send_with_timeout(socket_descriptor, timeout, uio, uio_len)) != 0) {
			close(socket_descriptor);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "_send_with_timeout fail (%s:%s%s) r:%d",
							kestrel_log->host, kestrel_log->port, kestrel_log->category, retry_counter);
			continue;
		}

		/* recv */
		if ((rv = recv_with_timeout(socket_descriptor, timeout, r->pool, &response)) != 0) {
			close(socket_descriptor);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "_recv_with_timeout fail (%s:%s%s) : %s r:%d",
							kestrel_log->host, kestrel_log->port, kestrel_log->category, response ? response : "", retry_counter);
			continue;
		}
		close(socket_descriptor);
		if (!response || strlen(response) == 0) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "##### RESPONSE : (%s) r:%d",
                          response, retry_counter);
			return (APR_SUCCESS);
		}
	}

	return (APR_SUCCESS);
}
