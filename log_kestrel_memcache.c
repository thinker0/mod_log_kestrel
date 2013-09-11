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

static int send_with_timeout(request_rec *r, int sockfd, apr_time_t usec,
									char *category,
									const char **strs,
									int *strl,
									int nelts,
									apr_size_t len) {
	int n = 0;
	int idx = 0;
	struct timeval tval;
	fd_set wset;

	FD_ZERO(&wset);
	FD_SET(sockfd, &wset);
	tval.tv_sec = 0;
	tval.tv_usec = usec;

	if ((n = select(sockfd + 1, NULL, &wset, NULL, (usec ? &tval : NULL))) == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "select %d", n);
		return (ETIMEDOUT);
	}

	if (FD_ISSET(sockfd, &wset)) {
		int error = 0;
		socklen_t socklen = sizeof(error);
		if ( (n = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &socklen)) < 0) { /* pending error */
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "getsockopt %d", n);
			return (-1);
		}

		struct iovec iov_logs[APR_MAX_IOVEC_SIZE] = {0, };
		int iov_idx = 0;
		apr_size_t new_length = 0;
		int i = 0;
		int tlen = 0;
		const char *buf;
		// TODO iovec limit 1024
	    // memcached protocol
	    // "SET <key> <flags> <exptime> <bytes> [noreply]\r\n"
	    iov_logs[iov_idx].iov_base = (void *) "set ";
	    iov_logs[iov_idx].iov_len = 4;
	    new_length += 4;
	    iov_idx++;

	    buf = apr_psprintf(r->pool, "%s 1 0 %"APR_SIZE_T_FMT"\r\n", category, len);
	    tlen = strlen(buf);
	    iov_logs[iov_idx].iov_base = (void *) buf;
	    iov_logs[iov_idx].iov_len = tlen;
	    new_length += tlen;
	    iov_idx++;

		for (i = 0; i < nelts; ++i) {
			iov_logs[iov_idx].iov_base = (void *) strs[i];
			iov_logs[iov_idx].iov_len = strl[i];
			new_length += strl[i];
			iov_idx++;
		}

		iov_logs[iov_idx].iov_base = (void *) "\r\nquit\r\n";
	    iov_logs[iov_idx].iov_len = 8;
	    new_length += 8;
	    iov_idx++;

		if ((n = writev(sockfd, iov_logs, iov_idx)) != new_length) { /* send error */
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "writev %d != %"APR_SIZE_T_FMT, n, new_length);
			return (-1);
		} else {
			// ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r, "writev success %d", n);
			return (0);
		}
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "select error %d", n);
	/* select error */
	return (-1);
}

static int recv_with_timeout(request_rec *r, int sockfd, apr_time_t usec, apr_pool_t *pool, char **recvstr) {
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
		char buf[8192] = { 0, };
		int nbuf = sizeof(buf) - 1;

		if ((n = select(sockfd + 1, &rset, NULL, NULL, (usec ? &tval : NULL))) == 0) {
			// ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r, "select ETIMEDOUT %d", n);
			return (ETIMEDOUT);
		}

		if (FD_ISSET(sockfd, &rset)) {
			int error = 0;
			socklen_t len = sizeof(error);
			if ((n = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len)) < 0) { /* pending error */
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "getsockopt SOL_SOCKET %d", n);
				return (-1);
			}
			if ((result = recv(sockfd, buf, nbuf, 0)) < 0) { /* recv error */
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "recv SOCKET %d", result);
				return (-1);
			}
			if (result == 0) { /* EOF */
				// ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "recv %s(EOF)", *recvstr);
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
	// hints.ai_family = AF_UNSPEC;            /* Allow IPv4 or IPv6 */
    hints.ai_family = AF_INET;           /* Allow IPv4 */
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

apr_status_t kestrel_write(request_rec *r, kestrel_log_t *kestrel_log,
									const char **strs,
									int *strl,
									int nelts,
									apr_size_t len) {
	struct addrinfo *addr = NULL;
	char *response = NULL;
	apr_status_t rv = 0;
	apr_time_t timeout;
	int socket_descriptor = -1;
	int retry_counter = 0;

	if (!strs || nelts == 0 || len == 0) {
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
		if ((socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1) {     // AF_UNSPEC(ipv4, ipv6), AF_INET(ipv4)
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "apr_socket_create fail (%s@%s:%s) re(%d)",
								kestrel_log->category, kestrel_log->host, kestrel_log->port, retry_counter);
			continue;
		}

		set_sock_linger(socket_descriptor);

		/* connect socket with non-block with timeout */
		if ((rv = connect_nonb_with_timeout(socket_descriptor, (struct sockaddr *) (addr->ai_addr), addr->ai_addrlen, timeout)) != 0) {
			close(socket_descriptor);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "_connect_nonb_with_timeout fail (%s@%s:%s) re(%d)",
								kestrel_log->category, kestrel_log->host, kestrel_log->port, retry_counter);
			continue;
		}

		/* send */
		if ((rv = send_with_timeout(r, socket_descriptor, timeout, kestrel_log->category, strs, strl, nelts, len)) != 0) {
			close(socket_descriptor);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "_send_with_timeout fail (%s@%s:%s) re(%d)",
								kestrel_log->category, kestrel_log->host, kestrel_log->port, retry_counter);
			continue;
		}

		/* recv */
		if ((rv = recv_with_timeout(r, socket_descriptor, timeout, r->pool, &response)) < 0) {
			close(socket_descriptor);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "_recv_with_timeout fail (%s@%s:%s) : %s re(%d)",
								kestrel_log->category, kestrel_log->host, kestrel_log->port, response ? response : "", retry_counter);
			continue;
		}

		close(socket_descriptor);
		if (response && apr_strnatcmp("STORED\r\n", response) == 0) {
            // ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "##### RESPONSE : rv(%d) (%s) re(%d)",
            //              	  	rv, response, retry_counter);
			return (APR_SUCCESS);
		}
		// ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "kestrel_write. re(%d)", retry_counter);
	}

	return (APR_SUCCESS);
}
