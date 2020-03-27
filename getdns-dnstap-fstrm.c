/**
 * \file getdns-dnstap-fstrm.c
 * @brief Functions for setting up dnstap servers
 */

/*
 * Copyright (c) 2020 NLNet Labs
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the names of the copyright holders nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "getdns-dnstap-fstrm.h"
#include <getdns/getdns_extra.h>

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <fcntl.h>
#include <assert.h>

#define GDNS_FSTRM_ACCEPT	1
#define GDNS_FSTRM_START	2
#define GDNS_FSTRM_STOP		3
#define GDNS_FSTRM_READY	4

#define GDNS_FSTRM_CONTENT_TYPE	1

#define GDNS_DNSTAP_ID		"protobuf:dnstap.Dnstap"
#define GDNS_DNSTAP_ID_SZ	(sizeof(GDNS_DNSTAP_ID) - 1)

struct getdns_dnstap_server {
	getdns_context         *ctxt;
	getdns_eventloop       *loop;
	getdns_eventloop_event  ev;
	void                   *userarg;
	getdns_frame_cb_type    cb;
	int                     fd;
	struct sockaddr_storage ss;
	socklen_t               len;
};

typedef struct dnstap_connection {
	getdns_dnstap_server   *srv;
	int                     fd;
	struct sockaddr_storage ss;
	socklen_t               len;
	getdns_eventloop_event  ev;

	int                     started;

	uint8_t                *buf_write_cur;
	size_t                  buf_write_len;

	size_t                  buf_sz;
	uint8_t                *buf_cur;
	uint8_t                *buf_end;
	uint8_t                 buf[1048576];
} dnstap_connection;

/* Reset buf_cur to start of buffer, moving along whatever came after  */
static inline void buf_reset(dnstap_connection *c)
{
	if (c->buf_cur > c->buf) {
		size_t sz = c->buf_end - c->buf_cur;

		if (sz)	memmove(c->buf, c->buf_cur, sz);
		c->buf_cur = c->buf;
		c->buf_end = c->buf + sz;
	}
}

static inline int buf_avail(dnstap_connection *c, size_t n)
{
	assert(n <= c->buf_sz);

	if (c->buf_cur + n - c->buf > c->buf_sz)
		buf_reset(c);
	return c->buf_end - c->buf_cur >= n;
}

static inline void buf_next(dnstap_connection *c, size_t n)
{
	if (c->buf_cur + n - c->buf > c->buf_sz - 12)
		buf_reset(c);
	assert(c->buf_cur + n <= c->buf_end);
	c->buf_cur += n;
}

static inline uint32_t buf_read_u32(uint8_t *buf, size_t pos)
{ return ntohl(((uint32_t *)buf)[pos]); }

static inline void buf_write_u32(uint8_t *buf, size_t pos, uint32_t value)
{ ((uint32_t *)buf)[pos] = htonl(value); }


static int sock_nonblock(int sockfd)
{
	int flag;
	return ((flag = fcntl(sockfd, F_GETFL))                   < 0
	             || fcntl(sockfd, F_SETFL, flag | O_NONBLOCK) < 0) ? -1 : 0;
}

static void connection_close(dnstap_connection *c)
{
	if (c->ev.ev)
		(void) c->srv->loop->vmt->clear(c->srv->loop, &c->ev);
	close(c->fd);
	free(c);
}

#if 1
#define CTRL_FRAME_ERR(C, MSG) fprintf(stderr, "%s\n", (MSG))
#else
#define CTRL_FRAME_ERR(C, MSG) ((void)(C))
#endif

static void read_cb(void *arg);
static void write_cb(void *arg)
{
	dnstap_connection *c = (dnstap_connection *)arg;
	ssize_t            sz;

	sz = write(c->fd, c->buf_write_cur, c->buf_write_len);
	if (sz == -1)
		perror("Writing to connection");

	else if (((c->buf_write_cur += sz), (c->buf_write_len -= sz)) > 0)
		return; /* write some more */

	else if (c->srv->loop->vmt->clear(c->srv->loop, &c->ev))
		CTRL_FRAME_ERR(c, "getdns_eventloop_clear write");

	else if ( (c->ev.read_cb = read_cb)
	        , (c->ev.write_cb = NULL))
		; /* unreachable */

	else if (c->srv->loop->vmt->schedule(c->srv->loop, c->fd, -1, &c->ev))
		CTRL_FRAME_ERR(c, "getdns_eventloop_schedule read");
	else
		return; /* start reading */

	connection_close(c);
}

static int control_frame_match_dnstap(uint8_t *ptr, size_t len)
{
	uint8_t *end = ptr + len;

	while (ptr + 8 < end) {
		uint32_t field_type = buf_read_u32(ptr, 0);
		uint32_t field_len  = buf_read_u32(ptr, 1);

		if (field_type != GDNS_FSTRM_CONTENT_TYPE) {
			CTRL_FRAME_ERR(c, "FORMERR: Unknown field type");
			return 0;
		
		} else if (ptr + field_len > end) {
			CTRL_FRAME_ERR(c, "FORMERR: Field overflow");
			return 0;

		} else if (field_len == GDNS_DNSTAP_ID_SZ
		     && !memcmp(ptr + 2 * sizeof(uint32_t), GDNS_DNSTAP_ID
		                                          , GDNS_DNSTAP_ID_SZ))
			return 1;
		else
			ptr += 2 * sizeof(uint32_t) + field_len;
	}
	return 0;
}

static int process_control_frame(dnstap_connection *c)
{
	uint32_t payload_len;
	uint32_t frame_len;
	uint32_t ctrl_type;
	uint8_t *payload;

	/* Control frame */
	if (!buf_avail(c, 3 * sizeof(uint32_t)))
		return 0; /* read some more */

	payload_len = buf_read_u32(c->buf_cur, 1);
	fprintf(stderr, "payload_len: %d\n", (int)payload_len);
	payload   =  c->buf_cur + 2 * sizeof(uint32_t);
	frame_len = payload_len + 2 * sizeof(uint32_t);
	if (payload_len < sizeof(uint32_t)
	||  payload_len > 512 /* max control frame length */)
		CTRL_FRAME_ERR(c, "FORMERR: Control frame length");
	
	else if (!buf_avail(c, frame_len))
		return 0; /* read some more */

	else if ( (payload += sizeof(uint32_t))
	        , (payload_len -= sizeof(uint32_t)), 0)
		; /* unreachable */

	else switch((ctrl_type = buf_read_u32(c->buf_cur, 2))) {
	case GDNS_FSTRM_READY:
		fprintf(stderr, "GDNS_FSTRM_READY\n");
		if (!control_frame_match_dnstap(payload, payload_len)) {
			CTRL_FRAME_ERR(c, "Not a dnstap stream");
			/* Wait for dnstap stream */
			goto exit_success;
		}
		buf_write_u32(c->buf_cur, 0, 0);
		buf_write_u32(c->buf_cur, 1, GDNS_DNSTAP_ID_SZ
		                           + 3 * sizeof(uint32_t));
		buf_write_u32(c->buf_cur, 2, GDNS_FSTRM_ACCEPT);
		buf_write_u32(c->buf_cur, 3, GDNS_FSTRM_CONTENT_TYPE);
		buf_write_u32(c->buf_cur, 4, GDNS_DNSTAP_ID_SZ);
		memcpy(c->buf_cur + 5 * sizeof(uint32_t), GDNS_DNSTAP_ID
		                                        , GDNS_DNSTAP_ID_SZ);
		c->buf_write_cur = c->buf_cur;
		c->buf_write_len = GDNS_DNSTAP_ID_SZ + 5 * sizeof(uint32_t);

		if (c->srv->loop->vmt->clear(c->srv->loop, &c->ev))
			CTRL_FRAME_ERR(c, "getdns_eventloop_clear read");

		else if ( (c->ev.write_cb = write_cb)
		        , (c->ev.read_cb  = NULL))
			; /* unreachable */

		else if (c->srv->loop->vmt->schedule(
		    c->srv->loop, c->fd, -1, &c->ev))
			CTRL_FRAME_ERR(c, "getdns_eventloop_schedule write");
		else 
			/* Start writing */
			goto exit_success;
		break;

	case GDNS_FSTRM_START:
		if (!control_frame_match_dnstap(payload, payload_len))
			CTRL_FRAME_ERR(c, "Not a dnstap stream");
		else
			c->started = 1;

		/* Start reading data frames */
		goto exit_success;

	case GDNS_FSTRM_STOP:
		c->started = 0;

		/* Continue reading */
		goto exit_success;
	default:
		/* Unhandled control frame type. Ignore. */
		goto exit_success;
	}
	/* exit error */
	connection_close(c);
	return 1;

exit_success:
	/* exit success */
	buf_next(c, frame_len);
	return 0;
}

static void read_cb(void *arg)
{
	ssize_t  sz;
	dnstap_connection *c = (dnstap_connection *)arg;

	if ((sz = read( c->fd, c->buf_end
	                     , c->buf_sz - (c->buf_end - c->buf))) == -1) {
		perror("Reading from connection");
		connection_close(c);
		return;
	}
	c->buf_end += sz;

	while (buf_avail(c, sizeof(uint32_t))) {
		uint32_t frame_len = ntohl(*(uint32_t *)c->buf_cur);

		if (!frame_len) {
			if (process_control_frame(c))
				break; /* connection was closed */
			else
				continue;
		}
		else if (!buf_avail(c, frame_len + sizeof(uint32_t)))
			break; /* read some more */

		if (c->started) {
			c->srv->cb(c->srv->userarg,
			    frame_len, c->buf_cur + sizeof(uint32_t));
		}
		buf_next(c, frame_len + sizeof(uint32_t));
	};
}

static void accept_cb(void *arg)
{
	dnstap_connection c, *new_c;
	getdns_return_t   r;

	(void) memset(&c, 0, sizeof(c));
	c.srv = (getdns_dnstap_server *)arg;
	c.len = sizeof(c.ss);
	c.buf_sz = sizeof(c.buf);

	if ((c.fd = accept(c.srv->fd, (struct sockaddr *)&c.ss, &c.len)) == -1) {
		perror("accept");
		return;
	}
	fprintf(stderr, "Accepting connection from ...\n");
	if (sock_nonblock(c.fd) < 0)
		perror("sock_nonblock connection");

	if (!(new_c = c.ev.userarg = malloc(sizeof(c)))) {
		fprintf(stderr, "memory error\n");
		exit(EXIT_FAILURE);
	}
	c.ev.read_cb = read_cb;
	c.buf_cur = c.buf_end = new_c->buf;
	(void) memcpy(c.ev.userarg, &c, sizeof(c));
	if (!(r = c.srv->loop->vmt->schedule(c.srv->loop, c.fd, -1, &new_c->ev)))
		return;

	fprintf(stderr, "getdns_eventloop_schedule connection: %s\n"
	              ,  getdns_get_errorstr_by_id(r));
}

getdns_return_t getdns_setup_dnstap_server_unix(
    getdns_context *ctxt, getdns_frame_cb_type cb, void *userarg,
    const char *path, getdns_dnstap_server **return_srv)
{
	getdns_dnstap_server   *srv = NULL;
	getdns_return_t         r;

	if (!ctxt || !cb || !return_srv
	|| strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
		return GETDNS_RETURN_INVALID_PARAMETER;

	if (!(srv = calloc(1, sizeof(getdns_dnstap_server))))
		return GETDNS_RETURN_MEMORY_ERROR;

	srv->ctxt = ctxt;
	srv->userarg = userarg;
	srv->cb = cb;
	srv->ev.userarg = srv;
	srv->ev.read_cb = accept_cb;
	srv->fd = -1;
	srv->ss.ss_family = AF_UNIX;
	(void) strncpy(        ((struct sockaddr_un *)&srv->ss)->sun_path
	              , path
	              , sizeof(((struct sockaddr_un *)&srv->ss)->sun_path) - 1);
	(void)  unlink(        ((struct sockaddr_un *)&srv->ss)->sun_path);
	srv->len =      sizeof(  struct sockaddr_un);

	if ((r = getdns_context_get_eventloop(srv->ctxt, &srv->loop)))
		fprintf(stderr, "getdns_context_get_eventloop");

	else if ((srv->fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1
	    || sock_nonblock(srv->fd) == -1
	    || bind(srv->fd, (struct sockaddr*)&srv->ss, srv->len)
	    || listen(srv->fd, 5))
		r = GETDNS_RETURN_IO_ERROR;

	else if ((r = srv->loop->vmt->schedule(srv->loop, srv->fd, -1, &srv->ev)))
		fprintf(stderr, "getdns_eventloop_schedule server");
	else {
		*return_srv = srv;
		return GETDNS_RETURN_GOOD;
	}
	if (srv->fd != -1)
		close(srv->fd);
	free(srv);
	return r;
}
