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
#include "dnstap.pb/dnstap.pb-c.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

typedef struct repeater_globals {
	getdns_context       *ctxt;
	getdns_dnstap_server *srv;
	size_t                n_completed;
	size_t                n_timedout;
	size_t                n_erred;
} repeater_globals;

void query_cb(getdns_context *ctxt, getdns_callback_type_t callback_type,
    getdns_dict *response, void *userarg, getdns_transaction_t transaction_id)
{
	repeater_globals *g = (repeater_globals *)userarg;

	assert(userarg);
	switch (callback_type) {
	case GETDNS_CALLBACK_COMPLETE: g->n_completed++; break;
	case GETDNS_CALLBACK_TIMEOUT : g->n_timedout++ ; break;
	case GETDNS_CALLBACK_ERROR   : g->n_erred++    ; break;
	default: fprintf(stderr, "%d\n", callback_type); goto no_counts;
	}
	if ((g->n_completed + g->n_timedout + g->n_erred) % 100 == 0)
		fprintf(stderr, "%d %d %d\n", (int)g->n_completed
		       , (int)g->n_timedout, (int)g->n_erred);
no_counts:
	if (response)
		getdns_dict_destroy(response);
}

void process_frame(void *userarg, size_t len, uint8_t *data)
{
	repeater_globals *g = (repeater_globals *)userarg;
	getdns_return_t   r = GETDNS_RETURN_GOOD;
	getdns_dict      *msg       = NULL;
	getdns_bindata   *qname     = NULL;
	char             *qname_str = NULL;
	uint32_t          qtype;
	Dnstap__Dnstap   *d         = NULL;
	char              ip[INET6_ADDRSTRLEN] = "?";

	assert(userarg);
	assert(data);

	if (!(d = dnstap__dnstap__unpack(NULL, len, data)))
		fprintf(stderr, "Error unpacking Dnstap data\n");

	else if (d->type != DNSTAP__DNSTAP__TYPE__MESSAGE)
		fprintf(stderr, "Unknown Dnstap.Type: %d\n", (int)d->type);

	else if (d->message->type != DNSTAP__MESSAGE__TYPE__AUTH_QUERY
	     &&  d->message->type != DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY
	     &&  d->message->type != DNSTAP__MESSAGE__TYPE__CLIENT_QUERY
	     &&  d->message->type != DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY
	     &&  d->message->type != DNSTAP__MESSAGE__TYPE__STUB_QUERY
	     &&  d->message->type != DNSTAP__MESSAGE__TYPE__TOOL_QUERY)
		; /* ignore responses */

	else if (!d->message->has_query_address)
		; /* Exclude my own to prevent loops */

	else if ((d->message->query_address.len == 4) && 0xB9318C00
	    == (ntohl(*(uint32_t *)d->message->query_address.data) & 0xFFFFFC00))
		; /* skip if not coming from NLnet Labs office */

	else if ((d->message->query_address.len == 16) && 0x2A04B900
	    == (ntohl(*(uint32_t *)d->message->query_address.data) & 0xFFFFFFF8))
		; /* skip if not coming from NLnet Labs office */

	else if (!d->message->has_query_message)
		; /* cannot decode message */

	else if ((r = getdns_wire2msg_dict(d->message->query_message.data,
	    d->message->query_message.len, &msg)))
		fprintf(stderr, "getdns_wire2msg_dict");

	else if ((r = getdns_dict_get_bindata(msg, "/question/qname", &qname)))
		fprintf(stderr, "getdns_dict_get_bindata qname");

	else if ((r = getdns_convert_dns_name_to_fqdn(qname, &qname_str)))
		fprintf(stderr, "getdns_convert_dns_name_to_fqdn");

	else if ((r = getdns_dict_get_int(msg, "/question/qtype", &qtype)))
		fprintf(stderr, "getdns_dict_get_int qtype");

	else if (qtype != 1 && qtype != 12 && qtype != 15 && qtype != 28)
		; /* Only A, PTR, MX and AAAA requests */

	else if ((d->message->query_address.len == 4)
	    && !inet_ntop(AF_INET, d->message->query_address.data, ip, sizeof(ip)))
		fprintf(stderr, "inet_ntop IPv4");

	else if ((d->message->query_address.len == 16)
	    && !inet_ntop(AF_INET6, d->message->query_address.data, ip, sizeof(ip)))
		fprintf(stderr, "inet_ntop IPv6");

	else if ((r = getdns_general(
	    g->ctxt, qname_str, qtype, NULL, g, NULL, query_cb)))
		fprintf(stderr, "Could not schedule query");

	if (r) fprintf(stderr, ": %s\n", getdns_get_errorstr_by_id(r));
	if (qname_str)
		free(qname_str);
	getdns_dict_destroy(msg);
	if (d)
		dnstap__dnstap__free_unpacked(d, NULL);
}

int main(int argc, char **argv)
{
	repeater_globals g;
	getdns_list     *upstreams = NULL;
	getdns_return_t  r;

	(void) memset(&g, 0, sizeof(g));

	if ((r = getdns_context_create(&g.ctxt, 1)))
		fprintf(stderr, "getdns_context_create");

	else if ((r = getdns_context_set_resolution_type(
	    g.ctxt, GETDNS_RESOLUTION_STUB)))
		fprintf(stderr, "getdns_context_set_resolution_type(STUB)");

	else if ((r = getdns_str2list("[ 185.49.141.38 ]", &upstreams)))
		fprintf(stderr, "getdns_str2list");

	else if ((r = getdns_context_set_upstream_recursive_servers(
	    g.ctxt, upstreams)))
		fprintf(stderr, "getdns_context_set_upstream_recursive_servers");
	
	else if ((r = getdns_setup_dnstap_server_unix(
	    g.ctxt, process_frame, &g, "dnstap.sock", &g.srv)))
		fprintf(stderr, "getdns_setup_dnstap_server_unix");
	else 
		getdns_context_run(g.ctxt);

	getdns_list_destroy(upstreams);
	getdns_context_destroy(g.ctxt);

	if (r) { 
		fprintf(stderr, ": %s\n", getdns_get_errorstr_by_id(r));
		if (r == GETDNS_RETURN_IO_ERROR)
			fprintf(stderr, "ioerror: %s\n", strerror(errno));
	}
	return -1;
}
