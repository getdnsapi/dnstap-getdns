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

static const char *get_msg_type_str(ssize_t msg_type)
{
	static const char *msg_types_strs[] = { ""
				              , "AUTH_QUERY"
				              , "AUTH_RESPONSE"
				              , "RESOLVER_QUERY"
				              , "RESOLVER_RESPONSE"
				              , "CLIENT_QUERY"
				              , "CLIENT_RESPONSE"
				              , "FORWARDER_QUERY"
				              , "FORWARDER_RESPONSE"
				              , "STUB_QUERY"
				              , "STUB_RESPONSE"
				              , "TOOL_QUERY"
				              , "TOOL_RESPONSE"
				              };
	if (msg_type <= 0
	||  msg_type >= sizeof(msg_types_strs) / sizeof(*msg_types_strs))
		return "UNKNOWN_MESSAGE_TYPE";
	else
		return msg_types_strs[msg_type];
}

void process_frame(void *userarg, size_t len, uint8_t *data)
{
	getdns_return_t   r = GETDNS_RETURN_GOOD;
	getdns_dict      *msg       = NULL;
	getdns_bindata   *qname     = NULL;
	char             *qname_str = NULL;
	uint32_t          qtype;
	Dnstap__Dnstap   *d         = NULL;
	uint32_t          udp_payload_size;
	getdns_list      *options   = NULL;
	size_t          n_options   = 0;
	getdns_dict      *option;
	uint32_t          option_code;
	getdns_bindata   *option_data;

	(void)userarg;
	assert(data);

	if (!(d = dnstap__dnstap__unpack(NULL, len, data)))
		fprintf(stderr, "Error unpacking Dnstap data\n");

	else if (d->type != DNSTAP__DNSTAP__TYPE__MESSAGE)
		fprintf(stderr, "Unknown Dnstap.Type: %d\n", (int)d->type);

	else if (!d->message->has_query_message && !d->message->has_response_message)
		; /* cannot decode message */

	else if (   (  d->message->has_query_message
	            && (r = getdns_wire2msg_dict(d->message->query_message.data,
	                                         d->message->query_message.len, &msg)))
	         || (   d->message->has_response_message
	            && (r = getdns_wire2msg_dict(d->message->response_message.data,
	                                         d->message->response_message.len, &msg))))
		fprintf(stderr, "getdns_wire2msg_dict");

	else if ((r = getdns_dict_get_bindata(msg, "/question/qname", &qname)))
		fprintf(stderr, "getdns_dict_get_bindata qname");

	else if ((r = getdns_convert_dns_name_to_fqdn(qname, &qname_str)))
		fprintf(stderr, "getdns_convert_dns_name_to_fqdn");

	else if ((r = getdns_dict_get_int(msg, "/question/qtype", &qtype)))
		fprintf(stderr, "getdns_dict_get_int qtype");

	else if ((r = getdns_dict_get_int(
	    msg, "/additional/0/udp_payload_size", &udp_payload_size)))
		fprintf(stderr, "msg[/additional/0/udp_payload_size]");

	else if (getdns_dict_get_list(
	    msg, "/additional/0/rdata/options", &options), 0)
		; /* pass; fprintf(stderr, "msg[/additional/0/rdata/options]"); */

	else if (options && (r = getdns_list_get_length(options, &n_options)))
		fprintf(stderr, "getdns_list_get_length");
	else {
		size_t i;

		fprintf(stdout, "%s %s TYPE%d udp_payload_size: %d, msg_size: %d\n",
		    get_msg_type_str(d->message->type),
		    qname_str, (int)qtype, (int)udp_payload_size,
		    (int)( d->message->has_query_message
		         ? d->message->query_message.len
		         : d->message->response_message.len));

		for (i = 0; !r && i < n_options; i++) {
			if ((r = getdns_list_get_dict(options, i, &option)))
				fprintf(stderr, "get option from options\n");

			else if ((r = getdns_dict_get_int(option, "option_code", &option_code)))
				fprintf(stderr, "get option_code from option\n");

			else if ((r = getdns_dict_get_bindata(option, "option_data", &option_data)))
				fprintf(stderr, "get option_data from option\n");
			else
				fprintf(stderr, "\tcode: %.2d, len(data): %.2d\n"
				              , (int)option_code, (int)option_data->size);
		}
	}

	if (r) fprintf(stderr, ": %s\n", getdns_get_errorstr_by_id(r));
	if (qname_str)
		free(qname_str);
	getdns_dict_destroy(msg);
	if (d)
		dnstap__dnstap__free_unpacked(d, NULL);
}

int main(int argc, char **argv)
{
	getdns_return_t       r;
	getdns_context       *ctxt = NULL;
	getdns_dnstap_server *srv  = NULL;


	if ((r = getdns_context_create(&ctxt, 1)))
		fprintf(stderr, "getdns_context_create");

	else if ((r = getdns_setup_dnstap_server_unix(
	    ctxt, process_frame, NULL, "dnstap.sock", &srv)))
		fprintf(stderr, "getdns_setup_dnstap_server_unix");
	else 
		getdns_context_run(ctxt);

	getdns_context_destroy(ctxt);

	if (r) { 
		fprintf(stderr, ": %s\n", getdns_get_errorstr_by_id(r));
		if (r == GETDNS_RETURN_IO_ERROR)
			fprintf(stderr, "ioerror: %s\n", strerror(errno));
	}
	return -1;
}
