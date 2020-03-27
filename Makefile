CFLAGS = -g -I. -Wall -Wpedantic
PROGS = getdns_dnstap_repeater
LIBS = -lgetdns -lprotobuf-c
GETDNS_DNSTAP_REPEATER_OBJS = getdns_dnstap_repeater.o getdns-dnstap-fstrm.o dnstap.pb-c.o

all: $(PROGS)

.SUFFIXES: .c .o .h .proto

.c.o:
	$(CC) $(CFLAGS) -c $<

getdns_dnstap_repeater: $(GETDNS_DNSTAP_REPEATER_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(GETDNS_DNSTAP_REPEATER_OBJS) $(LIBS)

dnstap.pb-c.o: dnstap.pb/dnstap.pb-c.c dnstap.pb/dnstap.pb-c.h
	$(CC) $(CFLAGS) -c dnstap.pb/dnstap.pb-c.c

dnstap.pb/dnstap.pb-c.c dnstap.pb/dnstap.pb-c.h: dnstap.pb/dnstap.proto
	protoc-c --c_out=. dnstap.pb/dnstap.proto

clean:
	rm -f $(PROGS) $(GETDNS_DNSTAP_REPEATER_OBJS) dnstap.pb/dnstap.pb-c.[ch]

getdns_dnstap_repeater.o: dnstap.pb/dnstap.pb-c.h
