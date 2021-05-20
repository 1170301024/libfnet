
INCLDDIR = include
CFLAGS = -O2 -I $(INCLDDIR)  -Wall -Wbad-function-cast -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wendif-labels -Wformat -Wformat-extra-args -Wformat-security -Wformat-y2k -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wimport -Winline -Winvalid-pch -Wmain -Wmissing-braces -Wmissing-format-attribute -Wmissing-noreturn -Wmultichar -Wnested-externs -Wnonnull -Wparentheses -Wpointer-arith -Wreturn-type -Wsequence-point -Wsign-compare -Wstrict-aliasing -Wstrict-prototypes -Wswitch -Wswitch-default -Wswitch-enum -Wsystem-headers -Wtrigraphs -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -Wwrite-strings -Wno-pointer-sign -Wextra -fPIC -fPIE -D_FORTIFY_SOURCE=2 -O -D_GNU_SOURCE  -Wunused-but-set-variable -Wcast-align -Wl,-z,noexecstack


OBJS = connect_manage.lo dispatch.lo error.lo flow.lo extractor.lo \
		utils.lo libfnet.lo nflog.lo packets.lo wrappthread.lo tls.lo parse_log.lo lablib.lo

LADIR = /usr/local/joy/lib

libfnet.la: $(OBJS) -lpthread -lpcap
	libtool --mode=link gcc -o libfnet.la $(OBJS)  -rpath /usr/local/lib -lpthread  -lpcap -lxml2 \
			 -lm $(LADIR)/libjoy.la -lm\
			./lib/safe_c_stub/libjoy_la-safe_mem_stub.o \
			./lib/safe_c_stub/libjoy_la-safe_str_stub.o


fnet_client: $(CLIENT_OBJS)
	libtool --mode=compile gcc -c $(CLIENT_OBJS) -o fnet_client

fnet_client.lo:
	libtool --mode=compile gcc -c $(CFLAGS) fnet_client.c 


connect_manage.lo:
	libtool --mode=compile gcc -c $(CFLAGS) connect_manage.c

error.lo:
	libtool --mode=compile gcc -c $(CFLAGS) error.c

dispatch.lo:
	libtool --mode=compile gcc -c $(CFLAGS) dispatch.c

libfnet.lo:
	libtool --mode=compile gcc -c $(CFLAGS) libfnet.c

config.lo:
	libtool --mode=compile gcc -c $(CFLAGS) config.c


flow.lo:
	libtool --mode=compile gcc -c $(CFLAGS) flow.c

utils.lo:
	libtool --mode=compile gcc -c $(CFLAGS) utils.c

extractor.lo:
	libtool --mode=compile gcc -c $(CFLAGS) extractor.c

nflog.lo:
	libtool --mode=compile gcc -c $(CFLAGS) nflog.c	

packets.lo:
	libtool --mode=compile gcc -c $(CFLAGS) packets.c

wrappthread.lo:
	libtool --mode=compile gcc -c $(CFLAGS) wrappthread.c

tls.lo:
	libtool --mode=compile gcc -c $(CFLAGS) tls.c

parse_log.lo:
	libtool --mode=compile gcc -c $(CFLAGS) parse_log.c
	
lablib.lo:
	libtool --mode=compile gcc -c $(CFLAGS) lablib.c
	
.PHONY: install
install:
	libtool --mode=install install -c libfnet.la /usr/local/lib/

.PHONY: clean
clean:
	rm *.o 
	rm *.lo
	rm *.la
	rm -r .libs