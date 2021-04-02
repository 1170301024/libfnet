
INCLDDIR = include
CFLAGS = -O2 -I $(INCLDDIR)  -Wall -Wbad-function-cast -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wendif-labels -Wformat -Wformat-extra-args -Wformat-security -Wformat-y2k -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wimport -Winline -Winvalid-pch -Wmain -Wmissing-braces -Wmissing-format-attribute -Wmissing-noreturn -Wmultichar -Wnested-externs -Wnonnull -Wparentheses -Wpointer-arith -Wreturn-type -Wsequence-point -Wsign-compare -Wstrict-aliasing -Wstrict-prototypes -Wswitch -Wswitch-default -Wswitch-enum -Wsystem-headers -Wtrigraphs -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -Wwrite-strings -Wno-pointer-sign -Wextra -fPIC -fPIE -D_FORTIFY_SOURCE=2 -O -D_GNU_SOURCE  -Wunused-but-set-variable -Wcast-align -Wl,-z,noexecstack


OBJS = connect_manage.o dispatch.o error.o flow.o extractor.o \
		utils.o libfnet.o nflog.o packets.o wrappthread.o tls.o parse_log.o lablib.o

LADIR = ./lib/joy

lab_task: lab_task.lo $(OBJS) -lpthread -lpcap
	libtool --mode=link gcc -o lab_task $(OBJS) -lpthread -lpcap -lxml2 \
			lab_task.lo -lm $(LADIR)/libjoy.la  -lm \
			./lib/safe_c_stub/libjoy_la-safe_mem_stub.o \
			./lib/safe_c_stub/libjoy_la-safe_str_stub.o

lab_task.lo: $(INCLDDIR)/*.h
	libtool --mode=compile gcc -c lab_task.c


fnet_client: $(CLIENT_OBJS)
	cc $(CLIENT_OBJS) -o fnet_client

fnet_client.o:
	cc -c $(CFLAGS) fnet_client.c 


connect_manage.o:
	cc -c $(CFLAGS) connect_manage.c

error.o:
	cc -c $(CFLAGS) error.c

dispatch.o:
	cc -c $(CFLAGS) dispatch.c

libfnet.o:
	cc -c $(CFLAGS) libfnet.c

config.o:
	cc -c $(CFLAGS) config.c


flow.o:
	cc -c $(CFLAGS) flow.c

utils.o:
	cc -c $(CFLAGS) utils.c

extractor.o:
	cc -c $(CFLAGS) extractor.c

nflog.o:
	cc -c $(CFLAGS) nflog.c	

packets.o:
	cc -c $(CFLAGS) packets.c

wrappthread.o:
	cc -c $(CFLAGS) wrappthread.c

tls.o:
	cc -c $(CFLAGS) tls.c

parse_log.o:
	cc -c $(CFLAGS) parse_log.c
lablib.o:
	cc -c $(CFLAGS) lablib.c
	
.PHONY: clean
clean:
	rm *.o 
	rm *.lo
	rm lab_task