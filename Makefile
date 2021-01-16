
INCLDDIR = include
CFLAGS = -O2 -I $(INCLDDIR)  -Wall #-Wbad-function-cast -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wendif-labels -Wformat -Wformat-extra-args -Wformat-security -Wformat-y2k -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wimport -Winline -Winvalid-pch -Wmain -Wmissing-braces -Wmissing-format-attribute -Wmissing-noreturn -Wmultichar -Wnested-externs -Wnonnull -Wparentheses -Wpointer-arith -Wreturn-type -Wsequence-point -Wsign-compare -Wstrict-aliasing -Wstrict-prototypes -Wswitch -Wswitch-default -Wswitch-enum -Wsystem-headers -Wtrigraphs -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -Wwrite-strings -Wno-pointer-sign -Wextra -fPIC -fPIE -D_FORTIFY_SOURCE=2 -O -D_GNU_SOURCE  -Wunused-but-set-variable -Wcast-align -Wl,-z,noexecstack

OBJS = lab_task.o connect_manage.o dispatch.o error.o fnetlib.o 

CLIENT_OBJS = fnet_client.o connect_manage.o \
				dispatch.o error.o config.o libfnet.o feature.o

lab_task: $(OBJS)
	cc $(OBJS) -o lab_task

fnet_client: $(CLIENT_OBJS)
	cc $(CLIENT_OBJS) -o fnet_client

fnet_client.o:
	cc -c $(CFLAGS) fnet_client.c 

lab_task.o:
	cc -c $(CFLAGS) lab_task.c

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

feature.o:
	cc -c $(CFLAGS) feature.c

fnetlib.o:
	cc -c $(CFLAGS) fnetlib.c
	
.PHONY: clean
clean:
	rm *.o 
	rm lab_task