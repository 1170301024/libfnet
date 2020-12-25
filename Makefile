
INCLDDIR = include
CFLAGS = -I $(INCLDDIR)/*.h

OBJS = test.o connect_manage.o dispatch.o error.o 

test: $(OBJS)
	cc $(OBJS) -o test
	
test.o:
	cc -c $(CFLAGS) test.c

connect_manage.o:
	cc -c $(CFLAGS) connect_manage.c

error.o:
	cc -c $(CFLAGS) error.c

dispatch.o:
	cc -c $(CFLAGS) dispatch.c


.PHONY: clean
clean:
	rm *.o test include/*.gch