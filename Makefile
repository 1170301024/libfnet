
INCLDDIR = include
CFLAGS = -I $(INCLDDIR)/*.h

OBJS = lab_task.o connect_manage.o dispatch.o error.o 

lab_task: $(OBJS)
	cc $(OBJS) -o lab_task
	
lab_task.o:
	cc -c $(CFLAGS) lab_task.c

connect_manage.o:
	cc -c $(CFLAGS) connect_manage.c

error.o:
	cc -c $(CFLAGS) error.c

dispatch.o:
	cc -c $(CFLAGS) dispatch.c


.PHONY: clean
clean:
	rm *.o lab_task include/*.gch