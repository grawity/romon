CFLAGS := -D_GNU_SOURCE
LIBS := -lpcap

#%.o: %.c $(DEPS)
#	$(CC) -c -o $@ $< $(CFLAGS)

romonrelay: main.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
