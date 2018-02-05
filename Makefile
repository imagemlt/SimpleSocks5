CC = gcc
CFLAGS = -Wall 

TARGET = server
OBJS = socks5server.o

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%*.o:%*.c
	$(CC) $(CFLAG) -c $^ -o $@

.PHONY:
	clean
clean:
	rm -rf $(TARGET) $(OBJS)
