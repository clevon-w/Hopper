CC = clang
CFLAGS = -g -Wall -fPIC
LDFLAGS = -shared

TARGET_LIB = libtoy.so
SRCS = toy.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET_LIB)