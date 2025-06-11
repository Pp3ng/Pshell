CC = gcc
CFLAGS = -Wall -Wextra -O2 -pedantic
LDFLAGS = 
TARGET = pshell
SRC = pshell.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) .ps*
