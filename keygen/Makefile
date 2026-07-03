CC      = gcc
CC_ARM  = aarch64-linux-gnu-gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lsodium
BUILD  ?= .

TARGET      = $(BUILD)/keygen
TARGET_ARM  = $(BUILD)/keygen-arm64

$(TARGET): keygen.c
	$(CC) $(CFLAGS) -o $@ keygen.c $(LDFLAGS)

arm64: keygen.c
	$(CC_ARM) $(CFLAGS) -o $(TARGET_ARM) keygen.c $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET_ARM)

.PHONY: clean arm64
