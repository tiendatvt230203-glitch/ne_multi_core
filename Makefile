CC     = gcc
CLANG  = clang

CFLAGS = -D_GNU_SOURCE -I. -Iinc/core -Iinc/crypto -Iinc/db -I./include -Wall -O2 $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})
LDFLAGS = -L./lib -Wl,-rpath,'$$ORIGIN/../lib' -Wl,-Bstatic -lxdp -lbpf -Wl,-Bdynamic -lelf -lz -lpthread -lssl -lcrypto -lpq -lscrypt

BPF_CFLAGS     = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

BIN_DIR = bin
TARGET  = $(BIN_DIR)/network-encryptor

APP_SRC = main.c \
          src/core/main_diag.c \
          src/core/interface.c \
          src/core/forwarder.c \
          src/core/bridge_mac.c \
          src/crypto/crypto_policy_utils.c \
          src/crypto/crypto_dispatch.c \
          src/crypto/packet_crypto.c \
          src/crypto/traffic_crypto.c \
          src/crypto/crypto_layer2.c \
          src/crypto/crypto_layer3.c \
          src/crypto/crypto_layer4.c \
          src/crypto/pqc_handshake.c \
          src/crypto/pqc_l2_handshake.c \
          src/core/flow_table.c \
          src/core/fragment.c
APP_OBJ = $(APP_SRC:.c=.o)

DB_SRC = src/db/config.c \
         src/db/db_config.c \
         src/db/db_env.c \
         src/db/db_runtime.c
DB_OBJ = $(DB_SRC:.c=.o)

BPF_SRC = bpf/xdp_redirect.c \
          bpf/xdp_wan_redirect.c
BPF_OBJ = bpf/xdp_redirect.o \
          bpf/xdp_wan_redirect.o

.PHONY: all clean dirs

all: dirs $(BPF_OBJ) $(TARGET)

dirs:
	@mkdir -p $(BIN_DIR)

$(TARGET): $(APP_OBJ) $(DB_OBJ)
	$(CC) -o $@ $(APP_OBJ) $(DB_OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I./include -c $< -o $@

clean:
	rm -rf $(BIN_DIR) src/*.o src/core/*.o src/crypto/*.o src/db/*.o *.o $(BPF_OBJ)