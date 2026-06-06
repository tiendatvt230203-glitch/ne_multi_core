CC       = gcc
CLANG    = clang
OBJCOPY  = objcopy

CFLAGS = -D_GNU_SOURCE -I. -Iinc -Iinc/core -Iinc/crypto -Iinc/db -Iinc/policy -Iinc/br_wire -Iinc/pipeline -Iinc/routing -Iinc/runtime -Iinc/io -I./include -Wall -O2 $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})
LDFLAGS = -L./lib -Wl,-rpath,'$$ORIGIN/../lib' -lxdp -lbpf -lelf -lz -lpthread -lssl -lcrypto -lpq -lscrypt

BPF_CFLAGS     = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  EMBED_BFD = elf64-x86-64
  EMBED_ARCH = i386
else ifeq ($(UNAME_M),aarch64)
  EMBED_BFD = elf64-littleaarch64
  EMBED_ARCH = aarch64
else
  EMBED_BFD = elf64-x86-64
  EMBED_ARCH = i386
endif

BIN_DIR = bin
TARGET  = $(BIN_DIR)/network-encryptor

APP_SRC = main.c \
          src/core/main_diag.c \
          src/io/interface_io.c \
          src/io/interface_setup.c \
          src/core/forwarder.c \
          src/core/forwarder_setup.c \
          src/runtime/reload.c \
          src/crypto/runtime.c \
          src/core/dataplane_util.c \
          src/pipeline/egress.c \
          src/pipeline/ingress.c \
          src/br_wire/br_wire.c \
          src/policy/policy_match.c \
          src/policy/policy_select.c \
          src/policy/policy_resolve.c \
          src/policy/policy_expand.c \
          src/core/ne_pqc_bridge.c \
          src/crypto/crypto_policy_utils.c \
          src/crypto/crypto_dispatch.c \
          src/crypto/packet_crypto.c \
          src/crypto/traffic_crypto.c \
          src/crypto/crypto_layer2.c \
          src/crypto/crypto_layer3.c \
          src/crypto/crypto_layer4.c \
          src/crypto/pqc_handshake.c \
          src/crypto/pqc_l2_handshake.c \
          src/routing/flow_table.c \
          src/routing/wan_pick.c \
          src/crypto/fragment.c
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

EMBED_DIR = bpf_embed
BPF_EMBED_OBJ = $(EMBED_DIR)/xdp_redirect_embed.o \
                $(EMBED_DIR)/xdp_wan_redirect_embed.o

.PHONY: all clean dirs

all: dirs $(BPF_OBJ) $(BPF_EMBED_OBJ) $(TARGET)

dirs:
	@mkdir -p $(BIN_DIR) $(EMBED_DIR)

$(TARGET): $(APP_OBJ) $(DB_OBJ) $(BPF_EMBED_OBJ)
	$(CC) -o $@ $(APP_OBJ) $(DB_OBJ) $(BPF_EMBED_OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I./include -c $< -o $@

# objcopy symbol names follow the *input* basename: _binary_xdp_redirect_o_start, etc.
$(EMBED_DIR)/xdp_redirect_embed.o: bpf/xdp_redirect.o | dirs
	@cp $< $(EMBED_DIR)/xdp_redirect.o
	@cd $(EMBED_DIR) && $(OBJCOPY) -I binary -O $(EMBED_BFD) -B $(EMBED_ARCH) \
		--rename-section .data=.rodata,alloc,load,readonly,data,contents \
		xdp_redirect.o xdp_redirect_embed.o && rm -f xdp_redirect.o

$(EMBED_DIR)/xdp_wan_redirect_embed.o: bpf/xdp_wan_redirect.o | dirs
	@cp $< $(EMBED_DIR)/xdp_wan_redirect.o
	@cd $(EMBED_DIR) && $(OBJCOPY) -I binary -O $(EMBED_BFD) -B $(EMBED_ARCH) \
		--rename-section .data=.rodata,alloc,load,readonly,data,contents \
		xdp_wan_redirect.o xdp_wan_redirect_embed.o && rm -f xdp_wan_redirect.o

clean:
	rm -rf $(BIN_DIR) src/*.o src/core/*.o src/crypto/*.o src/db/*.o src/policy/*.o src/br_wire/*.o src/io/*.o src/pipeline/*.o src/routing/*.o src/runtime/*.o *.o $(BPF_OBJ) $(BPF_EMBED_OBJ)
