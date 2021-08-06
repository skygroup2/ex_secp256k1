CFLAGS = -g -O3 -Wall -Wno-format-truncation
CXXFLAGS = --std=c++17 -g -O3 -Wall -Wno-format-truncation

ERLANG_PATH = $(shell erl -eval 'io:format("~s", [lists:concat([code:root_dir(), "/erts-", erlang:system_info(version), "/include"])])' -s init stop -noshell)
CFLAGS += -I"$(ERLANG_PATH)" -Ic_src -Ideps/secp256k1/include -fPIC
CXXFLAGS += -I"$(ERLANG_PATH)" -Ic_src -Ideps/secp256k1/include -fPIC
#LDFLAGS += --whole-file

LIB_NAME = priv/secp256k1_nif.so

NIF_SRC = c_src/secp256k1_nif.c

LIB_EXT = deps/secp256k1/.libs/libsecp256k1.a

all: $(LIB_NAME)

$(LIB_NAME): $(NIF_SRC) $(LIB_EXT)
	mkdir -p priv
	$(CC) $(CFLAGS) -shared $^ $(LDFLAGS) -o $@

$(LIB_EXT):
	if [ ! -d "deps" ]; then mkdir deps; fi
	cd deps; if [ ! -d "secp256k1" ]; then git clone https://github.com/bitcoin-core/secp256k1.git; fi
	cd deps/secp256k1 ; ./autogen.sh ; CFLAGS="-fPIC" ./configure --enable-module-ecdh --enable-module-recovery; make

clean:
	rm -f $(LIB_NAME)
	cd  deps/secp256k1 ; make clean

.PHONY: all clean