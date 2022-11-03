HEADERS_DIR = headers/

LIBBPF_DIR ?= libbpf/src/
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

OBJECT_UTILS = bfp-xdp.o config.o
UTILS_DIR = common/

SRC = src/
LOADER = xb-loader.c
LOADER_NAME = xb-loader
STATS = xb-stats.c
STATS_NAME = xb-stats

XDPPROG = xdp_prog.c
XDPPROG_INT = xdp_prog.ll
XDPPROG_NAME = xdp_prog.o

CC ?= clang

all: $(OBJECT_LIBBPF) obj_utils load-tool stats xdp-prog



load-tool: $(OBJECT_LIBBPF) obj_utils
	mkdir -p build
	cd $(SRC) && \
	$(CC) -Wall -lconfig -lz -I../$(HEADERS_DIR) -L../$(LIBBPF_DIR) -o ../build/$(LOADER_NAME) ../$(UTILS_DIR)/config.o ../$(UTILS_DIR)/bfp-xdp.o $(LOADER) -l:libbpf.a -lelf -lconfig 
	cp $(SRC)/xdp.conf build/
	
stats: $(OBJECT_LIBBPF) obj_utils
	mkdir -p build
	cd $(SRC) && \
	$(CC) -Wall -lconfig -lz -I../$(HEADERS_DIR) -L../$(LIBBPF_DIR) -o ../build/$(STATS_NAME) ../$(UTILS_DIR)/config.o ../$(UTILS_DIR)/bfp-xdp.o $(STATS) -l:libbpf.a -lelf -lconfig \
		
xdp-prog: $(OBJECT_LIBBPF)
	mkdir -p build
	cd $(SRC) && \
	clang -S -target bpf -D __BPF_TRACING__  -I../$(LIBBPF_DIR)/build/usr/include/ -I../$(HEADERS_DIR) -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o $(XDPPROG_INT) $(XDPPROG) && \
	llc -march=bpf -filetype=obj -o ../build/$(XDPPROG_NAME) $(XDPPROG_INT) \

obj_utils: $(OBJECT_LIBBPF)
	cd $(UTILS_DIR) && \
	gcc -g -Wall -I../$(LIBBPF_DIR)/build/usr/include/  -I../$(HEADERS_DIR) -c -o config.o config.c -lconfig && \
	gcc -g -Wall -I../$(LIBBPF_DIR)/build/usr/include/  -I../$(HEADERS_DIR) -c -o bfp-xdp.o bfp-xdp.c \
	
$(OBJECT_LIBBPF):
	cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
	mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \

clean:
	rm -rf $(LIBBPF_DIR)/build
	make -C $(LIBBPF_DIR)/ clean

	cd $(LIBBPF_DIR) && \
	rm -rf *.o *.a *.so *.so.* *.pc ./sharedobjs ./staticobjs \

	cd $(UTILS_DIR) && rm -f *.o

	cd $(SRC) && \
	rm -f $(XDPPROG_NAME) $(LOADER_NAME) $(STATS_NAME) && \
	rm -f *.ll
	rm -rf build/



