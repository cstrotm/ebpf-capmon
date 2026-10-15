all: ebpf-capmon

# vmlinux.h is generated from the running kernel's BTF (CO-RE: it need not
# match the kernel the monitor later runs on).
bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

capmon_x86_bpfel.go: bpf/capmon.bpf.c bpf/capmon.h bpf/vmlinux.h
	go generate ./...

ebpf-capmon: capmon_x86_bpfel.go main.go caps.go go.mod
	go build -o $@ .

test:
	go test ./...

install: ebpf-capmon
	install -m 0755 ebpf-capmon /usr/local/sbin/ebpf-capmon

clean:
	rm -f ebpf-capmon capmon_x86_bpfel.go capmon_x86_bpfel.o

.PHONY: all test install clean
