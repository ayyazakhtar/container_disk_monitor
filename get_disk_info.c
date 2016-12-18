/*
 * This file contains the BPF code that is used to count the cpu time 
 * of all the PIDs 
 * */
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

#include <linux/nsproxy.h>
#include <linux/ns_common.h>

enum disk_type {
    VFS_READ = 1,
    VFS_WRITE
};
typedef struct disk_key {
    u32 process_id;
    u32 disk_type;
} disk_key_t;

typedef struct counter {
    u64 bytes;
    u64 count;
} counter_t;


#define CONTAINER_PID CONTAINER_PARENT_PID
BPF_HASH(disk_map, disk_key_t, counter_t);

static int check_parent(struct task_struct *cur_struct)
{
    u32 pid =0;
    struct task_struct *parent ;
    bpf_probe_read(&parent, sizeof(struct task_struct *), &cur_struct);

    for(int i=0; i<9; i++)
    {
        bpf_probe_read(&pid, sizeof(pid), &(parent->pid));
        if(pid ==1)
            return 1;
        if(pid == CONTAINER_PID)
            return 0;
        //parent = parent->real_parent;
        bpf_probe_read(&parent, sizeof(struct task_struct *), &(parent->real_parent));
    }
    return 1;
}

static int vfs_func(struct pt_regs *ctx, struct file *file,
        char __user *buf, size_t count, u32 disk_type)
{
    struct task_struct *cur_struct;
    cur_struct = (struct task_struct *)bpf_get_current_task();

    if(check_parent(cur_struct) != 0)
        return 0;

    disk_key_t key;
    key.process_id = bpf_get_current_pid_tgid();
    key.disk_type = disk_type;
    counter_t *value_ptr, value;
    value.bytes = 0;
    value.count = 0;

    struct dentry *de = file->f_path.dentry;
    if (de->d_iname[0] == 0)
        return 0;

    value_ptr = disk_map.lookup_or_init(&key, &value);
    value_ptr->bytes += count;
    value_ptr->count++;
    return 0;
}

int vfs_read_func(struct pt_regs *ctx, struct file *file,
        char __user *buf, size_t count)
{
    return vfs_func(ctx, file, buf, count, VFS_READ);
}

int vfs_write_func(struct pt_regs *ctx, struct file *file,
        char __user *buf, size_t count)
{
    return vfs_func(ctx, file, buf, count, VFS_WRITE);
}

