#include <linux/device.h> 
#include <linux/init.h> 
#include <linux/module.h> 
#include <linux/types.h> 
#include <linux/version.h> 

#include <linux/fs.h>        // for file_operations and file struct
#include <linux/uaccess.h>   // for copy_to_user()
#include <linux/kernel.h>    // for pr_alert(), snprintf(), etc.
#include <linux/utsname.h>   // for utsname (to get kernel name and hostname)
#include <linux/sysinfo.h>   // for sysinfo and memory info
#include <linux/mm.h>
#include <linux/cpu.h>       // for CPU info
#include <linux/sched.h>     // for nr_threads (number of processes/threads)
#include <linux/time.h>      // for ktime_get_boottime_ts64() (uptime)
#include <linux/slab.h>      // for kmalloc() and kfree()
#include <linux/string.h>    // for strlen(), memset(), memcpy()
#include <linux/mutex.h>     // for mutex locking
#include <linux/sched/signal.h>

static int kfetch_open(struct inode *, struct file *); 
static int kfetch_release(struct inode *, struct file *); 
static ssize_t kfetch_read(struct file *, char __user *, size_t, loff_t *); 
static ssize_t kfetch_write(struct file *, const char __user *, size_t, 
                            loff_t *); 

#define DEVICE_NAME "kfetch"
#define INFO_LEN 64 
#define BUF_LEN 1024

#define KFETCH_NUM_INFO 6
#define KFETCH_RELEASE   (1 << 0)
#define KFETCH_NUM_CPUS  (1 << 1)
#define KFETCH_CPU_MODEL (1 << 2)
#define KFETCH_MEM       (1 << 3)
#define KFETCH_UPTIME    (1 << 4)
#define KFETCH_NUM_PROCS (1 << 5)
#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

static int KFETCH_MASK = KFETCH_FULL_INFO;

static const char *logo[8] = {
    "                      ",
    "         .-.          ",
    "        (.. |         ",
    "       \033[1;33m <> \033[1;0m |         ",
    "       / --- \\        ",
    "      ( |   | |       ",
    "    \033[1;33m|\\\033[1;0m\\_)___/\\)\033[1;33m/\\ \033[1;0m    ",
    "   \033[1;33m<__)\033[1;0m------\033[1;33m(__/\033[1;0m     ",
};

static int major;
static struct class *cls; 
static DEFINE_MUTEX(mask_lock);

const static struct file_operations kfetch_ops = {
    .owner   = THIS_MODULE,
    .read    = kfetch_read,
    .write   = kfetch_write,
    .open    = kfetch_open,
    .release = kfetch_release,
};

static ssize_t kfetch_read(struct file *filp, 
                           char __user *buffer, 
                           size_t length, 
                           loff_t *offset)
{

    char info_list[8][INFO_LEN];
    bool contain_info[8] = {true, true, false, false, false, false, false, false};
    char buf[INFO_LEN];
    
    // hostname
    snprintf(buf, sizeof(buf), "%s", utsname()->nodename);
    strcpy(info_list[0], buf);
    
    // Separator
    size_t separator_length = strlen(buf);
    char *separator = kmalloc(separator_length + 1, GFP_KERNEL);
    if (!separator) {
        return -ENOMEM;
    }
    memset(separator, '-', separator_length);
    separator[separator_length] = '\0';
    strcpy(info_list[1], separator);

    mutex_lock(&mask_lock);
    int mask_snapshot = KFETCH_MASK;
    mutex_unlock(&mask_lock);

    // Kernel
    if(mask_snapshot & KFETCH_RELEASE){
        contain_info[2] = true;
        snprintf(buf, sizeof(buf), "Kernel: %s", utsname()->release);
        strcpy(info_list[2], buf);
    }
    // CPU
    if(mask_snapshot & KFETCH_CPU_MODEL){
        struct cpuinfo_x86 *c = &cpu_data(0); 
        contain_info[3] = true;
        snprintf(buf, sizeof(buf), "CPU: %s", c->x86_model_id);
        strcpy(info_list[3], buf);
    }
    // CPUs
    if(mask_snapshot & KFETCH_NUM_CPUS){
        unsigned int online_cpus = num_online_cpus();
        unsigned int total_cpus = num_present_cpus();
        contain_info[4] = true;
        snprintf(buf, sizeof(buf), "CPUs: %d / %d", online_cpus, total_cpus);
        strcpy(info_list[4], buf);
    }
    // Mem
    if(mask_snapshot & KFETCH_MEM){
        struct sysinfo si;
        si_meminfo(&si);
        unsigned long total_mem_mb = (si.totalram * si.mem_unit) >> 20;
        unsigned long free_mem_mb = (si.freeram * si.mem_unit) >> 20;
        contain_info[5] = true;
        snprintf(buf, sizeof(buf), "Mem: %ld MB / %ld MB", free_mem_mb, total_mem_mb);
        strcpy(info_list[5], buf);
    }
    // Procs
    if(mask_snapshot & KFETCH_NUM_PROCS){ 
        struct task_struct *task;
        unsigned int count = 0;
        for_each_process(task){
            if(task->tgid == task->pid){
                count++;
            }
        }
        contain_info[6] = true;
        snprintf(buf, sizeof(buf), "Procs: %d", count);
        strcpy(info_list[6], buf);
    }
    // Uptime
    if (mask_snapshot & KFETCH_UPTIME) { 
        struct timespec64 uptime;
        ktime_get_boottime_ts64(&uptime);
        unsigned long uptime_minutes = (uptime.tv_sec / 60);
        contain_info[7] = true;
        snprintf(buf, sizeof(buf), "Uptime: %ld mins", uptime_minutes);
        strcpy(info_list[7], buf);
    }

    // Create a buffer for the output
    char *kfetch_buf = kmalloc(BUF_LEN, GFP_KERNEL);
    if (!kfetch_buf) {
        kfree(separator);
        return -ENOMEM;
    }

    int j = 0;
    size_t offset_buf = 0;
    for (int i = 0; i < 8; i++) {
        offset_buf += snprintf(kfetch_buf + offset_buf, BUF_LEN - offset_buf, "%s", logo[i]);
        while (j < 8) {
            if (contain_info[j]) {
                offset_buf += snprintf(kfetch_buf + offset_buf, BUF_LEN - offset_buf, "%s", info_list[j]);
                j++;
                break;
            }
            j++;
        }
        offset_buf += snprintf(kfetch_buf + offset_buf, BUF_LEN - offset_buf, "\n");
    }

    ssize_t kfetch_buf_size = offset_buf;

    if (copy_to_user(buffer, kfetch_buf, kfetch_buf_size)) {
        kfree(kfetch_buf);
        kfree(separator);
        return -EFAULT;
    }
    kfree(kfetch_buf);
    kfree(separator);

    return kfetch_buf_size; 
}


static ssize_t kfetch_write(struct file *filp,
                            const char __user *buffer,
                            size_t length,
                            loff_t *offset)
{
    int mask_info;
    if (copy_from_user(&mask_info, buffer, length)) {
        pr_alert("Failed to copy data from user");
        return -EFAULT;
    }

    mutex_lock(&mask_lock);
    KFETCH_MASK = mask_info;
    mutex_unlock(&mask_lock);
    return length;
}

static int kfetch_open(struct inode *inode, struct file *filp)
{
    pr_info("kfetch device opened\n");
    return 0;
}

static int kfetch_release(struct inode *inode, struct file *filp)
{
    pr_info("kfetch device closed\n");
    return 0;
}


static int __init kfetch_init(void)
{ 
    major = register_chrdev(0, DEVICE_NAME, &kfetch_ops); 
 
    if (major < 0) { 
        pr_alert("Registering kfetch failed with %d\n", major); 
        return major; 
    } 
    
    pr_info("kfetch was assigned major number %d.\n", major); 
 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0) 
    cls = class_create(DEVICE_NAME); 
#else 
    cls = class_create(THIS_MODULE, DEVICE_NAME); 
#endif 
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME); 
    pr_info("Device created on /dev/%s\n", DEVICE_NAME); 
    return 0;
} 
 
static void __exit kfetch_exit(void)
{ 
    device_destroy(cls, MKDEV(major, 0)); 
    class_destroy(cls); 
    unregister_chrdev(major, DEVICE_NAME); 
}
 
module_init(kfetch_init); 
module_exit(kfetch_exit); 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("kfetch-313551026");