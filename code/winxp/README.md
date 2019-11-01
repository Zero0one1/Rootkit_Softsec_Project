# Win XP Rootkit

本 Rootkit 仅适用于 Windows XP 平台，参考书本《Rootkit —— Windows 内核的安全防护》

## 功能简介

主要通过 Loader 用户态应用程序启动，启动后会加载同目录下的 system_root.sys 驱动程序，通过该驱动程序来隐藏自身进程、对外端口的连接以及注册表内容，之后 Loader 进程对注册表进行修改，从而实现关机后自启。

此外，本 Rootkit 需要一个攻击机配合。Loader 进程在加载完成之后会向攻击机发送一条就绪消息，之后等待接收攻击机的命令。攻击机可以发送以下 4 个命令来控制 Loader 进程：

* r: 读受害机一条时间
* w [content]: 写内容到受害机 C 盘下
* p [s]: Loader 进程休眠数秒
* q: 退出 Loader 进程
