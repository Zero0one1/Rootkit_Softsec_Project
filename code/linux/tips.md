Q: win上传文件会自动修改换行方式为当前系统

A: 可以修改git全局配置，禁止git自动将lf转换成crlf,  命令：

​	git config --global core.autocrlf false