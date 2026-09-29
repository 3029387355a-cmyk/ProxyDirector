# ProxyDirector — 本地多代理自动测速择优器

常驻后台工具：定时测试多个本地代理客户端（各类代理客户端）的连通与延迟，
按迟滞规则自动把 Windows 系统代理切换到最优端口。

> 文档将在交付时补全（使用前提、安装看门狗、卸载方法）。

## 特性
- 按进程名自动发现并识别代理端口（HTTP CONNECT / SOCKS5 双协议握手，零外网流量）
- 周期端到端测速（gstatic / msftconnecttest / captive.apple 目标池）
- 迟滞决策：快 25% 以上且停留满 5 分钟才切换；全部失联时不动作只告警
- 可视化界面 + 托盘常驻；看门狗每分钟自愈拉起
- 零第三方依赖：源码由系统自带 .NET Framework 4.8 编译器（csc）构建

## 目录
```
src\ProxyDirector.cs    源码（单文件，C# 5 语法）
build.cmd               编译脚本
watchdog.cmd            看门狗检查脚本（由计划任务每分钟调用）
install-watchdog.cmd    注册看门狗计划任务 + 开机自启
uninstall-watchdog.cmd  卸载看门狗与自启
dist\ProxyDirector.exe  编译产物
config.json             配置（首次运行自动生成）
runtime\                运行时目录（stop.flag 等）
```
