# ProxyDirector — 本地多代理自动测速择优器

常驻后台工具：定时测试多个本地代理客户端（各类机场/代理软件）的连通与延迟，
按迟滞规则自动把 Windows 系统代理切换到最优端口。

## ⚠ 使用前提（必读）

1. **关闭各代理客户端里的"系统代理"开关** —— 系统代理由本工具独占管理，
   两边同时开只会互相覆盖。
2. 两个代理客户端本身保持运行并连接节点（本工具只做选择，不启动它们的内核）。
3. 首次运行 `ProxyDirector.exe` 可能触发 SmartScreen 提示（自编译无签名 exe），点"仍要运行"。

## 快速开始

1. 双击 `dist\ProxyDirector.exe`
2. 首次使用点 **添加代理**：输入代理客户端的核心进程名（通常为客户端名 + Core）→ 扫描端口 →
   勾选识别为 HTTP/SOCKS5 的端口 → 添加。
3. 引擎每 60 秒测速一轮；发现更优链路（快 25% 以上且停留满 5 分钟）自动切换系统代理。
4. 关闭窗口 = 最小化到托盘；**退出请用托盘图标右键 → 退出**（会写 stop.flag，
   看门狗不再拉起）。

## 看门狗自恢复（推荐安装）

双击 `install-watchdog.cmd`（无需管理员）：
- 注册计划任务，每分钟检查一次，进程不在则自动拉起（用户主动退出除外）
- 通过 `watchdog-silent.vbs`（wscript）静默运行，**不会弹出任何窗口**
- 同时注册开机自启

卸载：双击 `uninstall-watchdog.cmd`

## 决策规则

- 周期：默认 60 秒（界面可调 15-3600 秒）
- 切换条件：候选链路比当前快 ≥ 25%（可调）且距上次切换 ≥ 5 分钟（可调）
- 当前链路连续 2 轮测速失败 → 立即切换到可用的最快链路
- 所有链路全部失联 → 不动作，仅告警（避免乱指向）
- 冲突检测：若系统代理被外部程序改写（机场客户端的开关被打开），状态栏显示 ⚠ 提醒

## 端口识别原理（两阶段）

1. **身份识别**（零外网流量）：进程名 → netstat 找监听端口 → 对每个端口发
   HTTP CONNECT / SOCKS5 握手，能回应代理协议的才是代理端口（内部通信口如
   助手进程的 47890、DNS 口 1053 会被正确排除）
2. **链路测速**：经代理端口请求目标池（gstatic / msftconnecttest / captive.apple），
   首个成功者计时

## 命令行自检

```
dist\ProxyDirector.exe --console scan <进程名>      # 扫描某进程的代理端口
dist\ProxyDirector.exe --console speed              # 按 config 测一轮速
dist\ProxyDirector.exe --console decide             # 测速 + 决策 dry-run（不写注册表）
```
结果同时写入 `dist\console-out.txt`（winexe 程序控制台输出受限，读文件为准）。

## 编译

```
build.cmd     # 调用 Windows 自带 .NET Framework 4.8 csc，无需安装任何 SDK
```

## 目录

```
src\ProxyDirector.cs     源码（单文件，C# 5 语法）
build.cmd                编译脚本
watchdog.cmd             看门狗检查脚本（由计划任务每分钟调用）
watchdog-silent.vbs      静默启动层（wscript 无窗口运行 watchdog.cmd）
install-watchdog.cmd     注册看门狗 + 开机自启
uninstall-watchdog.cmd   卸载看门狗 + 自启
dist\ProxyDirector.exe   编译产物
dist\config.json         配置（首次运行自动生成）
dist\proxy.log           运行日志（自动轮转）
runtime\stop.flag        退出标志（存在时看门狗不拉起）
```

## 已知限制

- 切换瞬间已建立的长连接会断（视频可能卡一下），这是"改系统代理"方案的固有代价
- 测速为周期采样，周期间发生的故障最迟下一轮发现
- 私有协议（非 HTTP/SOCKS）的代理端口无法自动识别，请在添加向导中手动确认
