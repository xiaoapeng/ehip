# EHIP

EHIP 是 [FLY](https://github.com/xiaoapeng/fly) 生态中的网络协议栈组件，提供从二层到四层的基础网络能力，支持以太网设备管理与 IPv4 协议处理。

## 功能概览

- IPv4 基础能力：收发、路由、分片重组、错误处理。
- 传输层支持：UDP、TCP。
- 常见网络协议：ARP、ICMP（含 ping）、DNS。
- 网络设备抽象：loopback、ethernet、tun 设备类。
- 与 `eventhub` / `eventhub-components` 事件机制协作运行。

## 目录结构

- `src/`：协议栈实现代码。
- `src/ehip-ipv4/`：IPv4、ARP、ICMP、UDP、TCP、路由等。
- `src/ehip-mac/`：MAC / 以太网相关实现。
- `src/ehip-netdev/`、`src/ehip-netdev-class/`：网络设备与设备类型实现。
- `src/ehip-protocol/`：上层协议（如 DNS）。
- `src/include/`：对外头文件（按模块分目录）。
- `CMakeLists.txt`：构建脚本，产出 `ehip` 对象库。

## 构建方式

本仓库通常作为 FLY 工程的子包使用。单独做编译检查可执行：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --target ehip -j
```

> 说明：该仓库本身不提供独立可执行程序，运行验证通常在上层工程中进行。

## 配置说明

默认配置位于 `src/include/ehip_conf.h`，可按场景调整：

- 内存池大小与数量（影响内存占用与吞吐能力）
- 协议项上限（如 ARP 缓存、DNS 表项、IP 分片数量）
- 超时参数（如 TX 看门狗、ARP 超时）

建议在修改配置后，结合目标硬件内存与网络负载进行联调测试。

## 开发建议

- 保持 API 与头文件同步：修改 `src/` 实现时同步更新 `src/include/`。
- 提交尽量小步、单一职责，便于回溯与评审。
- 优先在父工程中完成 ping、DNS、TCP/UDP 连通性回归验证。
