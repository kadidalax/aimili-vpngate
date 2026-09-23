# AimiliVPN v2.2.0 VPS 验收报告（2026-09-23）

依据：`docs/superpowers/specs/2026-09-23-exit-takeover-and-speedtest-design.md` 第 14 章。

## 环境

| 项目 | 值 |
| --- | --- |
| 系统 | Debian 12 (bookworm)，arm64，内核 6.1.0-50 |
| sing-box | 1.15.0-alpha.3（fscarmen 脚本，`/etc/sing-box`，Clash API 127.0.0.1:9414） |
| OpenVPN | 2.6.14 |
| Python | 3.11.2 |
| 部署方式 | `git archive` 同步到 `/opt/aimilivpn`，systemd 单元与 install.sh 一致 |

VPS 原先未安装 AimiliVPN，验收前按 install.sh 的依赖列表安装了 openvpn、python3 等软件包。sing-box 客户端侧测试在 VPS 本机另起一个 sing-box 客户端实例，经 127.0.0.1 连接 VLESS Reality（8881）与 Hysteria2（8882）入站，模拟外部客户端。

## 验收中发现并修复的问题

1. **sing-box 接管配置被 1.15 拒绝。** 只在出站写 `domain_resolver` 时 `sing-box check` 报 "missing `route.default_domain_resolver`" 并 FATAL 退出，字符串写法同样失败。修复：`render_config()` 增加 `route.default_domain_resolver`，spec 4.1 同步更新。修复后 `sing-box check` 通过。
2. **规则拆除顺序可能掐断现有 SSH 会话。** 原实现按 pref 升序删除，豁免规则先于 `lookup 100` 兜底规则消失，其间已建立连接的回包会被送进隧道。修复：`delete_all_prefs()` 改为从 30039 倒序删除，先删兜底规则。
3. **退出清理的防御加固。** 一次 `systemctl stop` 后观察到 11 条规则残留（之后 7 次复测均未复现）。加固两处：`existing_prefs()` 读取 `ip rule show` 失败时重试一次；退出钩子在规则存在或配置开关为开时都执行拆除，并在日志里写明判断依据。

以上修复均带单元测试，本地 146 个用例全部通过，并已重新部署后完成下列验收。

## 验收结果

### 1. 基线：通过

- `aimilivpn` 与 `sing-box` 均为 active，面板可登录，隧道自动连接。
- `curl -x socks5h://127.0.0.1:7928 https://api.ipify.org` 返回节点 IP 219.104.137.60，VPS 直连返回 168.110.24.176。

### 2. sing-box 接管：通过

- 开关打开后 `/etc/sing-box/conf/90_aimili_vpngate.json` 存在，`sing-box check -C /etc/sing-box/conf` 通过，sing-box 保持 active（reload 而非重启）。
- 经 Reality 与 Hysteria2 两种入站访问 `https://api.ipify.org` 都得到节点 IP。
- 下载进行中调用"验证"，Clash API 显示 1 条连接、1 条经隧道，出站链为 `aimili-vpngate`。空闲时返回 0 条属正常。
- 面板"断开连接"后客户端请求失败（curl 退出码 97），没有回落到 VPS IP。重新连接后恢复节点 IP。
- 开关关闭后文件消失，客户端得到 VPS IP 168.110.24.176。重新打开后文件恢复。

### 3. 待确认点：全部确认

| 待确认点 | 结论 |
| --- | --- |
| `bind_interface` 指向不存在的 `tun0` 时 `sing-box check` | 通过 |
| `domain_resolver` 对象写法与 `dns.final` | 接受，但必须同时设置 `route.default_domain_resolver`，见问题 1 |
| `ip rule add sport` | 可用，面板状态显示 `sport_supported: true` |
| `openvpn --mark` | 可用 |

### 4. 全局出口：通过

- 打开后 `ip rule show` 含 30000、30001、30010、30011、30020 到 30024、30030、30031 共 11 条规则，`ip route show table 100` 含 `default dev tun0` 与 `unreachable default metric 1000`。
- VPS 上 `curl -4 https://api.ipify.org` 返回节点 IP。IPv6 按设计不接管，仍走原生地址。
- 新开 SSH 连接正常，外部访问面板返回 200。
- sing-box 客户端得到节点 IP。
- `ip route get 10.0.0.1` 走 enp0s6，`ip route get 1.1.1.1` 走 tun0 表 100，ping 网关正常。
- 强杀 openvpn 后 VPS 上 curl 在 0.2 秒内失败，表 100 只剩 unreachable 兜底，SSH 不受影响。约 24 秒后自动换节点恢复。
- 面板"断开连接"会先关闭全局开关再断隧道，规则清零、直连恢复，符合 spec 第 9 节。
- `systemctl stop aimilivpn` 后规则清零、直连恢复。`systemctl start` 后规则重现并经隧道出站。修复后连续 4 轮 stop/start 均正确，期间同一条 SSH 会话持续保持。
- `python3 vpngate_manager.py --global-exit off` 退出码 0，规则清零，sing-box 接管按设计自动恢复。

### 5. 管线：通过

- 周期改为 1 小时后 `next_check_at` 从上次开始时间加 24 小时变为加 1 小时，没有立即触发。设为 0 返回 400 "节点检测周期必须是 1 至 72 之间的整数小时"。
- "更新节点"按 fetch、probe 线性执行，结束后全部节点为 available 或 unavailable，没有 testing 或 not_checked。运行中再点"开始测速"返回 409 "任务进行中，请稍后再试"。
- 国家选韩国时预估为 24 个节点、240 MB、约 514 秒。测速按 fetch、probe、speedtest 顺序推进，当前节点排第一个，进度字段逐个递增。
- 测速中点"停止任务"，0.7 秒后结束，`stopped_reason` 为 manual，当前节点不变。
- 阈值设为 1 Mbps 时测完第一个达标节点即停止，`stopped_reason` 为 threshold。
- 打开自动切换、余量 20% 时测完 23 个节点，当前节点 8.9 Mbps，最快节点 15.4 Mbps，进入 switch 阶段并切换，出口 IP 变为 121.134.136.164。
- 每轮测速结束后只剩 `tun0` 与项目原有的 `oif tun0 lookup 100` 规则，表 101 到 130 为空，只有 1 个 openvpn 进程。

面板上的进度面板与实测速度列由 `/api/nodes` 返回的 `state.pipeline` 与节点 `speed_mbps` 渲染，验收以接口数据核对，未做浏览器截图。

### 6. 收尾

验收结束后已停止并移除 AimiliVPN 服务与 `/opt/aimilivpn`，删除接管配置并 reload sing-box，卸载为验收安装的软件包，删除临时文件与专用公钥，VPS 恢复到验收前状态。
