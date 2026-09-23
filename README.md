<div align="center">

# AimiliVPN

**面向 Linux VPS 的 VPNGate 节点管理与 HTTP / HTTPS / SOCKS5 代理网关**

[![正式版本](https://img.shields.io/github/v/release/kadidalax/aimili-vpngate?style=flat-square&label=正式版&color=16a34a)](https://github.com/kadidalax/aimili-vpngate/releases/latest)
[![Docker](https://img.shields.io/badge/Docker-amd64%20%7C%20386%20%7C%20arm64%20%7C%20armv7-0ea5e9?style=flat-square&logo=docker&logoColor=white)](https://github.com/kadidalax/aimili-vpngate/pkgs/container/aimili-vpngate)
[![License](https://img.shields.io/badge/License-GPL--3.0-334155?style=flat-square)](LICENSE)

**简体中文** · [English](docs/README.en.md) · [日本語](docs/README.ja.md) · [한국어](docs/README.ko.md)

[快速安装](#quick-install) · [完整安装](#installation) · [连接使用](#connection) · [服务商推荐](#vps) · [社区入口](#community) · [法律声明](#legal)

[![项目网站](https://img.shields.io/badge/项目网站-339936.xyz-f97316?style=for-the-badge)](https://339936.xyz)
[![Telegram](https://img.shields.io/badge/Telegram-交流群-229ED9?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/arestemple)
[![YouTube](https://img.shields.io/badge/YouTube-视频教程-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://www.youtube.com/watch?v=s-ATfXR8BpI)

</div>

<a id="vps"></a>

## 服务商推荐

| 商家 | 推荐理由 | 入口 |
| --- | --- | --- |
| **Bandwagon** |代理 & 建站推荐：CN2/9929/CMI三网直连 2500 Mbps 高速线路；低延迟、高稳定性，适合直播、带货和长期出海业务。 | [立即查看](https://bandwagonhost.com/aff.php?aff=81790) |
| **RackNerd** | 综合服务器推荐：4000GB 大流量，价格与配置性价比突出；部署成本低，适合需要长期稳定运行的服务。 | [立即查看](https://my.racknerd.com/aff.php?aff=18708) |
| **OpenMili** | OpenMili Ai 中转站推荐：GPT-6 Astra & Images 2.0 Pro 美区原价 0.12倍率 不掺假、不降智，接受任何压力测试！| [立即查看](https://openmili.com/) |
| **JTTI VPS** | 稳定建站服务器推荐：5 Mbps 独享带宽 无限流量 CN2/9929/CMI三网直连，跨境网站访问低延迟，长期稳定API运营。| [立即查看](https://www.jtti.cc/zh/activity/y2026-national-day.html?k=baoweise) |

AimiliVPN 使用 Python 标准库管理 VPNGate 节点，提供节点获取与检测、连接切换、Web 管理后台，以及共用一个端口的 HTTP、HTTPS 网站代理和 SOCKS5 代理服务。

| 项目 | 默认值或支持范围 |
| --- | --- |
| Web 管理后台 | TCP `8787` + 独立安全路径 + 账号密码 |
| 本机代理 | `127.0.0.1:7928`，支持 HTTP、HTTPS `CONNECT` 和 SOCKS5 |
| 源码部署 | x64、x86、ARM64、ARM32 Linux |
| Docker 镜像 | `linux/amd64`、`linux/386`、`linux/arm64`、`linux/arm/v7` |
| 更新通道 | GitHub `main` 正式分支 / 最新正式 Release |

> [!IMPORTANT]
> **网络可用性提示：** 不同地区、数据中心和网络服务商可能限制 DNS、VPNGate API、GitHub 镜像或 VPN 协议。镜像与本地缓存只能提高节点列表的可用性，不能保证所有机型都能建立连接。部署前请确认所在地法律和 VPS 服务商条款允许使用 VPN/TUN。

<a id="quick-install"></a>
## 快速安装

使用 `root` 用户在受支持的 Linux VPS 上执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kadidalax/aimili-vpngate/main/install.sh)
```

安装完成后，终端会显示 Web 后台完整地址、随机安全路径、登录账号和密码。输入 `ml` 可打开管理菜单。

无人值守安装可显式跳过首次参数询问，并自动生成安全路径和登录凭据：

```bash
AIMILIVPN_NONINTERACTIVE=1 bash <(curl -Ls https://raw.githubusercontent.com/kadidalax/aimili-vpngate/main/install.sh)
```

> [!TIP]
> 安装前请在 VPS 控制面板启用 TUN/TAP，并确认 `/dev/net/tun` 存在。Web 默认使用 TCP `8787`，安全组建议只允许自己的 IP 访问。

<a id="installation"></a>
## 完整安装

### 运行条件

- 操作系统：Ubuntu、Debian、Alpine、CentOS、RHEL、Rocky Linux、AlmaLinux、Fedora、Oracle Linux 或 Amazon Linux。
- 权限与组件：`root`、OpenVPN、iptables、策略路由和 TUN/TAP。
- Windows 与 macOS 可作为代理客户端，但不能直接运行完整网关；Docker Desktop 也不等同于具备宿主机 TUN 能力的 Linux VPS。

### 方式一：一键源码安装

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kadidalax/aimili-vpngate/main/install.sh)
```

安装器会部署到 `/opt/aimilivpn` 并注册系统服务。常用命令：

```bash
ml                 # 打开管理菜单
ml status          # 查看状态、Web 地址和账号
ml logs            # 查看实时日志
ml restart         # 重启服务
ml password        # 重设 Web 账号密码
ml update          # 从 main 正式分支更新
ml uninstall       # 卸载
```

需要先审查脚本时：

```bash
git clone --branch main --single-branch https://github.com/kadidalax/aimili-vpngate.git
cd aimili-vpngate
sudo bash install.sh
```

通用 Linux 源码包与 SHA-256 校验文件可在 [GitHub Releases](https://github.com/kadidalax/aimili-vpngate/releases/latest) 下载，版本变更记录也统一放在 Release Notes 中。

### 方式二：Docker Compose

Docker 主机需要 `/dev/net/tun`、host 网络以及 `NET_ADMIN`、`NET_RAW` 权限。

```bash
git clone --branch main --single-branch https://github.com/kadidalax/aimili-vpngate.git
cd aimili-vpngate
docker compose pull
docker compose up -d
docker logs -f aimilivpn
```

正式镜像：`ghcr.io/kadidalax/aimili-vpngate:2.2`

> [!NOTE]
> 镜像由推送 `v*` 标签时的 Release 工作流发布；尚未发布时可改用下方"本地构建"。Docker 模式不支持 sing-box 出口接管与全局出口。

更新容器：

```bash
docker compose pull
docker compose up -d
```

<details>
<summary><strong>查看 docker run 命令</strong></summary>

```bash
docker run -d \
  --name aimilivpn \
  --restart unless-stopped \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --device /dev/net/tun:/dev/net/tun \
  -e UI_HOST=0.0.0.0 \
  -e UI_PORT=8787 \
  -e LOCAL_PROXY_HOST=127.0.0.1 \
  -e LOCAL_PROXY_PORT=7928 \
  -v aimilivpn-data:/data \
  ghcr.io/kadidalax/aimili-vpngate:2.2
```

</details>

<details>
<summary><strong>无法拉取 GHCR 时在 VPS 本地构建</strong></summary>

```bash
git clone --branch main --single-branch https://github.com/kadidalax/aimili-vpngate.git
cd aimili-vpngate
docker compose build
docker compose up -d
```

</details>

<a id="connection"></a>
## 连接与使用

### 1. 登录 Web 后台

源码安装完成后，使用终端输出的地址访问：

```text
http://VPS_IP:8787/随机安全路径/
```

忘记地址时执行 `ml status`；需要重设账号密码时执行 `ml password`。

Docker 用户可以读取首次启动时保存的 Web 配置：

```bash
docker exec aimilivpn cat /data/ui_auth.json
```

使用其中的 `secret_path`、`username` 和 `password` 登录，并在首次登录后修改安全路径和凭据。

### 2. 获取并连接节点

1. 登录后台，等待首次节点加载完成，或点击“更新节点”。
2. 按国家筛选节点，并使用“测试”检查本机实测延迟与可用性。
3. 点击目标节点的“切换”；目标预检失败时，程序会尽量保留当前可用连接。
4. 根据需要选择智能自动、固定国家或固定 IP 模式。
5. 在状态区域确认 VPN 已连接，并核对当前出口 IP。

### 3. 在 VPS 本机使用代理

HTTP、HTTPS 网站代理和 SOCKS5 共用 `127.0.0.1:7928`。HTTPS 网站通过 HTTP 代理的 `CONNECT` 方法访问，代理地址仍填写 `http://127.0.0.1:7928`。

```bash
# HTTP / HTTPS
curl -x http://127.0.0.1:7928 https://api.ipify.org

# SOCKS5，并通过代理解析域名
curl --proxy socks5h://127.0.0.1:7928 https://api.ipify.org
```

<details>
<summary><strong>查看 Shell 环境变量与 Python 示例</strong></summary>

```bash
export http_proxy="http://127.0.0.1:7928"
export https_proxy="http://127.0.0.1:7928"
curl https://api.ipify.org
```

```python
import requests

proxies = {
    "http": "http://127.0.0.1:7928",
    "https": "http://127.0.0.1:7928",
}

response = requests.get("https://api.ipify.org", proxies=proxies, timeout=20)
print(response.text)
```

</details>

### 4. 从电脑或其他设备连接

代理默认只监听 VPS 回环地址。推荐使用 SSH 隧道，不要直接暴露代理端口：

```bash
ssh -N \
  -L 8787:127.0.0.1:8787 \
  -L 7928:127.0.0.1:7928 \
  root@VPS_IP
```

隧道建立后：

- Web：`http://127.0.0.1:8787/随机安全路径/`
- HTTP / HTTPS 代理：`127.0.0.1:7928`
- SOCKS5 代理：`127.0.0.1:7928`，支持时选择远程 DNS 或 `socks5h`

> [!WARNING]
> `7928` 默认没有面向公网的用户认证。请勿在没有防火墙、来源 IP 限制或其他可靠访问控制的情况下将其直接开放到公网。

<a id="exit-takeover"></a>
## 出口接管与节点测速

V2.2.0 起，面板可以让同一台 VPS 上裸机安装的 sing-box、甚至整台 VPS 的出站流量都经 VPN 节点出去，并能对节点做真实下载测速。两项出口功能都只在源码安装（非 Docker）且系统为 Linux 时可用。

### sing-box 出口接管（默认开启）

- 原理：面板独占写入 `/etc/sing-box/conf/90_aimili_vpngate.json`，新增一个绑定 `tun0` 的出站并设为 `route.final`，DNS 也经隧道解析，sing-box 的默认出站因此全部走当前 VPN 节点；显式指定了出站的规则（例如 `warp-ep`）不受影响。
- 写入前执行 `sing-box check`，不通过则删除文件并把错误显示在面板；通过后 reload 服务。sing-box 未运行时只写文件，启动后自动生效。
- fail-closed：隧道断开时 sing-box 的出站直接失败，不会回退到 VPS 直连，因此不会泄漏 VPS 真实 IP。
- 验证：在“代理设置”里点“验证出口”，面板读取 sing-box 的 Clash API 并显示“最近 N 条连接中 M 条经隧道”。
- 全局出口打开期间本开关由系统自动关闭，全局出口关闭后自动重新打开。

### 全局出口接管（默认关闭）

- 打开后 VPS 本机发起的全部 IPv4 出站流量经 VPN 节点。实现方式是策略路由：主表不动，新增 pref 30000 到 30031 的规则，先查主表但忽略默认路由，其余流量查表 100（由面板维护 `default dev tun0` 与 `unreachable default` 兜底）。
- 豁免：SSH、Web 面板与 sing-box 的入站连接回包、内网网段（10/8、172.16/12、192.168/16、169.254/16、100.64/10）、面板自身的管理流量（OpenVPN 外层报文、节点拉取与探测）都固定走物理网卡，不受隧道状态影响。
- fail-closed：隧道断开时 `tun0` 默认路由消失，兜底路由使出站立即失败，而不是漏回直连。面板“断开连接”会先询问并关闭全局开关。
- 已知绕过：IPv6 不经隧道。若 VPS 有公网 IPv6，访问 IPv6 目标的流量仍从 VPS 直接出去；不需要时请在系统层面禁用 IPv6。
- 重启窗口：面板正常停止或因端口变更重启时会先拆除规则，重启期间有数秒直连窗口；崩溃或断电后由 systemd 拉起时按设置重新应用。
- 逃生命令：面板不可用时可在 VPS 上执行以下命令关闭（或打开）两个开关，命令不启动服务，只改设置并应用：

```bash
cd /opt/aimilivpn
python3 vpngate_manager.py --global-exit off
python3 vpngate_manager.py --singbox-exit off
```

- 手工清理：程序损坏时可直接删除全局出口规则：

```bash
for p in $(seq 30000 30039); do ip rule del pref $p 2>/dev/null; done
ip route del unreachable default table 100 2>/dev/null
```

### 线性管线与检测周期

每一轮任务按固定顺序执行：获取节点列表，然后检测列表里全部节点的可用性，然后按测速设置筛选候选，然后逐个测速，最后按需切换到最快节点。任一入口运行期间其他入口返回“任务进行中”。

- “更新节点”按钮只执行获取与检测；“测速”弹窗里的“保存并开始测速”执行完整五步。
- 检测周期在“代理设置”里按小时设置（1 到 72，默认 24）。任何一轮任务结束都重新起算，面板显示“下次自动检测：X 小时 Y 分钟后”。
- 进度面板显示当前阶段、检测与测速进度、当前节点与本轮最快节点，可随时“停止任务”，已得结果保留。

### 节点测速

- 筛选：节点状态（可用、失效、全部）、国家、IP 类型（住宅、移动、机房、未知），并遵守当前路由模式的限制；不限测速数量。
- 每个节点单独建立测试隧道下载测速文件（默认单节点最长 8 秒或 20 MB），活动节点直接用当前隧道测。可设置“达标即停”阈值，任一节点达到设定 MB/s 即停止本轮。
- 弹窗实时估算“预计测 N 个节点，最多约 X MB，约 Y 分钟”。测速会消耗节点与 VPS 流量，请按需缩小范围。
- 结果显示在节点表“实测速度”列（悬停查看 Mbps 与测速时间），工具栏可“按实测速度”排序。
- “每轮检测后自动测速”让周期任务也执行测速；“自动切换最快节点”在本轮最快节点比当前节点快超过设定百分比（默认 20%）时切换，固定 IP 模式下不切换。

### Docker 模式限制

Docker 部署的容器无法操作宿主机的 sing-box 配置与策略路由，因此两个出口开关在 Docker 模式下置灰。节点测速与线性管线在 Docker 模式下可正常使用。

### 更新来源

本仓库（`kadidalax/aimili-vpngate`）是上游 `baoweise-bot/aimili-vpngate` 的分支，面板的版本检查与 `install.sh` 均指向本仓库。

<a id="community"></a>
## 网站、社群与视频

| 入口 | 用途 | 链接 |
| --- | --- | --- |
| 项目网站 / 交流论坛 | 公告、经验交流与讨论 | [339936.xyz](https://339936.xyz) |
| Telegram 群 | 即时交流 | [t.me/arestemple](https://t.me/arestemple) |
| YouTube 教程 | 安装和使用视频 | [观看视频](https://www.youtube.com/watch?v=s-ATfXR8BpI) |
| GitHub Issues | 可复现的问题与功能建议 | [提交 Issue](https://github.com/kadidalax/aimili-vpngate/issues) |

<a id="legal"></a>
## 使用范围与法律声明

> [!CAUTION]
> 下载、部署或使用本项目即表示您应自行确认用途符合所在地法律、VPS 所在地法律、网络服务商条款及 VPNGate 的相关规则。以下内容是项目使用边界，不构成法律意见，也不能保证免除任何个人或组织依法应承担的责任。

1. **限定用途**：本项目仅用于合法的网络研究、教育、开发测试、隐私保护和经授权的网络访问，不得用于绕过依法实施的监管措施、未授权访问、攻击、扫描、垃圾信息、欺诈、侵权或其他违法活动。
2. **网络与地区限制**：不同地区和数据中心可能限制 VPNGate、GitHub 镜像或远端 VPN 节点。本项目不承诺任何地区或机型始终可用；仅应在当地法律和服务商条款允许的环境中合理使用。
3. **第三方节点**：VPNGate 节点由第三方志愿者运营，本项目不拥有、不控制也不审核这些节点，无法保证其稳定性、速度、安全性、隐私政策或日志行为。请勿通过不可信节点传输账号密码、金融信息、商业机密等敏感数据。
4. **用户责任**：节点选择、流量内容、部署位置、端口开放和账号安全均由使用者负责。因违法使用、配置不当、第三方节点、服务中断、数据泄露或账号滥用产生的后果，由使用者依法承担。
5. **无保证提供**：软件按“现状”提供，在适用法律允许的最大范围内，维护者不对可用性、适销性、特定用途适用性或间接损失作出保证。无法依法排除的责任不受本声明影响。
6. **不确定时停止使用**：如无法确认当地法律或服务商是否允许，请停止部署和使用，并咨询当地有执业资格的法律专业人士。

<div align="center">

[正式版本](https://github.com/kadidalax/aimili-vpngate/releases/latest) · [问题反馈](https://github.com/kadidalax/aimili-vpngate/issues) · [GPL-3.0 License](LICENSE)

</div>
