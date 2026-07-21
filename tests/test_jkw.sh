#!/usr/bin/env bash
set -euo pipefail

ROOT=$(mktemp -d)
ROOT_RC=''
trap 'rm -rf "$ROOT" ${ROOT_RC:+"$ROOT_RC"}' EXIT

output=$(JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试菜单)
grep -q '查看当前状态' <<<"$output"
grep -q '所有 sing-box 节点走家宽' <<<"$output"
grep -q '整机全走家宽' <<<"$output"
grep -q '撤销全部改动并恢复原设置' <<<"$output"
grep -q '卸载本工具并彻底清理' <<<"$output"
! grep -qE '\b(Status|Install|Uninstall|Enable|Disable|Exit|Error)\b' <<<"$output"
! grep -q '确认撤销' jkw.sh
! grep -q '确认卸载' jkw.sh

if JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试依赖 >"$ROOT/out" 2>&1; then
  echo '缺失组件时不应返回成功'
  exit 1
fi
grep -q '未检测到 AimiliVPN' "$ROOT/out"
grep -q '未检测到 sing-box' "$ROOT/out"
grep -Eq '缺少必要系统命令|未检测到受支持的服务管理器' "$ROOT/out"
test ! -e "$ROOT/usr/local/sbin/jkw"

mkdir -p "$ROOT/etc/sing-box/conf"
cat >"$ROOT/etc/sing-box/conf/01_outbounds.json" <<'JSON'
{
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ]
}
JSON

JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试绑定
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["outbounds"][0]["bind_interface"] == "tun0"; assert "bind_interface" not in data["outbounds"][1]' "$ROOT/etc/sing-box/conf/01_outbounds.json"
first=$(sha256sum "$ROOT/etc/sing-box/conf/01_outbounds.json" | cut -d' ' -f1)
JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试绑定
second=$(sha256sum "$ROOT/etc/sing-box/conf/01_outbounds.json" | cut -d' ' -f1)
test "$first" = "$second"
JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试恢复绑定
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert "bind_interface" not in data["outbounds"][0]' "$ROOT/etc/sing-box/conf/01_outbounds.json"

rm -rf "$ROOT/etc/jkw"
python3 -c 'import json,sys; p=sys.argv[1]; data=json.load(open(p)); data["outbounds"][0]["bind_interface"]="ens18"; open(p,"w").write(json.dumps(data))' "$ROOT/etc/sing-box/conf/01_outbounds.json"
JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试绑定
JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试恢复绑定
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["outbounds"][0]["bind_interface"] == "ens18"' "$ROOT/etc/sing-box/conf/01_outbounds.json"

mkdir -p "$ROOT/opt/aimilivpn" "$ROOT/etc/sing-box" "$ROOT/bin"
: >"$ROOT/opt/aimilivpn/vpngate_manager.py"
cat >"$ROOT/etc/sing-box/sing-box" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$JKW_TEST_ROOT/调用记录"
[[ ${FAIL_CHECK:-0} != 1 ]]
SH
chmod +x "$ROOT/etc/sing-box/sing-box"
cat >"$ROOT/bin/systemctl" <<'SH'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >>"$JKW_TEST_ROOT/调用记录"
if [[ ${FAIL_SINGBOX_RESTART:-0} == 1 && "$*" == 'restart sing-box' ]]; then
  exit 1
fi
exit 0
SH
chmod +x "$ROOT/bin/systemctl"
cat >"$ROOT/bin/ip" <<'SH'
#!/usr/bin/env bash
case "$*" in
  'link show tun0') exit 0 ;;
  'route show table 100') echo 'default dev tun0 scope link' ;;
esac
exit 0
SH
chmod +x "$ROOT/bin/ip"

if FAIL_CHECK=1 PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试启用节点 >"$ROOT/fail" 2>&1; then
  echo '配置检查失败时不应返回成功'
  exit 1
fi
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["outbounds"][0]["bind_interface"] == "ens18"' "$ROOT/etc/sing-box/conf/01_outbounds.json"

PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试启用节点
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["outbounds"][0]["bind_interface"] == "tun0"' "$ROOT/etc/sing-box/conf/01_outbounds.json"
grep -q 'check -C' "$ROOT/调用记录"
grep -q 'systemctl restart sing-box' "$ROOT/调用记录"
grep -q '^singbox$' "$ROOT/etc/jkw/当前模式"

rules=$(JKW_PUBLIC_IPV4=172.245.120.103 JKW_PUBLIC_SUBNET=172.245.120.0/25 bash ./jkw.sh --测试规则)
grep -q 'table inet jkw' <<<"$rules"
grep -q 'ct state established,related accept' <<<"$rules"
grep -q 'meta mark 51820 accept' <<<"$rules"
grep -q 'oifname "tun\*" accept' <<<"$rules"
grep -q 'meta nfproto ipv6 reject' <<<"$rules"
grep -q 'reject with icmp type admin-prohibited' <<<"$rules"

cat >"$ROOT/bin/ip" <<'SH'
#!/usr/bin/env bash
printf 'ip %s\n' "$*" >>"$JKW_TEST_ROOT/调用记录"
[[ "$*" == rule\ del\ priority* ]] && : >"$JKW_TEST_ROOT/发生规则删除"
case "$*" in
  '-4 route show default') echo 'default via 172.245.120.1 dev ens18 onlink' ;;
  '-4 -o addr show dev ens18 scope global') echo '2: ens18 inet 172.245.120.103/25 brd 172.245.120.127 scope global ens18' ;;
  '-4 route show dev ens18 proto kernel scope link') echo '172.245.120.0/25 dev ens18 proto kernel scope link src 172.245.120.103' ;;
  'link show tun0') exit 0 ;;
  'route show table 100') echo 'default dev tun0 scope link' ;;
  'rule show') echo '0: from all lookup local'; echo '32766: from all lookup main' ;;
esac
exit 0
SH
chmod +x "$ROOT/bin/ip"
cat >"$ROOT/bin/nft" <<'SH'
#!/usr/bin/env bash
printf 'nft %s\n' "$*" >>"$JKW_TEST_ROOT/调用记录"
[[ "$*" == 'delete table inet jkw' ]] && : >"$JKW_TEST_ROOT/发生防火墙删除"
[[ "$*" == 'list table inet jkw' ]] && exit 1
[[ ${FAIL_NFT_APPLY:-0} == 1 && ${1:-} == '-f' ]] && exit 1
exit 0
SH
chmod +x "$ROOT/bin/nft"
cat >"$ROOT/bin/openvpn" <<'SH'
#!/usr/bin/env bash
echo '--mark value'
SH
chmod +x "$ROOT/bin/openvpn"

: >"$ROOT/调用记录"
PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试恢复绑定
printf 'singbox\n' >"$ROOT/etc/jkw/当前模式"
if FAIL_SINGBOX_RESTART=1 PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --开机恢复; then
  echo '开机恢复重启 sing-box 失败时不应返回成功'
  exit 1
fi
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["outbounds"][0]["bind_interface"] == "ens18"' "$ROOT/etc/sing-box/conf/01_outbounds.json"
grep -q '^singbox$' "$ROOT/etc/jkw/当前模式"

: >"$ROOT/调用记录"
printf 'global\n' >"$ROOT/etc/jkw/当前模式"
if FAIL_NFT_APPLY=1 PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --开机恢复; then
  echo '开机恢复全局规则失败时不应返回成功'
  exit 1
fi
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["outbounds"][0]["bind_interface"] == "ens18"' "$ROOT/etc/sing-box/conf/01_outbounds.json"
grep -q '^global$' "$ROOT/etc/jkw/当前模式"
grep -q 'ip rule del priority 31830' "$ROOT/调用记录"

: >"$ROOT/调用记录"
PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试启用整机
grep -q '^global$' "$ROOT/etc/jkw/当前模式"
! grep -q 'systemctl restart aimilivpn' "$ROOT/调用记录"
grep -q 'ip route replace default dev tun0 table 110' "$ROOT/调用记录"
grep -q 'ip rule add priority 31820 fwmark 51820 lookup main' "$ROOT/调用记录"
grep -q 'ip rule add priority 31821 from 172.245.120.103/32 lookup main' "$ROOT/调用记录"
grep -q 'ip rule add priority 31822 to 172.245.120.0/25 lookup main' "$ROOT/调用记录"
grep -q 'ip rule add priority 31830 lookup 110' "$ROOT/调用记录"
grep -q 'nft -f' "$ROOT/调用记录"

: >"$ROOT/调用记录"
PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --刷新整机路由
grep -q 'ip route replace default dev tun0 table 110' "$ROOT/调用记录"
grep -q 'ip rule add priority 31830 lookup 110' "$ROOT/调用记录"
grep -q 'nft -f' "$ROOT/调用记录"

PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试关闭整机
grep -q '^singbox$' "$ROOT/etc/jkw/当前模式"
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["outbounds"][0]["bind_interface"] == "tun0"' "$ROOT/etc/sing-box/conf/01_outbounds.json"
grep -q 'nft delete table inet jkw' "$ROOT/调用记录"
grep -q 'ip rule del priority 31830' "$ROOT/调用记录"
grep -q 'ip route flush table 110' "$ROOT/调用记录"

PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试撤销
grep -q '^none$' "$ROOT/etc/jkw/当前模式"
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); assert data["outbounds"][0]["bind_interface"] == "ens18"' "$ROOT/etc/sing-box/conf/01_outbounds.json"
test -f "$ROOT/opt/aimilivpn/vpngate_manager.py"
test -f "$ROOT/etc/sing-box/conf/01_outbounds.json"

ROOT_RC=$(mktemp -d)
mkdir -p "$ROOT_RC/opt/aimilivpn" "$ROOT_RC/etc/sing-box/conf" "$ROOT_RC/etc/sing-box" "$ROOT_RC/bin"
: >"$ROOT_RC/opt/aimilivpn/vpngate_manager.py"
cat >"$ROOT_RC/etc/sing-box/conf/01_outbounds.json" <<'JSON'
{"outbounds":[{"type":"direct","tag":"direct"}]}
JSON
cat >"$ROOT_RC/etc/sing-box/sing-box" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$ROOT_RC/etc/sing-box/sing-box"
cat >"$ROOT_RC/bin/rc-service" <<'SH'
#!/usr/bin/env bash
printf 'rc-service %s\n' "$*" >>"$JKW_TEST_ROOT/调用记录"
exit 0
SH
cat >"$ROOT_RC/bin/rc-update" <<'SH'
#!/usr/bin/env bash
printf 'rc-update %s\n' "$*" >>"$JKW_TEST_ROOT/调用记录"
exit 0
SH
chmod +x "$ROOT_RC/bin/rc-service" "$ROOT_RC/bin/rc-update"
cat >"$ROOT_RC/bin/ip" <<'SH'
#!/usr/bin/env bash
case "$*" in
  'link show tun0') exit 0 ;;
  'route show table 100') echo 'default dev tun0 scope link' ;;
esac
exit 0
SH
cat >"$ROOT_RC/bin/nft" <<'SH'
#!/usr/bin/env bash
exit 0
SH
cat >"$ROOT_RC/bin/openvpn" <<'SH'
#!/usr/bin/env bash
echo '--mark value'
SH
chmod +x "$ROOT_RC/bin/ip" "$ROOT_RC/bin/nft" "$ROOT_RC/bin/openvpn"

environment=$(PATH="$ROOT_RC/bin:$PATH" JKW_SERVICE_MANAGER=openrc JKW_TEST_ROOT="$ROOT_RC" bash ./jkw.sh --测试环境)
grep -q '服务管理器：OpenRC' <<<"$environment"
grep -q '环境兼容性检查通过' <<<"$environment"

PATH="$ROOT_RC/bin:$PATH" JKW_SERVICE_MANAGER=openrc JKW_TEST_ROOT="$ROOT_RC" bash ./jkw.sh --测试启用节点
test -x "$ROOT_RC/etc/init.d/jkw"
test ! -e "$ROOT_RC/etc/systemd/system/jkw.service"
grep -q 'rc-service sing-box restart' "$ROOT_RC/调用记录"
grep -q 'rc-update add jkw default' "$ROOT_RC/调用记录"

PATH="$ROOT_RC/bin:$PATH" JKW_SERVICE_MANAGER=openrc JKW_TEST_ROOT="$ROOT_RC" bash ./jkw.sh --测试卸载
test ! -e "$ROOT_RC/etc/init.d/jkw"
grep -q 'rc-update del jkw default' "$ROOT_RC/调用记录"

: >"$ROOT/调用记录"
PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试撤销
grep -q 'ip rule del priority 31830' "$ROOT/调用记录"
grep -q 'ip route flush table 110' "$ROOT/调用记录"

status=$(PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试状态)
grep -q '当前模式：未启用' <<<"$status"
grep -q 'AimiliVPN 服务：运行中' <<<"$status"
grep -q 'sing-box 服务：运行中' <<<"$status"
grep -q '家宽网卡：可用' <<<"$status"

mkdir -p "$ROOT/etc/jkw"
printf 'global\n' >"$ROOT/etc/jkw/当前模式"
: >"$ROOT/etc/jkw/整机规则已创建"
status=$(PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试状态)
grep -q '整机规则：异常' <<<"$status"

PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试安装工具
test -x "$ROOT/usr/local/sbin/jkw"
test -f "$ROOT/etc/systemd/system/jkw.service"
grep -q '家宽出口开机恢复服务' "$ROOT/etc/systemd/system/jkw.service"
grep -q '/usr/local/sbin/jkw --开机恢复' "$ROOT/etc/systemd/system/jkw.service"

PATH="$ROOT/bin:$PATH" JKW_TEST_ROOT="$ROOT" bash ./jkw.sh --测试卸载
test ! -e "$ROOT/usr/local/sbin/jkw"
test ! -e "$ROOT/etc/systemd/system/jkw.service"
test ! -e "$ROOT/etc/jkw"
test -f "$ROOT/opt/aimilivpn/vpngate_manager.py"
test -f "$ROOT/etc/sing-box/conf/01_outbounds.json"
