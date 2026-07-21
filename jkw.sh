#!/usr/bin/env bash
set -u

TEST_ROOT=${JKW_TEST_ROOT:-}

root_path() {
  printf '%s%s' "$TEST_ROOT" "$1"
}

STATE_DIR=$(root_path /etc/jkw)
SINGBOX_CONF=$(root_path /etc/sing-box/conf/01_outbounds.json)
SINGBOX_CONF_DIR=$(root_path /etc/sing-box/conf)
SINGBOX_BIN=$(root_path /etc/sing-box/sing-box)
ORIGINAL_BIND_STATE="$STATE_DIR/原始出口接口.json"
MODE_FILE="$STATE_DIR/当前模式"
GLOBAL_RULE_MARKER="$STATE_DIR/整机规则已创建"
GLOBAL_ROUTE_TABLE=110
INSTALLED_COMMAND=$(root_path /usr/local/sbin/jkw)
SYSTEMD_SERVICE_FILE=$(root_path /etc/systemd/system/jkw.service)
OPENRC_SERVICE_FILE=$(root_path /etc/init.d/jkw)
SCRIPT_SOURCE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
SERVICE_MANAGER=${JKW_SERVICE_MANAGER:-}

detect_service_manager() {
  if [[ "$SERVICE_MANAGER" == systemd ]]; then
    check_commands systemctl || return 1
    return 0
  fi
  if [[ "$SERVICE_MANAGER" == openrc ]]; then
    check_commands rc-service rc-update || return 1
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl show-environment >/dev/null 2>&1; then
    SERVICE_MANAGER=systemd
    return 0
  fi
  if command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    SERVICE_MANAGER=openrc
    return 0
  fi
  echo '未检测到受支持的服务管理器，需要 systemd 或 OpenRC。'
  return 1
}

service_restart() {
  detect_service_manager || return 1
  if [[ "$SERVICE_MANAGER" == systemd ]]; then
    systemctl restart "$1"
  else
    rc-service "$1" restart
  fi
}

service_is_active() {
  detect_service_manager >/dev/null 2>&1 || return 1
  if [[ "$SERVICE_MANAGER" == systemd ]]; then
    systemctl is-active --quiet "$1"
  else
    rc-service "$1" status >/dev/null 2>&1
  fi
}

service_enable_runtime() {
  if [[ "$SERVICE_MANAGER" == systemd ]]; then
    systemctl daemon-reload
    systemctl enable jkw.service >/dev/null 2>&1 || true
  else
    rc-update add jkw default >/dev/null 2>&1 || true
  fi
}

service_disable_runtime() {
  detect_service_manager >/dev/null 2>&1 || return 0
  if [[ "$SERVICE_MANAGER" == systemd ]]; then
    systemctl disable --now jkw.service >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  else
    rc-service jkw stop >/dev/null 2>&1 || true
    rc-update del jkw default >/dev/null 2>&1 || true
  fi
}

change_singbox_bind() {
  local action=$1
  mkdir -p "$STATE_DIR"
  python3 - "$SINGBOX_CONF" "$ORIGINAL_BIND_STATE" "$action" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
state_path = Path(sys.argv[2])
action = sys.argv[3]

try:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    direct = next((item for item in data.get("outbounds", []) if item.get("tag") == "direct"), None)
    if direct is None:
        raise ValueError("未找到 direct 出站配置。")

    if action == "set":
        if not state_path.exists():
            state_path.write_text(
                json.dumps(
                    {"exists": "bind_interface" in direct, "value": direct.get("bind_interface")},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            os.chmod(state_path, 0o600)
        direct["bind_interface"] = "tun0"
    elif action == "restore":
        if not state_path.exists():
            sys.exit(0)
        original = json.loads(state_path.read_text(encoding="utf-8"))
        if original["exists"]:
            direct["bind_interface"] = original["value"]
        else:
            direct.pop("bind_interface", None)
    else:
        raise ValueError("未知配置操作。")

    temp_path = config_path.with_name(config_path.name + ".jkw.tmp")
    temp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temp_path, stat.S_IMODE(config_path.stat().st_mode))
    os.replace(temp_path, config_path)
except Exception as exc:
    print(f"配置 sing-box 失败：{exc}", file=sys.stderr)
    sys.exit(1)
PY
}

enable_singbox_mode() {
  check_components || return 1
  check_commands ip || return 1
  wait_for_tun0 || return 1
  install_runtime || return 1
  change_singbox_bind set || return 1
  if ! "$SINGBOX_BIN" check -C "$SINGBOX_CONF_DIR"; then
    echo 'sing-box 配置检查失败，正在恢复原设置。'
    change_singbox_bind restore || true
    return 1
  fi
  if ! service_restart sing-box; then
    echo 'sing-box 重启失败，正在恢复原设置。'
    change_singbox_bind restore || true
    service_restart sing-box >/dev/null 2>&1 || true
    return 1
  fi
  mkdir -p "$STATE_DIR"
  printf 'singbox\n' >"$MODE_FILE"
  echo '全部 sing-box 节点已切换到家宽出口。'
}

generate_nft_rules() {
  cat <<'EOF'
table inet jkw {
  chain output {
    type filter hook output priority -10; policy accept;
    oifname "lo" accept
    ct state established,related accept
    meta mark 51820 accept
    oifname "tun*" accept
    ip daddr 127.0.0.0/8 accept
    ip6 daddr { ::1, fe80::/10 } accept
    meta nfproto ipv6 reject with icmpv6 type admin-prohibited
    reject with icmp type admin-prohibited
  }
}
EOF
}

read_public_network() {
  local default_route
  default_route=$(ip -4 route show default | head -n 1)
  PUBLIC_INTERFACE=$(awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<<"$default_route")
  PUBLIC_IPV4=$(ip -4 -o addr show dev "$PUBLIC_INTERFACE" scope global | awk 'NR == 1 {sub(/\/.*/, "", $4); print $4}')
  PUBLIC_SUBNET=$(ip -4 route show dev "$PUBLIC_INTERFACE" proto kernel scope link | awk '$1 ~ /\// {print $1; exit}')
  if [[ -z "$PUBLIC_INTERFACE" || -z "$PUBLIC_IPV4" || -z "$PUBLIC_SUBNET" ]]; then
    echo '无法识别 VPS 原生网络信息。'
    return 1
  fi
}

wait_for_tun0() {
  local attempts=30
  [[ -n "$TEST_ROOT" ]] && attempts=1
  while (( attempts > 0 )); do
    if ip link show tun0 >/dev/null 2>&1 && ip route show table 100 | grep -q 'default dev tun0'; then
      return 0
    fi
    attempts=$((attempts - 1))
    (( attempts > 0 )) && sleep 2
  done
  echo '未检测到可用的 tun0 家宽出口。'
  return 1
}

delete_global_rules() {
  nft delete table inet jkw >/dev/null 2>&1 || true
  ip rule del priority 31830 >/dev/null 2>&1 || true
  ip rule del priority 31822 >/dev/null 2>&1 || true
  ip rule del priority 31821 >/dev/null 2>&1 || true
  ip rule del priority 31820 >/dev/null 2>&1 || true
  ip route flush table "$GLOBAL_ROUTE_TABLE" >/dev/null 2>&1 || true
  rm -f "$GLOBAL_RULE_MARKER"
}

check_global_rule_collisions() {
  [[ -f "$GLOBAL_RULE_MARKER" ]] && return 0
  local current
  current=$(ip rule show)
  if grep -Eq '^(31820|31821|31822|31830):' <<<"$current"; then
    echo '检测到策略路由编号冲突，未修改系统。'
    return 1
  fi
  if nft list table inet jkw >/dev/null 2>&1; then
    echo '检测到同名防火墙表，未修改系统。'
    return 1
  fi
}

apply_global_rules() {
  read_public_network || return 1
  check_global_rule_collisions || return 1
  [[ -f "$GLOBAL_RULE_MARKER" ]] && delete_global_rules

  if ! ip route replace default dev tun0 table "$GLOBAL_ROUTE_TABLE"; then
    delete_global_rules
    return 1
  fi

  if ! ip rule add priority 31820 fwmark 51820 lookup main \
    || ! ip rule add priority 31821 from "$PUBLIC_IPV4/32" lookup main \
    || ! ip rule add priority 31822 to "$PUBLIC_SUBNET" lookup main \
    || ! ip rule add priority 31830 lookup "$GLOBAL_ROUTE_TABLE"; then
    delete_global_rules
    return 1
  fi

  local rules_file
  rules_file=$(root_path /run/jkw-rules.nft)
  mkdir -p "$(dirname "$rules_file")"
  generate_nft_rules >"$rules_file"
  if ! nft -c -f "$rules_file"; then
    echo '防泄漏规则检查失败，正在撤销策略路由。'
    delete_global_rules
    rm -f "$rules_file"
    return 1
  fi
  nft delete table inet jkw >/dev/null 2>&1 || true
  if ! nft -f "$rules_file"; then
    echo '防泄漏规则加载失败，正在撤销策略路由。'
    delete_global_rules
    rm -f "$rules_file"
    return 1
  fi
  rm -f "$rules_file"
  mkdir -p "$STATE_DIR"
  : >"$GLOBAL_RULE_MARKER"
}

refresh_global_route() {
  [[ -f "$MODE_FILE" && "$(<"$MODE_FILE")" == global ]] || return 0
  wait_for_tun0 || return 1
  apply_global_rules
}

enable_global_mode() {
  check_commands ip nft || return 1
  check_openvpn_mark_support || return 1
  enable_singbox_mode || return 1
  if ! wait_for_tun0 || ! apply_global_rules; then
    delete_global_rules
    printf 'singbox\n' >"$MODE_FILE"
    return 1
  fi
  printf 'global\n' >"$MODE_FILE"
  echo '整机全走家宽已开启。'
}

disable_global_mode() {
  delete_global_rules
  mkdir -p "$STATE_DIR"
  printf 'singbox\n' >"$MODE_FILE"
  echo '整机全走家宽已关闭，sing-box 节点仍使用家宽出口。'
}

undo_all() {
  delete_global_rules
  change_singbox_bind restore || return 1
  if ! "$SINGBOX_BIN" check -C "$SINGBOX_CONF_DIR"; then
    echo '恢复后的 sing-box 配置检查失败，未重启服务。'
    change_singbox_bind set || true
    return 1
  fi
  service_restart sing-box || return 1
  mkdir -p "$STATE_DIR"
  printf 'none\n' >"$MODE_FILE"
  echo '已撤销全部改动并恢复原设置。'
}

install_runtime() {
  check_components || return 1
  detect_service_manager || return 1
  mkdir -p "$(dirname "$INSTALLED_COMMAND")" "$STATE_DIR"
  if [[ "$(readlink -f "$SCRIPT_SOURCE")" != "$(readlink -f "$INSTALLED_COMMAND" 2>/dev/null || true)" ]]; then
    cp "$SCRIPT_SOURCE" "$INSTALLED_COMMAND"
    chmod 0755 "$INSTALLED_COMMAND"
  fi
  if [[ "$SERVICE_MANAGER" == systemd ]]; then
    mkdir -p "$(dirname "$SYSTEMD_SERVICE_FILE")"
    cat >"$SYSTEMD_SERVICE_FILE" <<'EOF'
[Unit]
Description=家宽出口开机恢复服务
After=network-online.target aimilivpn.service sing-box.service
Wants=network-online.target aimilivpn.service sing-box.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/jkw --开机恢复
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  else
    mkdir -p "$(dirname "$OPENRC_SERVICE_FILE")"
    cat >"$OPENRC_SERVICE_FILE" <<'EOF'
#!/sbin/openrc-run
description="家宽出口开机恢复服务"

depend() {
  need net
  after aimilivpn sing-box
}

start() {
  ebegin "恢复家宽出口设置"
  /usr/local/sbin/jkw --开机恢复
  eend $?
}
EOF
    chmod 0755 "$OPENRC_SERVICE_FILE"
  fi
  service_enable_runtime
}

rollback_boot_restore() {
  delete_global_rules
  change_singbox_bind restore || true
  service_restart sing-box >/dev/null 2>&1 || true
}

restore_boot_mode() {
  local mode=none
  [[ -f "$MODE_FILE" ]] && mode=$(<"$MODE_FILE")
  case "$mode" in
    singbox|global)
      change_singbox_bind set || return 1
      if ! "$SINGBOX_BIN" check -C "$SINGBOX_CONF_DIR" || ! service_restart sing-box; then
        rollback_boot_restore
        return 1
      fi
      if [[ "$mode" == global ]] && ! apply_global_rules; then
        rollback_boot_restore
        return 1
      fi
      ;;
  esac
}

uninstall_tool() {
  undo_all || return 1
  service_disable_runtime
  rm -f "$SYSTEMD_SERVICE_FILE" "$OPENRC_SERVICE_FILE" "$INSTALLED_COMMAND" "$(root_path /run/jkw-rules.nft)"
  rm -rf "$STATE_DIR"
  [[ "$SERVICE_MANAGER" == systemd ]] && systemctl daemon-reload >/dev/null 2>&1 || true
  echo '本工具已卸载，创建的配置和规则已清理。'
}

check_openvpn_mark_support() {
  if ! command -v openvpn >/dev/null 2>&1; then
    echo '未检测到 OpenVPN 命令。'
    return 1
  fi
  if ! openvpn --help 2>&1 | grep -q -- '--mark value'; then
    echo '当前 OpenVPN 不支持数据包标记，无法开启整机模式。'
    return 1
  fi
}

environment_check() {
  local failed=0 manager_text='未知'
  echo '----------------------------------------'
  echo '开始检查运行环境……'
  check_components || failed=1
  if detect_service_manager; then
    [[ "$SERVICE_MANAGER" == systemd ]] && manager_text='systemd' || manager_text='OpenRC'
    echo "服务管理器：$manager_text"
  else
    failed=1
  fi
  check_commands ip nft curl openvpn || failed=1
  if [[ -z "$TEST_ROOT" && ! -c /dev/net/tun ]]; then
    echo 'TUN/TAP：不可用'
    failed=1
  else
    echo 'TUN/TAP：可用'
  fi
  if ip link show tun0 >/dev/null 2>&1 && ip route show table 100 | grep -q 'default dev tun0'; then
    echo '家宽隧道：已连接'
  else
    echo '家宽隧道：未连接'
    failed=1
  fi
  if check_openvpn_mark_support; then
    echo 'OpenVPN 数据包标记：支持'
  else
    failed=1
  fi
  if nft list tables >/dev/null 2>&1; then
    echo '防泄漏规则支持：可用'
  else
    echo '防泄漏规则支持：不可用'
    failed=1
  fi
  if (( failed == 0 )); then
    echo '环境兼容性检查通过。'
  else
    echo '环境兼容性检查未通过，未修改系统。'
  fi
  echo '----------------------------------------'
  return "$failed"
}

show_status() {
  local mode=none mode_text='未启用'
  [[ -f "$MODE_FILE" ]] && mode=$(<"$MODE_FILE")
  case "$mode" in
    singbox) mode_text='仅全部 sing-box 节点走家宽' ;;
    global) mode_text='整机全部流量走家宽' ;;
  esac

  echo '----------------------------------------'
  echo "当前模式：$mode_text"
  if service_is_active aimilivpn; then
    echo 'AimiliVPN 服务：运行中'
  else
    echo 'AimiliVPN 服务：未运行'
  fi
  if service_is_active sing-box; then
    echo 'sing-box 服务：运行中'
  else
    echo 'sing-box 服务：未运行'
  fi
  if ip link show tun0 >/dev/null 2>&1; then
    echo '家宽网卡：可用'
  else
    echo '家宽网卡：不可用'
  fi
  if [[ "$mode" == global ]] \
    && ip rule show | grep -Eq '^31830:.*lookup 110' \
    && ip route show table 110 | grep -q 'default dev tun0' \
    && nft list table inet jkw >/dev/null 2>&1; then
    echo '整机规则：正常'
  elif [[ "$mode" == global ]]; then
    echo '整机规则：异常'
  else
    echo '整机规则：未启用'
  fi
  echo '----------------------------------------'
}

query_ip() {
  curl "$@" -4 -fsS --max-time 20 https://api.ipify.org 2>/dev/null || return 1
}

test_singbox_egress() {
  local port config_file log_file pid result
  port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
  config_file=$(root_path "/run/jkw-test-$port.json")
  log_file=$(root_path "/run/jkw-test-$port.log")
  mkdir -p "$(dirname "$config_file")"
  cat >"$config_file" <<EOF
{
  "log": {"disabled": true},
  "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": $port}],
  "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "tun0"}]
}
EOF
  "$SINGBOX_BIN" run -c "$config_file" >"$log_file" 2>&1 &
  pid=$!
  sleep 1
  result=$(query_ip --proxy "socks5h://127.0.0.1:$port" || true)
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  rm -f "$config_file" "$log_file"
  [[ -n "$result" ]] && printf '%s' "$result"
}

test_egress() {
  local system_ip aimili_ip singbox_ip
  check_commands curl python3 || return 1
  system_ip=$(query_ip || true)
  aimili_ip=$(query_ip --proxy socks5h://127.0.0.1:7928 || true)
  singbox_ip=$(test_singbox_egress || true)
  echo "系统当前出口：${system_ip:-检测失败}"
  echo "AimiliVPN 家宽出口：${aimili_ip:-检测失败}"
  echo "sing-box 家宽出口：${singbox_ip:-检测失败}"
}

toggle_global_mode() {
  local mode=none
  [[ -f "$MODE_FILE" ]] && mode=$(<"$MODE_FILE")
  if [[ "$mode" == global ]]; then
    disable_global_mode
  else
    enable_global_mode
  fi
}

pause_menu() {
  read -r -p '按回车键返回菜单……' _
}

interactive_menu() {
  local choice confirm
  while true; do
    show_menu
    read -r -p '请选择操作：' choice
    case "$choice" in
      1) show_status; pause_menu ;;
      2) enable_singbox_mode; pause_menu ;;
      3) toggle_global_mode; pause_menu ;;
      4) test_egress; pause_menu ;;
      5)
        read -r -p '输入“确认撤销”继续：' confirm
        [[ "$confirm" == '确认撤销' ]] && undo_all || echo '已取消。'
        pause_menu
        ;;
      6)
        read -r -p '输入“确认卸载”继续：' confirm
        if [[ "$confirm" == '确认卸载' ]]; then
          uninstall_tool
          return
        fi
        echo '已取消。'
        pause_menu
        ;;
      7) environment_check; pause_menu ;;
      0) echo '已退出。'; return ;;
      *) echo '输入无效，请重新选择。'; pause_menu ;;
    esac
  done
}

check_components() {
  local failed=0
  if [[ ! -f "$(root_path /opt/aimilivpn/vpngate_manager.py)" ]]; then
    echo '未检测到 AimiliVPN，请先手动安装。'
    failed=1
  fi
  if [[ ! -x "$(root_path /etc/sing-box/sing-box)" || ! -f "$(root_path /etc/sing-box/conf/01_outbounds.json)" ]]; then
    echo '未检测到 sing-box，请先手动安装。'
    failed=1
  fi
  if ! check_commands python3 cp chmod; then
    failed=1
  fi
  detect_service_manager || failed=1
  return "$failed"
}

check_commands() {
  local command_name missing=()
  for command_name in "$@"; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done
  if (( ${#missing[@]} > 0 )); then
    echo "缺少必要系统命令：${missing[*]}。请先手动安装。"
    return 1
  fi
}

show_menu() {
  cat <<'EOF'
========================================
        家宽出口管理工具
========================================
1. 查看当前状态
2. 所有 sing-box 节点走家宽
3. 整机全走家宽：开启或关闭
4. 测试当前出口
5. 撤销全部改动并恢复原设置
6. 卸载本工具并彻底清理
7. 环境兼容性检查
0. 退出
EOF
}

case "${1:-}" in
  --测试菜单)
    show_menu
    exit 0
    ;;
  --测试依赖)
    check_components
    exit $?
    ;;
  --测试绑定)
    change_singbox_bind set
    exit $?
    ;;
  --测试恢复绑定)
    change_singbox_bind restore
    exit $?
    ;;
  --测试启用节点)
    enable_singbox_mode
    exit $?
    ;;
  --测试规则)
    generate_nft_rules
    exit 0
    ;;
  --测试启用整机)
    enable_global_mode
    exit $?
    ;;
  --测试关闭整机)
    disable_global_mode
    exit $?
    ;;
  --测试撤销)
    undo_all
    exit $?
    ;;
  --测试安装工具)
    install_runtime
    exit $?
    ;;
  --测试卸载)
    uninstall_tool
    exit $?
    ;;
  --测试状态)
    show_status
    exit 0
    ;;
  --测试环境)
    environment_check
    exit $?
    ;;
  --开机恢复)
    restore_boot_mode
    exit $?
    ;;
  --刷新整机路由)
    refresh_global_route
    exit $?
    ;;
  --启用节点家宽)
    enable_singbox_mode
    exit $?
    ;;
  --切换整机家宽)
    toggle_global_mode
    exit $?
    ;;
  --查看状态)
    show_status
    exit 0
    ;;
  --测试出口)
    test_egress
    exit $?
    ;;
  --撤销)
    undo_all
    exit $?
    ;;
esac

if [[ -z "$TEST_ROOT" && ${EUID:-$(id -u)} -ne 0 ]]; then
  echo '请使用 root 用户运行本工具。'
  exit 1
fi

check_components || exit 1
interactive_menu
