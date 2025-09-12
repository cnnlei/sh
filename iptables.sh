#!/bin/bash

# ======================================================================
#  专业多链交互式 IPTables 管理器 (v40.3.2 - 社区修正版)
# ======================================================================
#  - 版本说明 (v40.3.2):
#    - [功能强化] 为“重置防火墙”功能增加了二次确认步骤，防止误操作。
#    - [UI优化] 在菜单中将“重置防火墙”标记为谨慎操作。
#  - (继承 v40.3.1):
#    - [BUG修复] 修正了 `add_port_forward_rule` 中通用且不精确的 MASQUERADE 规则，
#      现在会为每个转发创建对应的、带有源地址的特定伪装规则，避免了在复杂 NAT 环境下的“单向通”问题。
#    - [BUG修复] 修正了 `view_delete_port_forward_rules` 逻辑，使其能够识别并
#      一并清除 v40.3.1 版本创建的特定 MASQUERADE 规则，确保规则集能够被完整移除。
#    - (继承 v40.3) 修正了 unattended_dep_deployment 中错误的数组声明。
#    - (继承 v40.3) 优化了 Docker 模块，现在可以正确处理并让用户选择拥有多个 IP 地址的容器。
# ======================================================================

# --- 配置 ---
export LESS="-R"
USE_COLORS=true
RULES_FILE_V4="/etc/iptables/rules.v4"
RULES_FILE_V6="/etc/iptables/rules.v6"
RULES_FILE_RHEL_V4="/etc/sysconfig/iptables"
RULES_FILE_RHEL_V6="/etc/sysconfig/ip6tables"

# --- 颜色定义 ---
RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; NC=''
if [ "$USE_COLORS" = true ]; then
    if [ -t 1 ]; then
        TPUT_COLORS=$(tput colors 2>/dev/null)
        if [ $? -eq 0 ] && [ "$TPUT_COLORS" -ge 8 ]; then
            RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
        fi
    fi
fi

if [[ $EUID -ne 0 ]]; then echo -e "${RED}错误：此脚本必须以 root 用户身份运行。请使用 'sudo'。${NC}"; exit 1; fi

# --- 全局变量 ---
IPTABLES_CMD=""
IP_VERSION=""
SCRIPT_INSTALL_PATH="/usr/local/sbin/iptables-mgr.sh"
SAFE_CMD_PATH="/usr/local/bin/ipt"
F2B_CMD_PATH="/usr/local/bin/f2b"


# ----------------------------------------------------------------------
#  协议选择
# ----------------------------------------------------------------------
function select_protocol() {
    clear
    echo "======================================================"
    echo "                           IPTables 防火墙管理器 V40.3.2 (社区修正版)"
    echo "======================================================"
    echo "请选择您要管理的防火墙协议："
    echo " 1. IPv4"
    echo " 2. IPv6"
    echo "------------------------------------------------------"
    read -p "请输入选择 [回车默认为 1 (IPv4)]: " proto_choice

    case $proto_choice in
        ""|1)
            IPTABLES_CMD="iptables"; IP_VERSION="IPv4"; RULES_FILE="$RULES_FILE_V4"; RULES_FILE_RHEL="$RULES_FILE_RHEL_V4"; SAVE_SERVICE_NAME="iptables"; SS_FAMILY_FLAG="-4"; ICMP_PROTO="icmp" ;;
        2)
            IPTABLES_CMD="ip6tables"; IP_VERSION="IPv6"; RULES_FILE="$RULES_FILE_V6"; RULES_FILE_RHEL="$RULES_FILE_RHEL_V6"; SAVE_SERVICE_NAME="ip6tables"; SS_FAMILY_FLAG="-6"; ICMP_PROTO="icmpv6" ;;
        *)
            echo -e "${RED}无效选择，正在重试...${NC}"; sleep 1; select_protocol ;;
    esac
    echo -e "${GREEN}✓ 您已选择管理 ${IP_VERSION} 防火墙。${NC}"; sleep 1
}

# ======================================================================
#  核心 OUTPUT 规则守护函数 (专注版)
# ======================================================================
function ensure_output_rule_exists() {
    local core_rule="OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    if ! $IPTABLES_CMD -C ${core_rule} > /dev/null 2>&1; then
        $IPTABLES_CMD -I ${core_rule}
        echo -e "\n${YELLOW}警告：检测到核心出站规则丢失，已自动恢复至第一条并保存。${NC}"
        save_all_rules
        sleep 2
    fi
}

# ----------------------------------------------------------------------
#  依赖部署与核心功能
# ----------------------------------------------------------------------
function unattended_dep_deployment() {
    export PATH=$PATH:/usr/sbin:/sbin
    local DISTRO=""
    if [ -f /etc/debian_version ]; then DISTRO="debian"; elif [ -f /etc/redhat-release ]; then DISTRO="rhel"; else echo -e "${RED}不支持的操作系统。${NC}"; exit 1; fi

    # 使用 local -A 显式声明为关联数组，确保各种bash版本都能正确识别。
    local -A base_deps_map
    base_deps_map=( ["grep"]="grep" ["awk"]="gawk" ["sed"]="sed" ["tput"]="ncurses-bin" ["curl"]="curl" )
    if [ "$DISTRO" == "rhel" ]; then
        base_deps_map["tput"]="ncurses"
    fi
    
    local base_to_install=()
    local base_pkg_to_install=()
    echo "--- 正在检查核心组件 ---"
    for cmd in "${!base_deps_map[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            base_to_install+=("$cmd")
            base_pkg_to_install+=("${base_deps_map[$cmd]}")
        fi
    done
    
    if [ ${#base_to_install[@]} -gt 0 ]; then
        # 使用 printf 和 sort -u 安全地去重包名
        local base_pkg_to_install_unique
        base_pkg_to_install_unique=($(printf "%s\n" "${base_pkg_to_install[@]}" | sort -u))
        echo -e "${YELLOW}警告: 检测到以下必需的核心命令缺失: ${base_to_install[*]}${NC}"
        # 显示去重后的包名列表
        read -p "是否尝试自动安装相关软件包 (${base_pkg_to_install_unique[*]})? [Y/n]: " consent
        if [[ "$consent" =~ ^[yY]([eE][sS])?$|^$ ]]; then
            if [ "$DISTRO" == "debian" ]; then
                apt-get update -yq && apt-get install -yq "${base_pkg_to_install_unique[@]}"
            else
                yum install -y "${base_pkg_to_install_unique[@]}"
            fi
            if [ $? -ne 0 ]; then
                echo -e "${RED}核心组件安装失败，脚本无法继续。${NC}"; exit 1
            fi
            hash -r # 刷新bash缓存的命令路径
        else
            echo -e "${RED}用户取消，脚本无法继续。${NC}"; exit 1
        fi
    else
        echo -e "${GREEN}✓ 核心组件检查通过。${NC}"
    fi

    echo "--- 正在执行无人值守环境部署 ---"
    if systemctl is-active --quiet firewalld; then echo -e "${YELLOW}检测到冲突服务 firewalld，正在自动禁用...${NC}"; systemctl stop firewalld; systemctl disable firewalld; systemctl mask firewalld; echo -e "${GREEN}✓ firewalld 已禁用。${NC}"; fi
    local -A deps_debian=( ["iptables"]="command -v iptables" ["conntrack"]="command -v conntrack" ["iproute2"]="command -v ss" ["lsof"]="command -v lsof" ["iptables-persistent"]="systemctl cat netfilter-persistent.service &>/dev/null" ["ipset"]="command -v ipset" ["ipset-persistent"]="dpkg -s ipset-persistent &>/dev/null" ["curl"]="command -v curl" ["ncurses-bin"]="command -v tput" ["dsniff"]="command -v tcpkill" ["coreutils"]="command -v timeout" )
    local -A deps_rhel=( ["iptables"]="command -v iptables" ["conntrack-tools"]="command -v conntrack" ["iproute"]="command -v ss" ["lsof"]="command -v lsof" ["iptables-services"]="systemctl cat iptables.service &>/dev/null" ["ipset"]="command -v ipset" ["ipset-service"]="systemctl cat ipset.service &>/dev/null" ["curl"]="command -v curl" ["ncurses"]="command -v tput" ["dsniff"]="command -v tcpkill" ["coreutils"]="command -v timeout" )
    local to_install=()
    local to_purge=()
    local -n deps_ref="deps_${DISTRO}"
    echo "正在进行功能性健康检查..."
    for pkg in "${!deps_ref[@]}"; do
        local check_cmd=${deps_ref[$pkg]}
        local is_installed=true
        if [ "$DISTRO" == "debian" ]; then dpkg -s "$pkg" &>/dev/null || is_installed=false; else rpm -q "$pkg" &>/dev/null || is_installed=false; fi
        local is_functional=true
        eval "$check_cmd" &>/dev/null || is_functional=false
        if ! $is_installed || ! $is_functional; then
            to_install+=("$pkg")
            if $is_installed && ! $is_functional && [[ "$pkg" == "ipset" ]]; then
                to_purge+=("$pkg")
            fi
        fi
    done
    if [ ${#to_install[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}检测到以下依赖需要安装或修复: ${to_install[*]}${NC}"
        if [ ${#to_purge[@]} -gt 0 ]; then echo -e "${YELLOW}其中，以下软件包将被彻底清除后重装以进行修复: ${to_purge[*]}${NC}"; fi
        echo -e "${BLUE}脚本将自动执行所有修复操作，请稍候...${NC}"; sleep 2
        if [ ${#to_purge[@]} -gt 0 ]; then
            echo "正在彻底清除损坏的软件包..."
            if [ "$DISTRO" == "debian" ]; then apt-get purge -y "${to_purge[@]}"; else dnf remove -y "${to_purge[@]}"; fi
        fi
        if [[ " ${to_install[*]} " =~ " iptables-persistent " ]]; then
            if [ ! -f "$RULES_FILE_V4" ]; then mkdir -p "$(dirname "$RULES_FILE_V4")"; iptables-save > "$RULES_FILE_V4"; fi
            if [ ! -f "$RULES_FILE_V6" ]; then mkdir -p "$(dirname "$RULES_FILE_V6")"; ip6tables-save > "$RULES_FILE_V6"; fi
            echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
            echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
        fi
        echo "正在以无人值守模式安装/重装依赖..."
        export DEBIAN_FRONTEND=noninteractive
        if [ "$DISTRO" == "debian" ]; then
            apt-get update -yq && apt-get install --reinstall -yq --no-install-recommends "${to_install[@]}"
        else
            local PKG_CMD="yum"
            if command -v dnf &>/dev/null; then PKG_CMD="dnf"; fi
            if [[ " ${to_install[*]} " =~ " dsniff " ]]; then $PKG_CMD install -y epel-release; fi
            $PKG_CMD reinstall -y "${to_install[@]}" || $PKG_CMD install -y "${to_install[@]}"
        fi
        if [ $? -eq 0 ]; then echo -e "${GREEN}✓ 依赖包处理成功。${NC}"; hash -r; else echo -e "${RED}✗ 依赖包处理失败！${NC}"; exit 1; fi
    fi
    if [ "$DISTRO" == "rhel" ]; then
        systemctl enable --now iptables.service &>/dev/null
        systemctl enable --now ip6tables.service &>/dev/null
        systemctl enable --now ipset.service &>/dev/null
    elif [ "$DISTRO" == "debian" ]; then
        systemctl enable --now netfilter-persistent.service &>/dev/null
    fi
    echo -e "${GREEN}✓ 系统环境已部署完毕。${NC}"; echo "------------------------------------"; sleep 1
}

function save_rules_auto() { local rules_file_path=$RULES_FILE; if [ -f /etc/redhat-release ]; then rules_file_path=$RULES_FILE_RHEL; fi; local save_cmd_status=1; if [ -f /etc/debian_version ] && command -v netfilter-persistent &> /dev/null; then netfilter-persistent save &>/dev/null; save_cmd_status=$?; elif [ -f /etc/redhat-release ]; then if grep -qE 'release 7\.' /etc/redhat-release && command -v service &>/dev/null; then service "$SAVE_SERVICE_NAME" save &>/dev/null; save_cmd_status=$?; else "$IPTABLES_CMD-save" > "$rules_file_path"; save_cmd_status=$?; fi; else "$IPTABLES_CMD-save" > "$rules_file_path"; save_cmd_status=$?; fi; if [ $save_cmd_status -ne 0 ]; then echo -e "${RED}✗ IPTables 规则保存失败！${NC}"; fi; }
function save_ipsets_auto() { if ! command -v ipset &>/dev/null; then echo -e "${RED}✗ 'ipset' 命令未找到，无法保存 IPSet 规则！${NC}"; return 1; fi; if [ -f /etc/redhat-release ]; then service ipset save &>/dev/null; if [ $? -ne 0 ]; then echo -e "${RED}✗ IPSet 规则保存失败 (RHEL)！${NC}"; fi; else mkdir -p /etc/iptables; ipset save > /etc/iptables/ipsets; if [ $? -ne 0 ]; then echo -e "${RED}✗ IPSet 规则显式保存至 /etc/iptables/ipsets 失败！${NC}"; fi; fi; }
function save_all_rules() { save_ipsets_auto; save_rules_auto; echo -e "${GREEN}✓ 所有防火墙规则 (IPTables + IPSet) 均已尝试保存。${NC}"; }

function flush_connections_safely() {
    echo -e "\n${YELLOW}正在清除已建立的连接 (保留当前SSH会话)...${NC}"

    # --- 步骤 1: 获取需要保护的 SSH 端口 ---
    local ssh_port
    ssh_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}' | head -n1)
    if [[ -z "$ssh_port" ]]; then
        ssh_port=$(ss -tn | grep -F "ESTAB" | grep -F "$(echo "$SSH_CONNECTION" | awk '{print $1}')" | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1)
    fi

    if [[ -n "$ssh_port" ]]; then
        read -p "脚本自动检测到需要保护的SSH端口为 [${YELLOW}${ssh_port}${NC}]，正确吗? (回车确认 / 或输入正确端口号): " manual_port
        if [[ -n "$manual_port" ]]; then
            if [[ "$manual_port" =~ ^[0-9]+$ && "$manual_port" -ge 1 && "$manual_port" -le 65535 ]]; then
                echo -e "${GREEN}✓ SSH保护端口已更新为: ${manual_port}${NC}"
                ssh_port="$manual_port"
            else
                echo -e "${RED}输入的端口无效，将继续使用自动检测的端口: ${ssh_port}${NC}"
            fi
        fi
    fi

    if [[ -z "$ssh_port" ]]; then
        echo -e "${RED}无法确定当前 SSH 会话端口，操作中止以确保安全。${NC}"
        return
    fi
    
    # --- 步骤 2: [tcpkill 终极方案] 清理 Docker 映射端口的连接 ---
    if command -v docker &>/dev/null && systemctl is-active --quiet docker &>/dev/null; then
        if ! command -v tcpkill >/dev/null 2>&1; then
            echo -e "${YELLOW}警告: 'tcpkill' 命令未找到，无法执行 Docker 连接清理。请尝试安装 'dsniff' 包。${NC}"
        else
            echo -e "${CYAN}正在扫描并使用 tcpkill 强行清除 Docker 容器的外部连接...${NC}"
            
            local docker_ports
            docker_ports=$(docker ps --format '{{.Ports}}' | awk '/->/ && /tcp/ {gsub(/.*:/, ""); gsub(/->.*/, ""); print}' | sort -un)
            
            if [[ -n "$docker_ports" ]]; then
                local cleared_count=0
                for port in $docker_ports; do
                    if [[ "$port" -ne "$ssh_port" ]]; then
                        echo -e "${BLUE} -> 正在对端口 ${port} 执行 tcpkill (全接口监听, 持续2秒)...${NC}"
                        # 使用 -i any 强制监听所有接口，确保捕捉到 docker0 上的流量
                        timeout 2 tcpkill -i any -9 port "$port" >/dev/null 2>&1 &
                        cleared_count=$((cleared_count + 1))
                    else
                        echo -e "${YELLOW} -> 正在保护 SSH 端口 ($port)，跳过清理。${NC}"
                    fi
                done
                # 等待所有后台的 tcpkill 进程结束
                if [ $cleared_count -gt 0 ]; then
                    sleep 2
                    echo -e "${GREEN}✓ 已尝试使用 tcpkill 清理 ${cleared_count} 个 Docker 相关端口的连接。${NC}"
                fi
            fi
        fi
    fi

    # --- 步骤 3: 使用 conntrack 清理其余非 Docker 和非 SSH 连接 (作为补充) ---
    if command -v conntrack &>/dev/null; then
        conntrack -D -p tcp --dport-neq "$ssh_port" &>/dev/null
        conntrack -D -p udp &>/dev/null
    fi
    echo -e "${GREEN}✓ 主机连接清理操作已完成。${NC}"
}


function start_firewall() {
    # --- START of new code ---
    clear
    echo -e "\n${RED}*** 警告 ***${NC}"
    echo -e "${YELLOW}此操作将彻底清除当前 ${IP_VERSION} 的所有 IPTables 规则和相关 IPSet，"
    echo -e "并将其重置为一个预设的安全默认结构（INPUT/FORWARD 策略为 DROP）。"
    echo -e "所有现有连接将被中断，Docker 服务将会重启。"
    echo -e "这是一个高风险操作，请确认您了解其后果。${NC}"
    read -p "请输入 'yes' 以确认执行重置操作: " confirm_reset

    if [[ "$confirm_reset" != "yes" ]]; then
        echo -e "\n${GREEN}操作已取消。防火墙未作任何更改。${NC}"
        return
    fi
    # --- END of new code ---

      echo -e "${YELLOW}正在为 ${IP_VERSION} 启动/重置防火墙...${NC}"; echo -e "${BLUE}正在清理所有现存的 IPTables 规则...${NC}"; $IPTABLES_CMD -F; $IPTABLES_CMD -X; $IPTABLES_CMD -Z; echo -e "${GREEN}✓ IPTables 规则已清空。${NC}"; echo -e "${BLUE}正在清理所有由本脚本创建的 IPSet...${NC}"; local sets_to_destroy; sets_to_destroy=($(ipset list 2>/dev/null | grep -oP '^Name: \Kgeo(block|whitelist)_[a-zA-Z0-9_]+')); if [ ${#sets_to_destroy[@]} -gt 0 ]; then for set in "${sets_to_destroy[@]}"; do ipset destroy "$set" &>/dev/null; done; echo -e "${GREEN}✓ 已清理 ${#sets_to_destroy[@]} 个旧的 IPSet。${NC}"; else echo -e "${GREEN}✓ 未发现需要清理的 IPSet。${NC}"; fi; echo -e "${BLUE}正在设置默认策略并创建新的规则链...${NC}"; $IPTABLES_CMD -P INPUT DROP; $IPTABLES_CMD -P FORWARD DROP; $IPTABLES_CMD -P OUTPUT ACCEPT; local chains_to_create=("WHITELIST" "BLACKLIST" "PORT_ALLOW" "PORT_DENY" "GEOBLOCK_IN" "GEOBLOCK_OUT" "GEOWHITELIST_IN" "GEOWHITELIST_OUT"); for chain in "${chains_to_create[@]}"; do $IPTABLES_CMD -N $chain; done; $IPTABLES_CMD -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; $IPTABLES_CMD -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; $IPTABLES_CMD -A INPUT -i lo -j ACCEPT; local ssh_port; ssh_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}' | head -n1); ssh_port=${ssh_port:-22}; if [[ "$IP_VERSION" == "IPv4" ]]; then echo -e "${YELLOW}正在将 SSH 端口 (${ssh_port}) 的放行规则强制插入到安全位置...${NC}"; $IPTABLES_CMD -I INPUT 3 -p tcp --dport "$ssh_port" -j ACCEPT; fi; if [ "$IPTABLES_CMD" == "ip6tables" ]; then echo -e "${YELLOW}正在为 IPv6 添加核心 ICMPv6 规则 (Neighbor Discovery)...${NC}"; $IPTABLES_CMD -A INPUT -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT; $IPTABLES_CMD -A INPUT -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT; $IPTABLES_CMD -A INPUT -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT; $IPTABLES_CMD -A INPUT -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT; fi; echo -e "${BLUE}正在构建优化的规则检查链条 (先拒绝, 后允许)...${NC}"; $IPTABLES_CMD -A INPUT -j WHITELIST; $IPTABLES_CMD -A INPUT -j BLACKLIST; $IPTABLES_CMD -A INPUT -j GEOBLOCK_IN; $IPTABLES_CMD -A INPUT -j GEOWHITELIST_IN; $IPTABLES_CMD -A INPUT -j PORT_ALLOW; $IPTABLES_CMD -A INPUT -j PORT_DENY; $IPTABLES_CMD -A OUTPUT -j GEOBLOCK_OUT; $IPTABLES_CMD -A OUTPUT -j GEOWHITELIST_OUT; echo -e "${GREEN}✓ ${IP_VERSION} 纯净防火墙逻辑已启动 (默认策略: DROP)。${NC}"; save_all_rules; if command -v docker &>/dev/null && systemctl is-active --quiet docker &>/dev/null; then echo -e "${YELLOW}为确保 Docker 网络规则兼容性，正在重启 Docker 服务...${NC}"; systemctl restart docker; echo -e "${GREEN}✓ Docker 服务已重启。${NC}"; fi; flush_connections_safely;
}
function load_or_initialize_firewall() { if [ -f /etc/debian_version ] && command -v netfilter-persistent &>/dev/null; then netfilter-persistent start &>/dev/null; elif [ -f /etc/redhat-release ] && command -v systemctl &>/dev/null; then systemctl is-active --quiet "$SAVE_SERVICE_NAME.service" || systemctl start "$SAVE_SERVICE_NAME.service" &>/dev/null; systemctl is-active --quiet "ipset.service" || systemctl start "ipset.service" &>/dev/null; else local rules_to_load=$RULES_FILE; if [ -f /etc/redhat-release ]; then rules_to_load=$RULES_FILE_RHEL; fi; if [ -f "$rules_to_load" ] && [ -s "$rules_to_load" ]; then "$IPTABLES_CMD-restore" < "$rules_to_load"; fi; fi; if ! $IPTABLES_CMD -L "GEOBLOCK_IN" &>/dev/null || ! $IPTABLES_CMD -L "GEOWHITELIST_IN" &>/dev/null ; then echo -e "${YELLOW}未找到防火墙核心架构，正在初始化...${NC}"; start_firewall; fi; }
function stop_firewall() { echo -e "${YELLOW}正在停止 ${IP_VERSION} 防火墙...${NC}"; $IPTABLES_CMD -F; $IPTABLES_CMD -X; $IPTABLES_CMD -P INPUT ACCEPT; $IPTABLES_CMD -P FORWARD ACCEPT; $IPTABLES_CMD -P OUTPUT ACCEPT; echo -e "${RED}✓ ${IP_VERSION} 防火墙已停止。${NC}"; save_all_rules; flush_connections_safely; }
function show_full_status() { clear; echo -e "${BLUE}--- ${IP_VERSION} 防火墙状态 (filter 表) ---${NC}"; $IPTABLES_CMD -L -v -n --line-numbers; if [[ "$IP_VERSION" == "IPv4" ]]; then echo; echo -e "${BLUE}--- ${IP_VERSION} NAT 表 ---${NC}"; $IPTABLES_CMD -t nat -L -v -n --line-numbers 2>/dev/null || echo -e "${YELLOW}NAT 表不存在或内核不支持。${NC}"; fi; echo "------------------------------------------"; }
function check_icmp_status() {
    # 规则 1: 检查是否存在明确的 ACCEPT 规则。这是最高优先级。
    if $IPTABLES_CMD -C INPUT -p "$ICMP_PROTO" -j ACCEPT &>/dev/null; then
        echo "允许"
    # 规则 2: 检查是否存在明确的 DROP 规则。这是第二优先级。
    # 这里的检查逻辑现在可以覆盖到我们在 ACCEPT 策略下手动添加的 DROP 规则。
    elif $IPTABLES_CMD -C INPUT -p "$ICMP_PROTO" -j DROP &>/dev/null || \
         ( [[ "$ICMP_PROTO" == "icmpv6" ]] && $IPTABLES_CMD -C INPUT -p icmpv6 --icmpv6-type echo-request -j DROP &>/dev/null ); then
        echo "阻止"
    # 规则 3: 如果没有任何明确的允许或阻止规则，再根据默认策略来判断。
    elif $IPTABLES_CMD -L INPUT -n | head -n 1 | grep -q "policy DROP"; then
        echo "阻止"
    # 规则 4: 如果默认策略不是 DROP (那就是 ACCEPT)，且没有其他规则，则为允许。
    else
        echo "允许"
    fi
}
function toggle_icmp() {
    local current_status
    current_status=$(check_icmp_status)
    local rule_pos=4 # 定义一个安全插入位置（通常在 conntrack, lo, ssh 规则之后）

    # 统一清理旧规则：使用 -D (Delete) 可以精确删除，无论规则在哪里
    $IPTABLES_CMD -D INPUT -p "$ICMP_PROTO" -j ACCEPT &>/dev/null
    if [[ "$ICMP_PROTO" == "icmpv6" ]]; then
        $IPTABLES_CMD -D INPUT -p icmpv6 --icmpv6-type echo-request -j DROP &>/dev/null
    else
        $IPTABLES_CMD -D INPUT -p icmp -j DROP &>/dev/null
    fi

    # 根据当前状态，执行相反的操作
    if [ "$current_status" == "允许" ]; then
        # 如果当前是“允许”，则切换为“阻止”
        # 使用 -I (Insert) 插入规则，确保高优先级
        if [[ "$ICMP_PROTO" == "icmpv6" ]]; then
            $IPTABLES_CMD -I INPUT $rule_pos -p icmpv6 --icmpv6-type echo-request -j DROP
        else
            $IPTABLES_CMD -I INPUT $rule_pos -p icmp -j DROP
        fi
        echo -e "${RED}ICMP (Ping) 已被阻止。${NC}"
    else
        # 如果当前是“阻止”，则切换为“允许”
        # 同样使用 -I (Insert) 插入规则，确保它在拦截规则之前被匹配
        $IPTABLES_CMD -I INPUT $rule_pos -p "$ICMP_PROTO" -j ACCEPT
        echo -e "${GREEN}ICMP (Ping) 已被允许。${NC}"
    fi

    save_all_rules
    flush_connections_safely
}
function check_default_policy() { $IPTABLES_CMD -L INPUT -n | head -n 1 | awk -F '[() ]' '{print $5}'; }
function toggle_default_policy() { local current_policy; current_policy=$(check_default_policy); if [[ "$current_policy" == "DROP" ]]; then echo -e "\n${YELLOW}警告: 您正试图将核心策略切换为 'ACCEPT'，这会极大降低安全性。${NC}"; read -p "您确定吗? (请输入 'yes' 确认): " confirm; if [[ "$confirm" == "yes" ]]; then $IPTABLES_CMD -P INPUT ACCEPT; echo -e "\n${GREEN}✓ 防火墙核心策略已切换为 ACCEPT。${NC}"; save_all_rules; flush_connections_safely; else echo -e "\n${GREEN}操作已取消。${NC}"; fi; else $IPTABLES_CMD -P INPUT DROP; echo -e "\n${GREEN}✓ 防火墙核心策略已切换回 DROP。${NC}"; save_all_rules; flush_connections_safely; fi; }

function add_to_list() {
    local list_type=$1; local chain_name=$2; local jump_action=$3
    clear
    echo "======================================================"
    echo "                      新增 IP 到${list_type} (${IP_VERSION})"
    echo "======================================================"
    read -p "请输入要添加到${list_type}的 ${IP_VERSION} IP (单个或CIDR): " ip
    if [[ -z "$ip" ]]; then echo -e "\n${RED}错误：IP 不能为空。${NC}"; return 1; fi
    local valid_format=false
    if [[ "$IP_VERSION" == "IPv4" ]]; then
        local ipv4_regex='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/(3[0-2]|[12]?[0-9]))?$'
        if echo "$ip" | grep -qE "$ipv4_regex"; then valid_format=true; fi
    else
        if [[ "$ip" == *":"* && "$ip" != *" "* ]]; then valid_format=true; fi
    fi
    if ! $valid_format; then echo -e "\n${RED}错误：'${ip}' 格式无效。${NC}"; return 1; fi
    read -p "端口 (单个, 多个80,443, 范围3000:4000) [回车默认所有端口]: " ports
    local rule_added=0
    if [[ -n "$ports" ]]; then
        for proto in tcp udp; do
            local port_param
            if [[ "$ports" == *","* || "$ports" == *":"* ]]; then
                port_param="-m multiport --dports $ports"
            else
                port_param="--dport $ports"
            fi
            if $IPTABLES_CMD -A "$chain_name" -s "$ip" -p "$proto" $port_param -j "$jump_action"; then
                rule_added=$((rule_added+1))
            fi
        done
    else
        if $IPTABLES_CMD -A "$chain_name" -s "$ip" -j "$jump_action"; then
            rule_added=$((rule_added+1))
        fi
    fi
    if [ $rule_added -gt 0 ]; then
        echo -e "\n${GREEN}✓ 规则添加成功。${NC}"
        save_all_rules
        flush_connections_safely
    else
        echo -e "\n${RED}✗ 添加规则失败！${NC}"
        return 1
    fi
}

function manage_port_rule() {
    local chain=$1; local action=$2; local action_text=$3
    clear
    echo "======================================================"
    echo "                      新增 [端口${action_text}] 规则 (${IP_VERSION})"
    echo "======================================================"
    read -p "源 IP (留空则所有): " ip
    read -p "协议: 1.TCP 2.UDP 3.两者 [回车默认为 3]: " proto_choice
    local protos=()
    case $proto_choice in
        1) protos=("tcp");;
        2) protos=("udp");;
        ""|3) protos=("tcp" "udp");;
        *) echo -e "${RED}无效选择。${NC}"; return;;
    esac
    read -p "端口(可输入单个80, 多个80,443, 或范围3000:4000): " port
    if [[ -z "$port" ]]; then echo -e "${RED}端口不能为空。${NC}"; return; fi
    local rules_added_count=0
    for proto in "${protos[@]}"; do
        local rule_added=false
        local rule_base="$IPTABLES_CMD -A \"$chain\" ${ip:+-s \"$ip\"} -p \"$proto\""
        local rule_final=""
        if [[ "$port" == *":"* ]]; then
            rule_final="$rule_base -m multiport --dports \"$port\" -j \"$action\""
        elif [[ "$port" == *","* ]]; then
            rule_final="$rule_base -m multiport --dports \"$port\" -j \"$action\""
        else
            rule_final="$rule_base --dport \"$port\" -j \"$action\""
        fi
        
        if eval "$rule_final"; then
            rule_added=true
            rules_added_count=$((rules_added_count+1))
        fi
    done
    
    if [ $rules_added_count -gt 0 ]; then
        echo -e "\n${GREEN}✓ ${rules_added_count} 条规则已成功添加。${NC}"
        save_all_rules
        flush_connections_safely
    else
        echo -e "\n${RED}✗ 添加规则失败。${NC}"
    fi
}

function interactive_delete_rule() { while true; do clear; declare -a rule_map; local i=1; echo "--- 可删除规则 ---"; local chains_to_scan=("WHITELIST" "BLACKLIST" "PORT_ALLOW" "PORT_DENY"); for chain in "${chains_to_scan[@]}"; do if ! $IPTABLES_CMD -L "$chain" -n | grep -q '^[0-9A-Z]'; then continue; fi; echo -e "\n${BLUE}[$chain] 链:${NC}"; local rules_output; rules_output=$($IPTABLES_CMD -L "$chain" -v -n --line-numbers | tail -n +3); while IFS= read -r line; do if [[ -z "$line" ]]; then continue; fi; printf " %-4s -> %s\n" "$i" "$(echo "$line" | sed -r 's/^[0-9]+\s+//')"; rule_map[$i]="$chain $(echo "$line" | awk '{print $1}')"; i=$((i+1)); done <<< "$rules_output"; done; if [ $i -eq 1 ]; then echo -e "${YELLOW}无规则可删。${NC}"; read -n 1 -s -r -p "按键返回..."; break; fi; read -p "输入编号删除 (q退出): " choice; case $choice in q|Q) break ;; ''|*[!0-9]*) echo -e "${RED}无效。${NC}"; sleep 1; continue ;; *) if [ "$choice" -ge 1 ] && [ "$choice" -lt $i ]; then local details=${rule_map[$choice]}; local chain_to_del=$(echo "$details" | awk '{print $1}'); local line_to_del=$(echo "$details" | awk '{print $2}'); $IPTABLES_CMD -D "$chain_to_del" "$line_to_del"; save_all_rules; flush_connections_safely; else echo -e "${RED}无效编号。${NC}"; sleep 1; fi; esac; done; }
function add_geo_rule() { local type=$1; local action=$2; local chain_prefix=$3; local type_text=$4; clear; echo "======================================================"; echo "                                 按国家代码添加IP${type_text}规则 (${IP_VERSION})"; echo "======================================================"; read -p "请输入要${type_text}国家的两位字母代码 (例如 CN, US, RU): " country_code; country_code=$(echo "$country_code"|tr 'a-z' 'A-Z'); if ! [[ "$country_code" =~ ^[A-Z]{2}$ ]]; then echo -e "${RED}错误：国家代码必须是两位字母。${NC}"; return 1; fi; echo "请选择流量方向:"; echo " 1. ${type_text}入站 (INPUT)"; echo " 2. ${type_text}出站 (OUTPUT)"; echo " 3. 入站和出站 (BOTH)"; read -p "请输入选择 [回车默认为 3]: " direction_choice; local directions=(); case $direction_choice in 1) directions=("IN");; 2) directions=("OUT");; ""|3) directions=("IN" "OUT");; *) echo -e "${RED}无效选择。${NC}"; return 1 ;; esac; echo "请选择协议:"; echo " 1. TCP"; echo " 2. UDP"; echo " 3. TCP 和 UDP (ALL)"; read -p "请输入选择 [回车默认为 3]: " proto_choice; local proto_name; case $proto_choice in 1) proto_name="TCP";; 2) proto_name="UDP";; ""|3) proto_name="ALL";; *) echo -e "${RED}无效选择。${NC}"; return 1 ;; esac; read -p "端口 (单个, 多个80,443, 范围3000:4000) [回车默认所有端口]: " ports; local default_url; local ipset_family_param=""; if [[ "$IP_VERSION" == "IPv6" ]]; then default_url="https://www.ipdeny.com/ipv6/ipaddresses/blocks/${country_code,,}.zone"; ipset_family_param="family inet6"; else default_url="https://www.ipdeny.com/ipblocks/data/countries/${country_code,,}.zone"; fi; read -p "请输入 IP 列表下载地址 [默认: ${default_url}]: " custom_url; local download_url=${custom_url:-$default_url}; echo -e "${BLUE}正在从 ${download_url} 下载 IP 列表...${NC}"; local ip_list_file; ip_list_file=$(mktemp); if ! curl -sL --connect-timeout 10 "$download_url" -o "$ip_list_file" || ! [ -s "$ip_list_file" ]; then echo -e "${RED}下载 IP 列表失败！请检查国家代码、URL 或服务器网络连接。${NC}"; rm -f "$ip_list_file"; return 1; fi; echo -e "${GREEN}✓ IP 列表下载成功。${NC}"; for direction in "${directions[@]}"; do local chain_name="${chain_prefix}_${direction}"; local ip_match_dir; if [[ "$direction" == "IN" ]]; then ip_match_dir="src"; else ip_match_dir="dst"; fi; local set_name="${type}_${IP_VERSION}_${direction}_${proto_name}_${country_code}"; echo -e "\n${BLUE}--- 正在处理方向: ${direction} | 集合: ${set_name} ---${NC}"; if ipset list "$set_name" &>/dev/null; then echo -e "${YELLOW}IPSet '${set_name}' 已存在，将清空并重新加载。${NC}"; ipset flush "$set_name"; else echo "正在创建新的 IPSet: ${set_name}..."; ipset create "$set_name" hash:net $ipset_family_param maxelem 1000000; if [ $? -ne 0 ]; then echo -e "${RED}创建 IPSet 失败!${NC}"; continue; fi; fi; echo "正在将 IP 列表高效导入 IPSet..."; local restore_file; restore_file=$(mktemp); awk -v set_name="$set_name" '{print "add " set_name " " $1}' "$ip_list_file" > "$restore_file"; ipset restore < "$restore_file"; rm -f "$restore_file"; local rule_added=0; if [[ -n "$ports" ]]; then local protos_to_apply=(); if [[ "$proto_name" == "ALL" ]]; then protos_to_apply=("tcp" "udp"); else protos_to_apply=("$proto_name"); fi; for proto in "${protos_to_apply[@]}"; do local port_param; if [[ "$ports" == *","* || "$ports" == *":"* ]]; then port_param="-m multiport --dports $ports"; else port_param="--dport $ports"; fi; if $IPTABLES_CMD -A "$chain_name" -p "$proto" $port_param -m set --match-set "$set_name" "$ip_match_dir" -j "$action"; then rule_added=$((rule_added+1)); fi; done; else local protos_to_apply=(); local proto_params=(); if [[ "$proto_name" == "ALL" ]]; then protos_to_apply=("tcp" "udp"); proto_params=("-p tcp" "-p udp"); else protos_to_apply=("$proto_name"); proto_params=("-p ${proto_name,,}"); fi; for proto_param in "${proto_params[@]}"; do if $IPTABLES_CMD -A "$chain_name" $proto_param -m set --match-set "$set_name" "$ip_match_dir" -j "$action"; then rule_added=$((rule_added+1)); fi; done; if [ $rule_added -eq 0 ]; then if $IPTABLES_CMD -A "$chain_name" -m set --match-set "$set_name" "$ip_match_dir" -j "$action"; then rule_added=$((rule_added+1)); fi; fi; fi; if [ $rule_added -gt 0 ]; then echo -e "${GREEN}✓ 已成功添加并启用对 ${country_code} 的${type_text}规则。${NC}"; else echo -e "${RED}✗ 添加 IPTables 规则失败。${NC}"; fi; done; rm -f "$ip_list_file"; save_all_rules; flush_connections_safely; }
function add_custom_geo_rule() { local type=$1; local action=$2; local chain_prefix=$3; local type_text=$4; clear; echo "======================================================"; echo "                                 添加自定义IP列表${type_text}规则 (${IP_VERSION})"; echo "======================================================"; local custom_name; read -p "请输入自定义名称 (仅限字母数字, 如 MyBlocklist): " custom_name; if ! [[ "$custom_name" =~ ^[a-zA-Z0-9]+$ ]]; then echo -e "${RED}错误：自定义名称格式无效。${NC}"; return 1; fi; local download_url; read -p "请输入IP列表的完整下载URL: " download_url; if [[ -z "$download_url" ]]; then echo -e "${RED}错误：下载地址不能为空。${NC}"; return 1; fi; echo "请选择流量方向:"; echo " 1. ${type_text}入站 (INPUT)"; echo " 2. ${type_text}出站 (OUTPUT)"; echo " 3. 入站和出站 (BOTH)"; read -p "请输入选择 [回车默认为 3]: " direction_choice; local directions=(); case $direction_choice in 1) directions=("IN");; 2) directions=("OUT");; ""|3) directions=("IN" "OUT");; *) echo -e "${RED}无效选择。${NC}"; return 1 ;; esac; read -p "请选择协议: 1.TCP 2.UDP 3.两者 [回车默认为 3]: " proto_choice; local proto_name; case $proto_choice in 1) proto_name="TCP";; 2) proto_name="UDP";; ""|3) proto_name="ALL";; *) echo -e "${RED}无效选择。${NC}"; return 1 ;; esac; read -p "端口 (单个, 多个80,443, 范围3000:4000) [回车默认所有端口]: " ports; local ipset_family_param=""; if [[ "$IP_VERSION" == "IPv6" ]]; then ipset_family_param="family inet6"; fi; echo -e "${BLUE}正在从 ${download_url} 下载 IP 列表...${NC}"; local ip_list_file; ip_list_file=$(mktemp); if ! curl -sL --connect-timeout 10 "$download_url" -o "$ip_list_file" || ! [ -s "$ip_list_file" ]; then echo -e "${RED}下载 IP 列表失败！${NC}"; rm -f "$ip_list_file"; return 1; fi; echo -e "${GREEN}✓ IP 列表下载成功。${NC}"; for direction in "${directions[@]}"; do local chain_name="${chain_prefix}_${direction}"; local ip_match_dir; if [[ "$direction" == "IN" ]]; then ip_match_dir="src"; else ip_match_dir="dst"; fi; local set_name="${type}_${IP_VERSION}_${direction}_${proto_name}_${custom_name}"; echo -e "\n${BLUE}--- 正在处理方向: ${direction} | 集合: ${set_name} ---${NC}"; if ipset list "$set_name" &>/dev/null; then echo -e "${YELLOW}IPSet '${set_name}' 已存在，将清空并重新加载。${NC}"; ipset flush "$set_name"; else echo "正在创建新的 IPSet: ${set_name}..."; ipset create "$set_name" hash:net $ipset_family_param maxelem 1000000; if [ $? -ne 0 ]; then echo -e "${RED}创建 IPSet 失败!${NC}"; continue; fi; fi; echo "正在将 IP 列表高效导入 IPSet..."; local restore_file; restore_file=$(mktemp); awk -v set_name="$set_name" '{print "add " set_name " " $1}' "$ip_list_file" > "$restore_file"; ipset restore < "$restore_file"; rm -f "$restore_file"; local rule_added=0; if [[ -n "$ports" ]]; then local protos_to_apply=(); if [[ "$proto_name" == "ALL" ]]; then protos_to_apply=("tcp" "udp"); else protos_to_apply=("$proto_name"); fi; for proto in "${protos_to_apply[@]}"; do local port_param; if [[ "$ports" == *","* || "$ports" == *":"* ]]; then port_param="-m multiport --dports $ports"; else port_param="--dport $ports"; fi; if $IPTABLES_CMD -A "$chain_name" -p "$proto" $port_param -m set --match-set "$set_name" "$ip_match_dir" -j "$action"; then rule_added=$((rule_added+1)); fi; done; else local protos_to_apply=(); local proto_params=(); if [[ "$proto_name" == "ALL" ]]; then protos_to_apply=("tcp" "udp"); proto_params=("-p tcp" "-p udp"); else protos_to_apply=("$proto_name"); proto_params=("-p ${proto_name,,}"); fi; for proto_param in "${proto_params[@]}"; do if $IPTABLES_CMD -A "$chain_name" $proto_param -m set --match-set "$set_name" "$ip_match_dir" -j "$action"; then rule_added=$((rule_added+1)); fi; done; if [ $rule_added -eq 0 ]; then if $IPTABLES_CMD -A "$chain_name" -m set --match-set "$set_name" "$ip_match_dir" -j "$action"; then rule_added=$((rule_added+1)); fi; fi; fi; if [ $rule_added -gt 0 ]; then echo -e "${GREEN}✓ 已成功添加并启用对 ${custom_name} 的${type_text}规则。${NC}"; else echo -e "${RED}✗ 添加 IPTables 规则失败。${NC}"; fi; done; rm -f "$ip_list_file"; save_all_rules; flush_connections_safely; }
function view_delete_geo_rules() { local type=$1; local type_text=$2; while true; do clear; echo "--- 管理 ${IP_VERSION} IP ${type_text}规则 ---"; local sets; sets=($(ipset list 2>/dev/null | grep -oP "^Name: \K${type}_${IP_VERSION}_\w+")); if [ ${#sets[@]} -eq 0 ]; then echo -e "${YELLOW}当前无 ${IP_VERSION} IP ${type_text}规则。${NC}"; read -n 1 -s -r -p "按任意键返回..."; return; fi; echo -e "${BLUE}当前规则:${NC}"; echo "-----------------------------------------------------------------"; printf " %-4s | %-15s | %-4s | %-4s | %s\n" "编号" "名称/代码" "方向" "协议" "条目数"; echo "-----------------------------------------------------------------"; local i=1; declare -a map; for set in "${sets[@]}"; do map[$i]=$set; local parts; IFS='_' read -r -a parts <<< "$set"; local dir=${parts[2]}; local proto=${parts[3]}; local name_code=${parts[4]}; local members=$(ipset list "$set" 2>/dev/null | grep -c '^[0-9]'); printf " %-4s | %-15s | %-4s | %-4s | %s\n" "$i" "$name_code" "$dir" "$proto" "$members"; i=$((i+1)); done; echo "-----------------------------------------------------------------"; read -p "请输入要删除的规则编号 (或 'q' 退出): " choice; if [[ "$choice" == "q" || "$choice" == "Q" ]]; then break; fi; if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge $i ]; then echo -e "${RED}无效编号。${NC}"; sleep 1; continue; fi; local set_to_del=${map[$choice]}; echo -e "\n${YELLOW}正在删除与 '${set_to_del}' 相关的规则...${NC}"; echo "正在扫描并删除关联的防火墙规则..."; local found=0; for cmd in iptables ip6tables; do if ! command -v "$cmd" &>/dev/null; then continue; fi; while IFS= read -r rule; do if [[ -z "$rule" ]]; then continue; fi; local spec=$(echo "$rule" | sed 's/^-A //'); echo "  -> 正在删除: ($cmd) -D ${spec}"; $cmd -D ${spec} &>/dev/null; found=$((found + 1)); done <<< "$($cmd -S | grep -- "--match-set ${set_to_del}")"; done; if [ $found -gt 0 ]; then echo "✓ 已找到并删除 ${found} 条关联的防火墙规则。"; echo "正在保存已更新的 IPTables 规则集..."; save_rules_auto; else echo "✓ 未找到关联的防火墙规则。"; fi; echo "正在销毁 IPSet '${set_to_del}'..."; if ipset destroy "$set_to_del" &>/dev/null; then echo "✓ IPSet 已成功销毁。"; echo "正在保存已更新的 IPSet 配置..."; save_ipsets_auto; else echo -e "${RED}✗ 销毁 IPSet 失败!${NC}"; echo -e "${YELLOW}这通常意味着该 IPSet 仍被某条（可能是您手动添加的）防火墙规则所引用。${NC}"; echo -e "${YELLOW}请手动检查 'iptables-save' 的输出并移除相关规则后重试。${NC}"; fi; echo -e "${GREEN}操作完成！${NC}"; flush_connections_safely; sleep 3; done; }
function manage_geoip() { while true; do clear; echo "--- IP 封锁管理 (Geo-IP & Custom) ---"; echo " 1. 按国家代码添加规则"; echo " 2. 添加自定义规则 (自定义名称+URL)"; echo " 3. 查看/删除当前模式 (${IP_VERSION}) 的规则"; echo "-----------------------------------"; echo " q. 返回主菜单"; read -p "请输入您的选择: " choice; case $choice in 1) add_geo_rule "geoblock" "DROP" "GEOBLOCK" "封锁" ;; 2) add_custom_geo_rule "geoblock" "DROP" "GEOBLOCK" "封锁" ;; 3) view_delete_geo_rules "geoblock" "封锁" ;; q|Q) break ;; *) echo -e "${RED}无效选择。${NC}"; sleep 1 ;; esac; done; }
function manage_geowhitelist() { while true; do clear; echo "--- IP 许可管理 (Geo-IP & Custom) ---"; echo " 1. 按国家代码添加规则"; echo " 2. 添加自定义规则 (自定义名称+URL)"; echo " 3. 查看/删除当前模式 (${IP_VERSION}) 的规则"; echo "-----------------------------------"; echo " q. 返回主菜单"; read -p "请输入您的选择: " choice; case $choice in 1) add_geo_rule "geowhitelist" "ACCEPT" "GEOWHITELIST" "许可" ;; 2) add_custom_geo_rule "geowhitelist" "ACCEPT" "GEOWHITELIST" "许可" ;; 3) view_delete_geo_rules "geowhitelist" "许可" ;; q|Q) break ;; *) echo -e "${RED}无效选择。${NC}"; sleep 1 ;; esac; done; }

# ======================================================================
#  Docker 网络管理模块 (v36.0 - 简体中文 & 自动修复 & DOCKER-USER 兼容版)
# ======================================================================
function docker_init_chain() { local IPTABLES="iptables-legacy"; local CHAIN_NAME="DOCKER_NET_POLICY"; $IPTABLES -N $CHAIN_NAME 2>/dev/null; if ! $IPTABLES -L DOCKER-USER >/dev/null 2>&1; then echo -e "${RED}错误：未找到 Docker 核心链 DOCKER-USER，请确保 Docker 服务正常运行！${NC}"; return 1; fi; if ! $IPTABLES -C DOCKER-USER -j $CHAIN_NAME >/dev/null 2>&1; then echo -e "${BLUE}[+] 正在将 ${CHAIN_NAME} 挂载到 Docker 官方链 (DOCKER-USER)...${NC}"; $IPTABLES -I DOCKER-USER 1 -j $CHAIN_NAME; fi; return 0; }
function docker_select_container() { local DOCKER_CMD; DOCKER_CMD=$(command -v docker); local -a container_ids container_names; mapfile -t container_ids < <($DOCKER_CMD ps --format "{{.ID}}"); mapfile -t container_names < <($DOCKER_CMD ps --format "{{.Names}}"); if [ ${#container_ids[@]} -eq 0 ]; then echo -e "${YELLOW}⚠ 没有侦测到正在运行的容器，请先启动容器再试。${NC}" >&2; return 1; fi; echo "--------------------------------------" >&2; echo "--- 请选择要操作的容器 ---" >&2; for ((i=0; i<${#container_ids[@]}; i++)); do printf " %2d) %-20s ${CYAN}[%s]${NC}\n" "$((i+1))" "${container_names[$i]}" "${container_ids[$i]:0:12}" >&2; done; echo "--------------------------------------" >&2; local choice; read -p "请输入编号: " choice; if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#container_ids[@]} ]; then echo -e "${RED}无效选择!${NC}" >&2; return 1; fi; echo "${container_ids[$((choice-1))]}""_""${container_names[$((choice-1))]}"; return 0; }
function docker_add_rule() { local IPTABLES="iptables-legacy"; local CHAIN_NAME="DOCKER_NET_POLICY"; local DOCKER_CMD; DOCKER_CMD=$(command -v docker); local action=$1; local action_color="${GREEN}"; if [[ "$action" == "DROP" ]]; then action_color="${RED}"; fi; local container_info; container_info=$(docker_select_container) || return; local cid="${container_info%_*}"; local cname="${container_info#*_}"; local all_ips; readarray -t all_ips < <($DOCKER_CMD inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$cid" | xargs -n1); local ip=""; if [ ${#all_ips[@]} -eq 0 ]; then echo -e "${RED}⚠ 无法获取容器 ${cname} 的 IP 地址。${NC}"; return 1; elif [ ${#all_ips[@]} -eq 1 ]; then ip="${all_ips[0]}"; else clear; echo -e "${YELLOW}检测到容器 ${cname} 拥有多个 IP 地址。${NC}"; echo "请选择一个用于创建防火墙规则的 IP:"; local i=1; for item_ip in "${all_ips[@]}"; do echo " ${i}) ${item_ip}"; i=$((i+1)); done; read -p "请输入编号: " ip_choice; if ! [[ "$ip_choice" =~ ^[0-9]+$ ]] || [ "$ip_choice" -lt 1 ] || [ "$ip_choice" -gt ${#all_ips[@]} ]; then echo -e "${RED}无效选择!${NC}"; return 1; fi; ip="${all_ips[$((ip_choice-1))]}"; fi; echo -e "${BLUE}已选择容器: ${YELLOW}${cname}${NC} (策略将应用于 IP: ${CYAN}${ip}${NC})"; local direction dir_tag; echo "请选择策略的流量方向:"; echo " 1. 入站 (外部网络访问此容器)"; echo " 2. 出站 (此容器访问外部网络)"; read -p "请输入选择 [回车默认为 所有方向]: " direction; local rule_part_s rule_part_d; case "$direction" in 1) dir_tag="IN" ;; 2) dir_tag="OUT" ;; "") dir_tag="ALL" ;; *) echo -e "${RED}无效的方向选择。${NC}"; return 1 ;; esac; read -p "请输入远程IP (单个或CIDR, 留空则为 'any'): " remote_ip; remote_ip=${remote_ip:-"0.0.0.0/0"}; read -p "目标端口 (单个, 逗号分隔或范围, 留空则为 'all'): " ports; ports=${ports:-"all"}; local proto_choice proto; echo "协议选择: 1=TCP, 2=UDP, [回车默认为 ALL]"; read -p "请选择协议: " proto_choice; case "$proto_choice" in 1) proto="tcp" ;; 2) proto="udp" ;; *) proto="all" ;; esac; local rules_to_add=(); if [[ "$dir_tag" == "IN" || "$dir_tag" == "ALL" ]]; then rules_to_add+=("-s ${remote_ip} -d ${ip}"); fi; if [[ "$dir_tag" == "OUT" || "$dir_tag" == "ALL" ]]; then rules_to_add+=("-s ${ip} -d ${remote_ip}"); fi; local rule_added_count=0; for base_rule in "${rules_to_add[@]}"; do local rule="$base_rule"; [ "$proto" != "all" ] && rule="$rule -p $proto"; if [ "$ports" != "all" ]; then if [ "$proto" = "all" ]; then echo -e "${YELLOW}⚠ 必须选择特定协议 (TCP/UDP) 才能限制端口，已跳过此条规则。${NC}" >&2; continue; fi; if [[ "$ports" == *","* ]]; then rule="$rule -m multiport --dports $ports"; elif [[ "$ports" == *":"* ]]; then rule="$rule -m multiport --dports $ports"; else rule="$rule --dport $ports"; fi; fi; local effective_dir_tag=""; if [[ "$base_rule" == *"-d ${ip}"* ]]; then effective_dir_tag="IN"; else effective_dir_tag="OUT"; fi; local comment="docker:${effective_dir_tag}:${cname}(${cid:0:12})"; if $IPTABLES -A $CHAIN_NAME $rule -j $action -m comment --comment "$comment"; then echo -e "${GREEN}✓ 已添加 ${action_color}${action}${NC} 策略: ${rule} --comment ${comment}${NC}"; rule_added_count=$((rule_added_count + 1)); else echo -e "${RED}[!] 添加策略失败: ${rule}${NC}"; fi; done; if [ $rule_added_count -gt 0 ]; then save_all_rules; flush_connections_safely; fi; }
function docker_show_rules() { local IPTABLES="iptables-legacy"; local CHAIN_NAME="DOCKER_NET_POLICY"; clear; echo "======================================================"; echo -e "                         ${CYAN}当前 Docker 防火墙策略 (${CHAIN_NAME})${NC}"; echo "======================================================"; $IPTABLES -L $CHAIN_NAME -n --line-numbers -v; echo "======================================================"; }
function docker_delete_rule() { local IPTABLES="iptables-legacy"; local CHAIN_NAME="DOCKER_NET_POLICY"; docker_show_rules; local rule_count; rule_count=$($IPTABLES -L $CHAIN_NAME -n --line-numbers 2>/dev/null | sed '1,2d' | wc -l); if [ "$rule_count" -eq 0 ]; then echo -e "\n${YELLOW}当前没有任何规则可删除。${NC}"; return; fi; echo " a) 删除此链中的全部规则"; read -p "请输入要删除的规则编号 (或 a): " num; if [[ "$num" == "a" || "$num" == "A" ]]; then $IPTABLES -F $CHAIN_NAME; echo -e "${GREEN}[✓] 已清空 ${CHAIN_NAME} 链的所有规则。${NC}"; save_all_rules; flush_connections_safely; else local total_lines_for_check; total_lines_for_check=$($IPTABLES -S $CHAIN_NAME 2>/dev/null | wc -l); if ! [[ "$num" =~ ^[0-9]+$ ]] || [ "$num" -lt 1 ] || [ "$num" -gt "$total_lines_for_check" ]; then echo -e "${RED}⚠ 无效的规则编号！${NC}"; return 1; fi; if $IPTABLES -D $CHAIN_NAME "$num"; then echo -e "${GREEN}[✓] 已删除规则 ${num}。${NC}"; save_all_rules; flush_connections_safely; else echo -e "${RED}[!] 删除规则 ${num} 失败！${NC}"; fi; fi; }
function manage_docker_menu() { if [[ "$IP_VERSION" != "IPv4" ]]; then echo -e "${RED}错误: Docker 网络管理目前仅在 IPv4 模式下受支持。${NC}"; sleep 2; return; fi; if ! command -v iptables-legacy >/dev/null 2>&1; then echo -e "${RED}错误: 此模块需要 'iptables-legacy'，但命令未找到。${NC}"; sleep 3; return; fi; if ! command -v docker >/dev/null 2>&1; then echo -e "${RED}错误：无法在您的 PATH 中找到 'docker' 命令。${NC}"; sleep 3; return 1; fi; if ! iptables-legacy-save | grep -q -- "-A FORWARD -j DOCKER-USER"; then clear; echo -e "${RED}======================================================${NC}"; echo -e "${YELLOW}                               警告：侦测到 Docker 的核心防火墙规则丢失！${NC}"; echo -e "${RED}======================================================${NC}"; echo; echo -e "${BLUE}正在尝试自动修复 (重启 Docker 服务)...${NC}"; systemctl restart docker; sleep 3; if iptables-legacy-save | grep -q -- "-A FORWARD -j DOCKER-USER"; then echo -e "${GREEN}✓ 自动修复成功！Docker 网络规则已恢复。${NC}"; sleep 2; else echo -e "${RED}✗ 自动修复失败！Docker 服务重启后规则依然缺失。${NC}"; echo -e "${YELLOW}请退出本脚本，手动检查 Docker 服务状态及系统 iptables 版本设置。${NC}"; read -n 1 -s -r -p "按任意键返回主菜单..."; return; fi; fi; set -o pipefail; if ! docker_init_chain; then sleep 3; return; fi; while true; do clear; echo "======================================"; echo -e "                         ${CYAN}Docker 网络防火墙管理${NC}"; echo "======================================"; echo -e " 1. 添加 ${GREEN}允许 (ACCEPT)${NC} 策略"; echo -e " 2. 添加 ${RED}拒绝 (DROP)${NC} 策略"; echo " 3. 查看当前所有策略"; echo " 4. 删除指定策略"; echo "--------------------------------------"; echo " q. 返回主菜单"; echo "======================================"; read -p "请输入您的选择: " choice; case "$choice" in 1) docker_add_rule ACCEPT ;; 2) docker_add_rule DROP ;; 3) docker_show_rules; read -n 1 -s -r -p $'\n按任意键返回...';; 4) docker_delete_rule ;; q|Q) break ;; *) echo -e "${RED}无效选择，请重新输入。${NC}"; sleep 1 ;; esac; done; }

# ======================================================================
#  备份与恢复模块
# ======================================================================
function backup_rules() { clear; echo "--- 规则备份 ---"; local backup_dir="/root/safe"; read -p "请输入备份目录 [默认: ${backup_dir}]: " custom_backup_dir; backup_dir=${custom_backup_dir:-$backup_dir}; if ! mkdir -p "$backup_dir"; then echo -e "${RED}✗ 无法创建备份目录: ${backup_dir}${NC}"; return 1; fi; echo -e "${BLUE}正在准备备份数据...${NC}"; local tmp_dir=$(mktemp -d); local v4_rules_file="${tmp_dir}/rules.v4"; local v6_rules_file="${tmp_dir}/rules.v6"; local ipset_rules_file="${tmp_dir}/ipsets.rules"; local all_ok=true; iptables-save > "$v4_rules_file"; if [ $? -ne 0 ] || [ ! -s "$v4_rules_file" ]; then echo -e "${YELLOW}警告: 备份 IPv4 规则失败或规则为空。${NC}"; all_ok=false; fi; ip6tables-save > "$v6_rules_file"; if [ $? -ne 0 ] || [ ! -s "$v6_rules_file" ]; then echo -e "${YELLOW}警告: 备份 IPv6 规则失败或规则为空。${NC}"; fi; if command -v ipset &>/dev/null; then ipset save > "$ipset_rules_file"; if [ $? -ne 0 ] || [ ! -s "$ipset_rules_file" ]; then echo -e "${YELLOW}警告: 备份 IPSet 规则失败或规则为空。${NC}"; fi; else echo -e "${YELLOW}未找到 ipset 命令，跳过 IPSet 备份。${NC}"; fi; if ! $all_ok; then echo -e "${RED}✗ 由于核心的 IPv4 规则备份失败，操作已中止。${NC}"; rm -rf "$tmp_dir"; return 1; fi; local timestamp=$(date +%Y%m%d_%H%M%S); local backup_filename="firewall_backup_${timestamp}.tar.gz"; local backup_filepath="${backup_dir}/${backup_filename}"; echo -e "${BLUE}正在创建备份包: ${backup_filename}...${NC}"; if tar -czf "$backup_filepath" -C "$tmp_dir" .; then echo -e "${GREEN}✓ 备份成功！文件已储存至:${NC}"; echo -e "${YELLOW}${backup_filepath}${NC}"; else echo -e "${RED}✗ 创建备份压缩包失败！${NC}"; fi; rm -rf "$tmp_dir"; }
function restore_rules() { clear; echo "--- 规则恢复 ---"; local backup_dir="/root/safe"; read -p "请输入备份文件所在目录 [默认: ${backup_dir}]: " custom_backup_dir; backup_dir=${custom_backup_dir:-$backup_dir}; if [ ! -d "$backup_dir" ]; then echo -e "${RED}错误: 目录 '${backup_dir}' 不存在。${NC}"; return 1; fi; mapfile -t backups < <(find "$backup_dir" -maxdepth 1 -name "firewall_backup_*.tar.gz" -printf "%f\n" | sort -r); if [ ${#backups[@]} -eq 0 ]; then echo -e "${YELLOW}在目录 '${backup_dir}' 中未找到任何有效的备份文件。${NC}"; return 1; fi; echo "--- 请选择要恢复的规则包 ---"; local i=1; for backup in "${backups[@]}"; do printf " %-4s -> %s\n" "$i" "$backup"; i=$((i+1)); done; echo "-------------------------------------"; read -p "请输入选择的编号 (或 'q' 退出): " choice; if [[ "$choice" == "q" || "$choice" == "Q" ]]; then echo "操作已取消。"; return 0; fi; if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#backups[@]} ]; then echo -e "${RED}无效的编号。${NC}"; return 1; fi; local selected_backup_file="${backup_dir}/${backups[$((choice-1))]}"; echo -e "\n${RED}*** 警告 ***${NC}"; echo -e "${YELLOW}此操作将完全覆盖您当前的防火墙和IPSet规则。${NC}"; echo -e "${YELLOW}所有现有的连接可能会被中断。${NC}"; read -p "您确定要从 '${backups[$((choice-1))]}' 恢复吗? (请输入 'yes' 确认): " confirm; if [[ "$confirm" != "yes" ]]; then echo -e "\n${GREEN}恢复操作已取消。${NC}"; return 0; fi; echo -e "\n${BLUE}正在准备恢复环境...${NC}"; local tmp_dir=$(mktemp -d); if ! tar -xzf "$selected_backup_file" -C "$tmp_dir"; then echo -e "${RED}✗ 解压缩备份文件失败！文件可能已损坏。${NC}"; rm -rf "$tmp_dir"; return 1; fi; echo -e "${BLUE}正在清空当前的防火墙规则和 IPSet...${NC}"; iptables -F; iptables -X; iptables -Z; iptables -t nat -F; iptables -t nat -X; iptables -t nat -Z; iptables -t mangle -F; iptables -t mangle -X; iptables -t mangle -Z; ip6tables -F; ip6tables -X; ip6tables -Z; ip6tables -t mangle -F; ip6tables -t mangle -X; ip6tables -t mangle -Z; if command -v ipset &>/dev/null; then while read -r set_name; do ipset destroy "${set_name#Name: }"; done < <(ipset list | grep '^Name:'); fi; echo -e "${BLUE}正在恢复规则...${NC}"; local restore_ok=true; local v4_rules_file="${tmp_dir}/rules.v4"; local v6_rules_file="${tmp_dir}/rules.v6"; local ipset_rules_file="${tmp_dir}/ipsets.rules"; if [ -f "$ipset_rules_file" ] && [ -s "$ipset_rules_file" ] && command -v ipset &>/dev/null; then if ipset restore < "$ipset_rules_file"; then echo -e "${GREEN}✓ IPSet 规则已恢复。${NC}"; else echo -e "${RED}✗ IPSet 规则恢复失败！${NC}"; restore_ok=false; fi; fi; if [ -f "$v4_rules_file" ] && [ -s "$v4_rules_file" ]; then if iptables-restore < "$v4_rules_file"; then echo -e "${GREEN}✓ IPv4 规则已恢复。${NC}"; else echo -e "${RED}✗ IPv4 规则恢复失败！${NC}"; restore_ok=false; fi; fi; if [ -f "$v6_rules_file" ] && [ -s "$v6_rules_file" ]; then if ip6tables-restore < "$v6_rules_file"; then echo -e "${GREEN}✓ IPv6 规则已恢复。${NC}"; else echo -e "${RED}✗ IPv6 规则恢复失败！${NC}"; restore_ok=false; fi; fi; rm -rf "$tmp_dir"; if $restore_ok; then echo -e "\n${GREEN}✓ 规则恢复成功！正在储存以确保持久化...${NC}"; save_all_rules; else echo -e "\n${RED}✗ 恢复过程中发生错误。防火墙可能处于不确定状态。${NC}"; echo -e "${YELLOW}建议您手动检查 ('iptables -L -n') 或使用脚本的重置功能。${NC}"; fi; }
function manage_backup_restore_menu() { while true; do clear; echo "======================================================"; echo "                                 防火墙规则备份与恢复"; echo "======================================================"; echo " 1. 备份当前所有防火墙规则"; echo " 2. 从备份文件中恢复规则"; echo "------------------------------------------------------"; echo " q. 返回主菜单"; read -p "请输入您的选择: " choice; case $choice in 1) backup_rules; break ;; 2) restore_rules; break ;; q|Q) break ;; *) echo -e "${RED}无效输入。${NC}"; sleep 1 ;; esac; done; }

# ======================================================================
#  Fail2ban 管理模块
# ======================================================================
function get_effective_f2b_param() { local param_name=$1; local JAIL_LOCAL="/etc/fail2ban/jail.local"; cat /etc/fail2ban/jail.conf "$JAIL_LOCAL" 2>/dev/null | grep -E "^[[:space:]]*${param_name}[[:space:]]*=" | grep -vE "^[[:space:]]*#" | tail -n 1 | awk -F= '{print $2}' | xargs; }
function install_fail2ban_f2b() { if command -v fail2ban-client &>/dev/null; then echo -e "${GREEN}✓ Fail2ban 已安装。${NC}"; return 0; fi; local DISTRO=""; if [ -f /etc/debian_version ]; then DISTRO="debian"; elif [ -f /etc/redhat-release ]; then DISTRO="rhel"; fi; echo -e "${BLUE}正在为您安装 Fail2ban...${NC}"; case $DISTRO in "debian") apt-get update -yq && apt-get install -yq fail2ban ;; "rhel") local PKG_CMD="yum"; if command -v dnf &>/dev/null; then PKG_CMD="dnf"; fi; $PKG_CMD install -y epel-release && $PKG_CMD install -y fail2ban ;; *) echo -e "${RED}不支持的操作系统，无法自动安装 Fail2ban。${NC}"; return 1 ;; esac; if [ $? -eq 0 ]; then echo -e "${GREEN}✓ Fail2ban 安装成功。${NC}"; if [ "$DISTRO" == "debian" ]; then echo -e "${BLUE}正在为 systemd 系统优化 Fail2ban 日志后端...${NC}"; local JAIL_LOCAL="/etc/fail2ban/jail.local"; if ! grep -q "^\s*\[DEFAULT\]" "$JAIL_LOCAL" 2>/dev/null; then mkdir -p "$(dirname "$JAIL_LOCAL")"; echo -e "\n[DEFAULT]\n" >> "$JAIL_LOCAL"; fi; if ! grep -q "^\s*backend\s*=" "$JAIL_LOCAL" 2>/dev/null; then sed -i "/\[DEFAULT\]/a backend = systemd" "$JAIL_LOCAL"; echo -e "${GREEN}✓ 已在 ${JAIL_LOCAL} 中设置 backend = systemd。${NC}"; else echo -e "${YELLOW}侦测到 backend 已在 ${JAIL_LOCAL} 中设置，跳过自动设置。${NC}"; fi; local ACTION_LOCAL="/etc/fail2ban/action.d/iptables-multiport.local"; if [ ! -f "$ACTION_LOCAL" ]; then echo -e "[Definition]\nallowipv6 = true" > "$ACTION_LOCAL"; echo -e "${GREEN}✓ 已创建 ${ACTION_LOCAL} 并明确启用 IPv6 支持。${NC}"; fi; fi; echo -e "${BLUE}正在启动并设置开机自启 (使用 restart 确保新设置生效)...${NC}"; systemctl enable fail2ban; systemctl restart fail2ban; echo -e "${GREEN}✓ Fail2ban 已启动。${NC}"; else echo -e "${RED}✗ Fail2ban 安装失败！${NC}"; return 1; fi; }
function check_fail2ban_status_f2b() { echo -e "${BLUE}--- Fail2ban 服务状态 ---${NC}"; systemctl status fail2ban --no-pager; echo -e "\n${BLUE}--- Fail2ban Jails 状态 (摘要) ---${NC}"; fail2ban-client status; }
function view_all_banned_f2b() { echo -e "${BLUE}--- 所有被 Fail2ban 封锁的 IP 列表 ---${NC}"; local jails; jails=$(fail2ban-client status | grep "Jail list:" | sed -E 's/.*Jail list:\s*//' | sed 's/,//g'); local total_bans=0; if [[ -z "$jails" ]]; then echo -e "${YELLOW}未发现任何活动的 jail。${NC}"; return; fi; for jail in $jails; do local banned_ips; banned_ips=$(fail2ban-client status "$jail" | grep 'Banned IP list:' | sed 's/.*Banned IP list:\s*//'); if [[ -n "$banned_ips" ]]; then echo -e "\n--- Jail: ${YELLOW}${jail}${NC} ---"; for ip in $banned_ips; do echo "$ip"; done; total_bans=$((total_bans + $(echo "$banned_ips" | wc -w))); fi; done; if [[ $total_bans -eq 0 ]]; then echo -e "\n${GREEN}当前没有任何 IP 被封锁。${NC}"; fi; }
function check_banned_ip_f2b() { read -p "请输入要查询的 IP 地址: " ip_to_check; if [[ -z "$ip_to_check" ]]; then echo -e "\n${RED}IP 地址不可为空。${NC}"; return; fi; echo -e "\n${BLUE}正在查询所有活动的 jail 中关于 '${ip_to_check}' 的封锁状态...${NC}"; local jails; jails=$(fail2ban-client status | grep "Jail list:" | sed -E 's/.*Jail list:\s*//' | sed 's/,//g'); local is_banned=false; for jail in $jails; do if fail2ban-client status "$jail" | grep -q "$ip_to_check"; then echo -e "IP ${YELLOW}${ip_to_check}${NC} 在 jail ${GREEN}${jail}${NC} 中 ${RED}被封锁${NC}。"; is_banned=true; fi; done; if ! $is_banned; then echo -e "IP ${YELLOW}${ip_to_check}${NC} ${GREEN}未被任何活动的 jail 封锁${NC}。"; fi; }
function unban_ip_f2b() { read -p "请输入要解锁的 IP 地址: " ip_to_unban; if [[ -z "$ip_to_unban" ]]; then echo -e "\n${RED}IP 地址不可为空。${NC}"; return; fi; local banned_in_jails=(); local all_jails; all_jails=$(fail2ban-client status | grep "Jail list:" | sed -E 's/.*Jail list:\s*//' | sed 's/,//g'); for jail in $all_jails; do if fail2ban-client status "$jail" | grep -q "$ip_to_unban"; then banned_in_jails+=("$jail"); fi; done; if [ ${#banned_in_jails[@]} -eq 0 ]; then echo -e "\n${GREEN}侦测到 IP '${ip_to_unban}' 未被任何活动的 jail 封锁。${NC}"; return; fi; echo -e "\n${BLUE}侦测到 IP '${ip_to_unban}' 被以下服务封锁：${NC}"; local i=1; for jail in "${banned_in_jails[@]}"; do echo " ${i}. ${jail}"; i=$((i+1)); done; echo " a. 从以上所有服务中解锁"; echo "-------------------------------------"; read -p "请选择要解锁的服务编号 (或 a): " choice; if [[ "$choice" == "a" || "$choice" == "A" ]]; then for jail in "${banned_in_jails[@]}"; do if fail2ban-client set "$jail" unbanip "$ip_to_unban"; then echo -e "${GREEN}✓ 已从 ${jail} 解锁。${NC}"; else echo -e "${RED}✗ 从 ${jail} 解锁失败。${NC}"; fi; done; elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -lt $i ]; then local jail_to_unban="${banned_in_jails[$((choice-1))]}"; if fail2ban-client set "$jail_to_unban" unbanip "$ip_to_unban"; then echo -e "${GREEN}✓ 已从 ${jail_to_unban} 解锁。${NC}"; else echo -e "${RED}✗ 从 ${jail_to_unban} 解锁失败。${NC}"; fi; else echo -e "${RED}无效选择。${NC}"; return; fi; }
function ban_ip_f2b() { read -p "请输入要手动封锁的 IP 地址: " ip_to_ban; if [[ -z "$ip_to_ban" ]]; then echo -e "\n${RED}IP 地址不可为空。${NC}"; return; fi; local jails_arr; readarray -t jails_arr <<< "$(fail2ban-client status | grep "Jail list:" | sed -E 's/.*Jail list:\s*//' | sed 's/,/\n/g' | xargs)"; if [ ${#jails_arr[@]} -eq 0 ]; then echo -e "${RED}错误：未找到任何活动的 Fail2ban jail。${NC}"; return; fi; echo -e "\n${BLUE}请选择要使用哪个 Jail 来封锁此 IP：${NC}"; local i=1; for jail in "${jails_arr[@]}"; do echo " ${i}. ${jail}"; i=$((i+1)); done; echo "-------------------------------------"; read -p "请输入选择的编号: " choice; if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#jails_arr[@]} ]; then echo -e "${RED}无效编号。${NC}"; return; fi; local jail_name="${jails_arr[$((choice-1))]}"; echo -e "\n${BLUE}正在将 IP '${ip_to_ban}' 新增到 jail '${jail_name}'...${NC}"; if fail2ban-client set "$jail_name" banip "$ip_to_ban"; then echo -e "${GREEN}✓ IP '${ip_to_ban}' 已被 jail '${jail_name}' 封锁。${NC}"; else echo -e "${RED}✗ 封锁失败。请检查 jail 名称是否存在或服务是否在运行。${NC}"; fi; }
function modify_fail2ban_params() { local JAIL_LOCAL="/etc/fail2ban/jail.local"; echo -e "${BLUE}--- Fail2ban 核心参数修改 ---${NC}"; echo "此功能将通过创建/修改 ${JAIL_LOCAL} 来覆盖默认设置。"; local current_bantime=$(get_effective_f2b_param "bantime"); local current_findtime=$(get_effective_f2b_param "findtime"); local current_maxretry=$(get_effective_f2b_param "maxretry"); echo "-------------------------------------"; echo -e "当前值 (留空则不修改):"; read -p "封锁时长 (bantime) [当前: ${YELLOW}${current_bantime}${NC} (单位:秒,可用m,h,d)]: " new_bantime; read -p "侦测周期 (findtime) [当前: ${YELLOW}${current_findtime}${NC} (单位:秒,可用m,h,d)]: " new_findtime; read -p "最大尝试次数 (maxretry) [当前: ${YELLOW}${current_maxretry}${NC} (单位:次)]: " new_maxretry; echo "-------------------------------------"; local changed=false; if ! grep -q "^\s*\[DEFAULT\]" "$JAIL_LOCAL" 2>/dev/null; then mkdir -p "$(dirname "$JAIL_LOCAL")"; echo -e "[DEFAULT]\n" >> "$JAIL_LOCAL"; fi; if [[ -n "$new_bantime" ]]; then if grep -q "^\s*bantime\s*=" "$JAIL_LOCAL" 2>/dev/null; then sed -i "s|^\s*bantime\s*=.*|bantime = ${new_bantime}|" "$JAIL_LOCAL"; else sed -i "/\[DEFAULT\]/a bantime = ${new_bantime}" "$JAIL_LOCAL"; fi; changed=true; echo "✓ bantime 已更新。"; fi; if [[ -n "$new_findtime" ]]; then if grep -q "^\s*findtime\s*=" "$JAIL_LOCAL" 2>/dev/null; then sed -i "s|^\s*findtime\s*=.*|findtime = ${new_findtime}|" "$JAIL_LOCAL"; else sed -i "/\[DEFAULT\]/a findtime = ${new_findtime}" "$JAIL_LOCAL"; fi; changed=true; echo "✓ findtime 已更新。"; fi; if [[ -n "$new_maxretry" ]]; then if grep -q "^\s*maxretry\s*=" "$JAIL_LOCAL" 2>/dev/null; then sed -i "s|^\s*maxretry\s*=.*|maxretry = ${new_maxretry}|" "$JAIL_LOCAL"; else sed -i "/\[DEFAULT\]/a maxretry = ${new_maxretry}" "$JAIL_LOCAL"; fi; changed=true; echo "✓ maxretry 已更新。"; fi; if $changed; then echo -e "\n${BLUE}参数已修改，正在尝试应用设置...${NC}"; if systemctl is-active --quiet fail2ban; then echo "服务正在运行，正在执行 'reload' 操作..."; if fail2ban-client reload; then echo -e "${GREEN}✓ Fail2ban 已成功重新加载新设置。${NC}"; else echo -e "${RED}✗ Fail2ban 重新加载失败！请手动检查设置: 'fail2ban-client -t'${NC}"; fi; else echo -e "${YELLOW}服务当前已停止。设置已保存，将在下次启动时生效。${NC}"; read -p "是否现在启动 Fail2ban 服务? [y/n]: " start_choice; if [[ "$start_choice" == "y" || "$start_choice" == "Y" ]]; then if systemctl start fail2ban; then echo -e "${GREEN}✓ Fail2ban 服务已启动。${NC}"; else echo -e "${RED}✗ Fail2ban 服务启动失败！${NC}"; fi; fi; fi; else echo -e "${YELLOW}未做任何修改。${NC}"; fi; }
function view_failed_logins_f2b() { while true; do clear; echo "======================================================"; echo -e "                                    ${YELLOW}Fail2ban 日志审计中心${NC}"; echo "======================================================"; echo " 1. 查看 SSH 认证失败日志 (攻击来源)"; echo " 2. 查看 Fail2ban 自身操作日志 (封锁/解锁历史)"; echo "------------------------------------------------------"; echo " q. 返回 Fail2ban 菜单"; read -p "请输入您的选择: " log_choice; echo; case $log_choice in 1) echo -e "${BLUE}--- 最近 50 条 SSH 登录失败记录 ---${NC}"; if command -v journalctl &>/dev/null; then journalctl -u sshd | grep -E "Failed|failure" | tail -n 50; else local auth_log="/var/log/auth.log"; if [ -f "/var/log/secure" ]; then auth_log="/var/log/secure"; fi; grep -E "sshd.*(Failed|failure)" "$auth_log" | tail -n 50; fi ;; 2) echo -e "${BLUE}--- 最近 50 条 Fail2ban 操作记录 ---${NC}"; if command -v journalctl &>/dev/null; then journalctl -u fail2ban | grep -E "Ban|Unban" | tail -n 50; else grep -E "Ban|Unban" /var/log/fail2ban.log | tail -n 50; fi ;; q|Q) break ;; *) echo -e "${RED}无效输入。${NC}"; sleep 1 ;; esac; echo; read -n 1 -s -r -p "按任意键返回..."; done; }
function manage_fail2ban_menu() { while true; do clear; echo "======================================================"; echo -e "                                    ${YELLOW}Fail2ban 管理中心${NC}"; echo "======================================================"; if ! command -v fail2ban-client &>/dev/null; then echo -e "${YELLOW}警告: 系统未侦测到 Fail2ban。${NC}"; echo "------------------------------------------------------"; echo " 1. 安装 Fail2ban"; echo "------------------------------------------------------"; echo " q. 返回主菜单"; read -p "请输入您的选择: " f2b_choice; case $f2b_choice in 1) install_fail2ban_f2b; read -n 1 -s -r -p "按任意键继续...";; q|Q) break ;; *) echo -e "${RED}无效输入。${NC}"; sleep 1 ;; esac; else local f2b_status; if systemctl is-active --quiet fail2ban; then f2b_status="${GREEN}运行中${NC}"; else f2b_status="${RED}已停止${NC}"; fi; echo -e " (服务状态: ${f2b_status})"; echo "------------------------------------------------------"; echo " 1. 查看 Fail2ban 详细状态"; echo " 2. 查看所有被封锁的 IP"; echo " 3. 查询指定 IP 是否被封锁"; echo " 4. [解锁] 一个 IP (Unban)"; echo " 5. [封锁] 一个 IP (Ban)"; echo " 6. 修改核心参数 (bantime, maxretry等)"; echo " 7. 查看登录尝试及封锁日志"; echo "------------------------------------------------------"; echo " q. 返回主菜单"; read -p "请输入您的选择: " f2b_choice; case $f2b_choice in 1) check_fail2ban_status_f2b ;; 2) view_all_banned_f2b ;; 3) check_banned_ip_f2b ;; 4) unban_ip_f2b ;; 5) ban_ip_f2b ;; 6) modify_fail2ban_params ;; 7) view_failed_logins_f2b ;; q|Q) break ;; *) echo -e "${RED}无效输入。${NC}"; sleep 1 ;; esac; echo; read -n 1 -s -r -p "操作完成，按任意键返回 Fail2ban 菜单..."; fi; done; }

function check_and_run_tool() { local cmd_name=$1; local pkg_name=$2; if ! command -v "$cmd_name" &>/dev/null; then echo -e "\n${YELLOW}警告: 命令 '${cmd_name}' 未找到。${NC}"; read -p "是否尝试自动安装 '${pkg_name}'? [y/n]: " install_choice; if [[ "$install_choice" == "y" || "$install_choice" == "Y" ]]; then echo -e "${BLUE}正在安装 ${pkg_name}...${NC}"; if [ -f /etc/debian_version ]; then apt-get update -yq && apt-get install -yq "$pkg_name"; elif [ -f /etc/redhat-release ]; then local PKG_CMD="yum"; if command -v dnf &>/dev/null; then PKG_CMD="dnf"; fi; if [[ "$pkg_name" == "iftop" ]]; then $PKG_CMD install -y epel-release; fi; $PKG_CMD install -y "$pkg_name"; else echo -e "${RED}无法确定包管理器，请手动安装 ${pkg_name}。${NC}"; sleep 2; return 1; fi; if [ $? -eq 0 ]; then echo -e "${GREEN}✓ ${pkg_name} 安装成功。${NC}"; hash -r; else echo -e "${RED}✗ ${pkg_name} 安装失败。${NC}"; sleep 2; return 1; fi; else echo -e "${GREEN}操作已取消。${NC}"; sleep 1; return 1; fi; fi; echo -e "${GREEN}正在启动 ${cmd_name}... (通常按 'q' 退出)${NC}"; sleep 1; clear; "$cmd_name"; }
function view_connections() { while true; do clear; echo "--- 查看连接与网络监控 ---"; echo " 1. 活动连接 (ss -tanp)"; echo " 2. 监听端口 (ss -tlnp)"; echo " 3. IP连接排名 (ss)"; echo " 4. lsof 查看"; echo "-----------------------------------"; echo -e " 5. ${GREEN}bmon → 监控网卡实时速率${NC}"; echo -e " 6. ${GREEN}iftop → 监控 IP 连接速率${NC}"; echo "-----------------------------------"; echo " q. 返回"; read -p "选择: " choice; case $choice in 1) ss "$SS_FAMILY_FLAG" -tanp | grep ESTAB; read -n 1 -s -r -p $'\n按任意键继续...';; 2) ss "$SS_FAMILY_FLAG" -tlnp; read -n 1 -s -r -p $'\n按任意键继续...';; 3) ss "$SS_FAMILY_FLAG" -tan | grep ESTAB | awk '{print $5}' | sed -e 's/\[//g' -e 's/\]//g' -e 's/:[^:]*$//' | sort | uniq -c | sort -nr | head -n 20; read -n 1 -s -r -p $'\n按任意键继续...';; 4) lsof -i"${SS_FAMILY_FLAG#-}"; read -n 1 -s -r -p $'\n按任意键继续...';; 5) check_and_run_tool "bmon" "bmon" ;; 6) check_and_run_tool "iftop" "iftop" ;; q|Q) break;; *) echo -e "${RED}无效选择。${NC}"; sleep 1;; esac; done; }

function get_forwarding_status() { local fwd_path="/proc/sys/net/ipv4/ip_forward"; if [[ "$IP_VERSION" == "IPv6" ]]; then fwd_path="/proc/sys/net/ipv6/conf/all/forwarding"; fi; if [[ -f "$fwd_path" ]] && [[ $(cat "$fwd_path") -eq 1 ]]; then echo "已开启"; else echo "已停用"; fi; }
function check_and_enable_forwarding() { local fwd_path="/proc/sys/net/ipv4/ip_forward"; local sysctl_var="net.ipv4.ip_forward"; if [[ "$IP_VERSION" == "IPv6" ]]; then fwd_path="/proc/sys/net/ipv6/conf/all/forwarding"; sysctl_var="net.ipv6.conf.all.forwarding"; fi; if [[ -f "$fwd_path" ]] && [[ $(cat "$fwd_path") -ne 1 ]]; then echo -e "${YELLOW}警告：${IP_VERSION} 转发已停用，正在自动为您启用...${NC}"; if ! sysctl -w "$sysctl_var=1"; then echo -e "${RED}✗ 启用 ${sysctl_var} 失败!${NC}"; return 1; fi; if grep -q "^\s*#*\s*${sysctl_var}" /etc/sysctl.conf; then sed -i -E "s/^\s*#*\s*${sysctl_var}.*/${sysctl_var} = 1/" /etc/sysctl.conf; else echo "" >> /etc/sysctl.conf; echo "# Added by IPTables Manager Script for ${IP_VERSION}" >> /etc/sysctl.conf; echo "${sysctl_var} = 1" >> /etc/sysctl.conf; fi; sysctl -p &>/dev/null; echo -e "${GREEN}✓ ${IP_VERSION} 转发已临时并永久启用。${NC}"; else echo -e "${GREEN}✓ ${IP_VERSION} 转发状态正常 (已开启)。${NC}"; fi; return 0; }

function add_chain_rule() {
    local chain=$1
    if [[ "$chain" == "FORWARD" ]]; then
        if ! check_and_enable_forwarding; then return 1; fi
    fi
    clear
    echo "--- 在 $chain 链中新增新规则 ($IP_VERSION) ---"
    echo "请选择规则的目标 (Target):"
    echo " 1. ACCEPT (允许)"
    echo " 2. DROP   (丢弃 - 静默)"
    echo " 3. REJECT (拒绝 - 告知对方)"
    read -p "请输入选择 [1-3]: " target_choice
    local target
    case $target_choice in
        1) target="ACCEPT" ;;
        2) target="DROP" ;;
        3) target="REJECT" ;;
        *) echo -e "${RED}无效选择。${NC}"; return 1 ;;
    esac
    echo "请选择协议 (Protocol):"
    echo " 1. all (全部协议)"
    echo " 2. tcp"
    echo " 3. udp"
    echo " 4. ${ICMP_PROTO}"
    read -p "请输入选择 [回车默认为 1 (all)]: " proto_choice
    local proto
    case $proto_choice in
        ""|1) proto="all" ;;
        2) proto="tcp" ;;
        3) proto="udp" ;;
        4) proto="${ICMP_PROTO}" ;;
        *) echo -e "${RED}无效选择。${NC}"; return 1 ;;
    esac
    read -p "源地址 (IP/CIDR, 留空为 any): " src
    read -p "目的地址 (IP/CIDR, 留空为 any): " dst
    local dport=""
    if [[ "$proto" == "tcp" || "$proto" == "udp" ]]; then
        read -p "目的端口 (留空为 any): " dport
    fi
    local rule_cmd="$IPTABLES_CMD -A $chain"
    if [[ "$proto" != "all" ]]; then rule_cmd+=" -p $proto"; fi
    if [[ ! -z "$src" ]]; then rule_cmd+=" -s $src"; fi
    if [[ ! -z "$dst" ]]; then rule_cmd+=" -d $dst"; fi
    if [[ ! -z "$dport" ]]; then rule_cmd+=" --dport $dport"; fi
    rule_cmd+=" -j $target"
    echo -e "${BLUE}将要执行: $rule_cmd${NC}"
    if eval "$rule_cmd"; then
        echo -e "\n${GREEN}✓ 规则新增成功。${NC}"
        save_all_rules
    else
        echo -e "\n${RED}✗ 规则新增失败。${NC}"
    fi
}

function delete_chain_rule() { local chain=$1; while true; do clear; echo "--- 从 $chain 链中删除规则 ($IP_VERSION) ---"; $IPTABLES_CMD -L "$chain" -v -n --line-numbers | grep -v -E "GEOBLOCK_OUT|GEOWHITELIST_OUT"; echo "---------------------------------"; read -p "请输入要删除的规则编号 (或输入 'q' 退出): " choice; if [[ "$choice" == "q" || "$choice" == "Q" ]]; then break; fi; if ! [[ "$choice" =~ ^[0-9]+$ ]]; then echo -e "${RED}无效输入。${NC}"; sleep 1; continue; fi; if $IPTABLES_CMD -D "$chain" "$choice"; then echo -e "${GREEN}✓ 规则 ${choice} 已从 ${chain} 删除。${NC}"; save_all_rules; sleep 1; else echo -e "${RED}✗ 删除失败，请检查编号是否正确。${NC}"; sleep 2; fi; done; }

# ====================================================================================
# 函数: add_port_forward_rule (已修复)
# 修复说明:
# 1. MASQUERADE 规则现在使用与 DNAT/FORWARD 规则相同的唯一 comment_tag 进行标记。
# 2. MASQUERADE 规则现在包含源地址(-s "$private_ip")，使其更具针对性，避免与其他NAT规则冲突。
# 3. 检查逻辑现在会查找这条特定的规则，而不是一个通用的MASQUERADE规则。
# ====================================================================================
function add_port_forward_rule() {
    if [[ "$IP_VERSION" == "IPv6" ]]; then echo -e "\n${RED}错误：此功能仅在 IPv4 模式下可用。${NC}"; sleep 2; return 1; fi
    if ! check_and_enable_forwarding; then return 1; fi
    clear
    echo "--- 新增新的端口转发 (DNAT) 规则 (IPv4) ---"
    local public_ip private_ip public_port private_port proto_choice
    local public_ip_param=""
    local ipv4_regex='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    read -p "公网目标 IP (留空则代表所有IP): " public_ip
    if [[ -n "$public_ip" ]]; then
        if ! [[ "$public_ip" =~ $ipv4_regex ]]; then echo -e "\n${RED}错误：公网IP地址格式无效。请输入单一IPv4地址。${NC}"; return 1; fi
        public_ip_param="-d $public_ip"
    fi
    read -p "公网端口 (1-65535): " public_port
    if ! [[ "$public_port" =~ ^[0-9]+$ && "$public_port" -ge 1 && "$public_port" -le 65535 ]]; then echo -e "\n${RED}错误：公网端口号无效。必须是 1-65535 之间的数字。${NC}"; return 1; fi
    read -p "内网目标 IP: " private_ip
    if ! [[ "$private_ip" =~ $ipv4_regex ]]; then echo -e "\n${RED}错误：内网目标IP地址格式无效。${NC}"; return 1; fi
    read -p "内网目标端口 [回车同公网端口]: " private_port
    [[ -z "$private_port" ]] && private_port=$public_port
    if ! [[ "$private_port" =~ ^[0-9]+$ && "$private_port" -ge 1 && "$private_port" -le 65535 ]]; then echo -e "\n${RED}错误：内网目标端口号无效。必须是 1-65535 之间的数字。${NC}"; return 1; fi
    echo "请选择协议:"
    echo " 1. TCP"
    echo " 2. UDP"
    echo " 3. 两者 (TCP+UDP)"
    read -p "请输入选择 [回车默认为 3]: " proto_choice
    local protos=()
    case $proto_choice in
        1) protos=("tcp") ;;
        2) protos=("udp") ;;
        ""|3) protos=("tcp" "udp") ;;
        *) echo -e "\n${RED}无效选择。${NC}"; return 1 ;;
    esac

    local rules_added=0
    for proto in "${protos[@]}"; do
        echo -e "\n${BLUE}--- 正在为协议 ${proto^^} 新增规则 ---${NC}"
        local comment_tag="dnat_${proto}_${public_port}_to_${private_ip}_${private_port}"
        local to_destination_format="${private_ip}:${private_port}"
        echo "  -> 新增 DNAT 规则 (nat 表)..."
        if $IPTABLES_CMD -t nat -A PREROUTING $public_ip_param -p "$proto" --dport "$public_port" -j DNAT --to-destination "$to_destination_format" -m comment --comment "$comment_tag"; then
            echo "  -> 新增 FORWARD 规则 (filter 表)..."
            $IPTABLES_CMD -A FORWARD -d "$private_ip" -p "$proto" --dport "$private_port" -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT -m comment --comment "$comment_tag"
            rules_added=$((rules_added + 1))
        else
            echo -e "${RED}                                  ✗ 新增 DNAT 规则失败！可能是规则已存在或参数冲突。${NC}"
        fi
    done

    if [ $rules_added -gt 0 ]; then
        echo -e "\n${YELLOW}注意: 为使转发流量能正确返回，通常需要设置 SNAT 或 MASQUERADE。${NC}"
        read -p "是否需要为此转发新增对应的 MASQUERADE 伪装规则? [y/n]: " add_masq
        if [[ "$add_masq" == "y" || "$add_masq" == "Y" ]]; then
            local public_iface
            public_iface=$(ip -o -${SS_FAMILY_FLAG:1} route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+')
            
            if [[ -n "$public_iface" ]]; then
                read -p "脚本自动检测到公网接口为 [${YELLOW}${public_iface}${NC}]，正确吗? (回车确认 / 或输入正确接口名): " manual_iface
                if [[ -n "$manual_iface" ]]; then
                    public_iface="$manual_iface"
                    echo -e "${GREEN}✓ 公网接口已更新为: ${public_iface}${NC}"
                fi
            else
                echo -e "${RED}无法自动侦测到公网接口!${NC}"
                read -p "请手动输入公网接口名称 (例如: eth0): " public_iface
            fi

            if [[ -z "$public_iface" ]]; then
                echo -e "${RED}未提供接口名称，跳过 MASQUERADE 规则添加。${NC}"
            else
                # 【修复】为每个协议创建对应的、带有源IP的特定MASQUERADE规则
                for proto in "${protos[@]}"; do
                    local comment_tag="dnat_${proto}_${public_port}_to_${private_ip}_${private_port}"
                    # 【修复】检查一条非常具体的规则是否存在
                    if ! $IPTABLES_CMD -t nat -C POSTROUTING -s "$private_ip" -p "$proto" -o "$public_iface" -j MASQUERADE 2>/dev/null; then
                        echo -e "${BLUE}正在为 ${private_ip} (${proto^^}) -> ${public_iface} 添加一条特定的 MASQUERADE 规则...${NC}"
                        # 【修复】添加带有源地址和唯一注释的规则
                        $IPTABLES_CMD -t nat -A POSTROUTING -s "$private_ip" -p "$proto" -o "$public_iface" -j MASQUERADE -m comment --comment "$comment_tag"
                    else
                        echo -e "${YELLOW}侦测到已存在针对 ${private_ip} (${proto^^}) 的 MASQUERADE 规则，无需重复新增。${NC}"
                    fi
                done
            fi
        fi
        echo -e "\n${GREEN}✓ 端口转发规则集新增完成。${NC}"
        save_all_rules
    else
        echo -e "\n${YELLOW}未新增任何新规则。${NC}"
    fi
}

# ====================================================================================
# 函数: view_delete_port_forward_rules (已修复)
# 修复说明:
# 1. 在要扫描和删除规则的链列表(tables_and_chains)中，增加了 "nat POSTROUTING"。
# 2. 这使得删除逻辑可以自动找到并清除与转发规则相关联的、由新版函数创建的 MASQUERADE 规则。
# ====================================================================================
function view_delete_port_forward_rules() { 
    if [[ "$IP_VERSION" == "IPv6" ]]; then echo -e "\n${RED}错误：此功能仅在 IPv4 模式下可用。${NC}"; sleep 2; return 1; fi; 
    while true; do 
        clear; 
        echo "--- 查看/删除端口转发 (DNAT) 规则 (IPv4) ---"; 
        local dnat_comments; 
        dnat_comments=($($IPTABLES_CMD-save -t nat | sed -n 's/.*--comment "\(dnat[-_][^"]*\)".*/\1/p' | sort -u)); 
        if [ ${#dnat_comments[@]} -eq 0 ]; then echo -e "${YELLOW}当前没有由本脚本创建的端口转发规则。${NC}"; read -n 1 -s -r -p "按键返回..."; return; fi; 
        echo -e "${BLUE}当前活动的端口转发规则集:${NC}"; 
        local i=1; 
        declare -a comment_map; 
        for comment in "${dnat_comments[@]}"; do 
            comment_map[$i]=$comment; 
            local proto pport dip dport; 
            if [[ "$comment" == *"_"* ]]; then IFS='_' read -r -a parts <<< "$comment"; proto=${parts[1]}; pport=${parts[2]}; dip=${parts[4]}; dport=${parts[5]}; 
            else IFS='-' read -r -a parts <<< "$comment"; proto=${parts[1]}; pport=${parts[2]}; dip=${parts[4]}; dport=${parts[5]}; fi; 
            printf " %-4s -> Proto: %-3s, Public Port: %-5s, Target: %s:%s\n" "$i" "$proto" "$pport" "$dip" "$dport"; i=$((i+1)); 
        done; 
        echo "-----------------------------------"; 
        read -p "请输入要删除的规则集编号 (或 'q' 退出): " choice; 
        if [[ "$choice" == "q" || "$choice" == "Q" ]]; then break; fi; 
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -ge $i ]; then echo -e "${RED}无效编号。${NC}"; sleep 1; continue; fi; 
        local comment_to_delete=${comment_map[$choice]}; 
        echo -e "\n${YELLOW}正在删除与 '${comment_to_delete}' 相关的所有规则...${NC}"; 
        local rules_deleted_count=0; 
        # 【修复】在扫描列表中增加了 nat POSTROUTING，以删除对应的MASQUERADE规则
        local tables_and_chains=("nat PREROUTING" "filter FORWARD" "nat POSTROUTING"); 
        for item in "${tables_and_chains[@]}"; do 
            local table chain; 
            read -r table chain <<< "$item"; 
            local lines_to_delete; 
            lines_to_delete=$($IPTABLES_CMD -t "$table" -L "$chain" -v -n --line-numbers | grep -F "${comment_to_delete}" | awk '{print $1}' | sort -rn); 
            if [[ -z "$lines_to_delete" ]]; then continue; fi; 
            for line_num in $lines_to_delete; do 
                echo "  -> 正在删除 ($table 表, $chain 链) 的第 ${line_num} 条规则..."; 
                if $IPTABLES_CMD -t "$table" -D "$chain" "$line_num" &>/dev/null; then rules_deleted_count=$((rules_deleted_count + 1)); 
                else echo "           ${RED}✗ 删除失败! 这可能是一个暂时错误，请重试。${NC}"; fi; 
            done; 
        done; 
        if [ $rules_deleted_count -gt 0 ]; then echo -e "${GREEN}✓ 规则集 '${comment_to_delete}' 已成功删除 ${rules_deleted_count} 条关联规则。${NC}"; 
        else echo -e "${RED}✗ 未找到与 '${comment_to_delete}' 相关的规则进行删除。可能是规则已被手动更改。${NC}"; fi; 
        save_all_rules; sleep 3; 
    done; 
}

function reorder_rules_in_chain() { local chain=$1; while true; do clear; echo "--- 调整链 [${YELLOW}${chain}${NC}] 内的规则顺序 (${IP_VERSION}) ---"; local rule_count; rule_count=$($IPTABLES_CMD -L "$chain" -n 2>/dev/null | tail -n +3 | wc -l); $IPTABLES_CMD -L "$chain" -v -n --line-numbers; echo "----------------------------------------------------"; if [ "$rule_count" -lt 2 ]; then echo -e "${YELLOW}此链中的规则少于2条，无需排序。${NC}"; read -n 1 -s -r -p "按任意键返回..."; break; fi; read -p "请输入要移动的规则编号 (或 'q' 退出): " src_num; if [[ "$src_num" == "q" || "$src_num" == "Q" ]]; then break; fi; read -p "请输入新的目标位置编号: " dst_num; if ! [[ "$src_num" =~ ^[0-9]+$ && "$dst_num" =~ ^[0-9]+$ ]]; then echo -e "${RED}无效输入，必须是数字。${NC}"; sleep 1; continue; fi; if [ "$src_num" -gt "$rule_count" ] || [ "$dst_num" -gt "$rule_count" ] || [ "$src_num" -eq 0 ] || [ "$dst_num" -eq 0 ]; then echo -e "${RED}编号超出范围 (1-${rule_count})。${NC}"; sleep 1; continue; fi; if [ "$src_num" -eq "$dst_num" ]; then echo -e "${YELLOW}来源和目标位置相同，无需移动。${NC}"; sleep 1; continue; fi; local rule_spec; rule_spec=$($IPTABLES_CMD -S "$chain" "$src_num" | sed "s/^-A ${chain} //"); echo -e "${BLUE}正在移动规则: ${rule_spec}${NC}"; $IPTABLES_CMD -D "$chain" "$src_num"; if [ "$src_num" -lt "$dst_num" ]; then $IPTABLES_CMD -I "$chain" $((dst_num - 1)) $rule_spec; else $IPTABLES_CMD -I "$chain" "$dst_num" $rule_spec; fi; echo -e "${GREEN}✓ 规则已移动。正在储存...${NC}"; save_all_rules; sleep 1; done; }
function reorder_input_chain_jumps() { clear; echo -e "--- ${RED}高风险操作${NC}: 调整 INPUT 链核心检查顺序 (${IP_VERSION}) ---"; local reorderable_chains=("WHITELIST" "BLACKLIST" "GEOBLOCK_IN" "GEOWHITELIST_IN" "PORT_ALLOW" "PORT_DENY"); local current_order=(); while IFS= read -r line; do for chain in "${reorderable_chains[@]}"; do if [[ "$line" == *"-j ${chain}"* ]]; then current_order+=("$chain"); break; fi; done; done <<< "$($IPTABLES_CMD -S INPUT)"; echo "核心系统规则 (如 SSH, ESTABLISHED) 已被保护，不会参与排序。"; echo "当前检查顺序:"; local i=1; for chain in "${current_order[@]}"; do echo " ${i}. ${chain}"; i=$((i+1)); done; echo "----------------------------------------------------"; echo "请输入您期望的新顺序，用逗号分隔编号 (例如: 2,1,3,4,5,6):"; read -p "> " new_order_str; local new_order_map=(); IFS=',' read -r -a new_order_indices <<< "$new_order_str"; if [ ${#new_order_indices[@]} -ne ${#current_order[@]} ]; then echo -e "${RED}错误：输入的数量与可排序的链数量不符!${NC}"; sleep 2; return; fi; for index in "${new_order_indices[@]}"; do if ! [[ "$index" =~ ^[0-9]+$ ]] || [ "$index" -lt 1 ] || [ "$index" -gt ${#current_order[@]} ]; then echo -e "${RED}错误：包含无效或超出范围的编号 '${index}'!${NC}"; sleep 2; return; fi; new_order_map+=("${current_order[$((index-1))]}"); done; if [ $(printf "%s\n" "${new_order_indices[@]}" | sort -n | uniq -c | awk '$1 > 1 {print $1}') ]; then echo -e "${RED}错误：输入中包含重复的编号!${NC}"; sleep 2; return; fi; echo -e "\n${YELLOW}您确定的新顺序将是:${NC}"; i=1; for chain in "${new_order_map[@]}"; do echo " ${i}. ${chain}"; i=$((i+1)); done; read -p "确认要应用此新顺序吗? [y/n]: " confirm; if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then echo -e "${GREEN}操作已取消。${NC}"; return; fi; echo -e "${BLUE}正在应用新顺序...${NC}"; for (( idx=${#current_order[@]}-1 ; idx>=0 ; idx-- )) ; do $IPTABLES_CMD -D INPUT -j "${current_order[idx]}" 2>/dev/null; done; for chain in "${new_order_map[@]}"; do $IPTABLES_CMD -A INPUT -j "$chain"; done; echo -e "${GREEN}✓ INPUT 链检查顺序已更新。正在储存...${NC}"; save_all_rules; }
function manage_rule_ordering_menu() { while true; do clear; echo "======================================================"; echo -e "               规则与链路表顺序管理 (${YELLOW}${IP_VERSION} 谨慎操作${NC})"; echo "======================================================"; echo -e " 1. ${RED}调整 INPUT 链核心检查顺序 (高风险)${NC}"; echo "------------------------------------------------------"; echo "   --- 调整指定链内部的规则顺序 ---"; local menu_index=2; local chains_to_list=("WHITELIST" "BLACKLIST" "PORT_ALLOW" "PORT_DENY" "OUTPUT" "FORWARD" "GEOBLOCK_IN" "GEOBLOCK_OUT" "GEOWHITELIST_IN" "GEOWHITELIST_OUT"); for chain in "${chains_to_list[@]}"; do echo " ${menu_index}. ${chain}"; menu_index=$((menu_index+1)); done; echo "------------------------------------------------------"; echo " q. 返回主菜单"; echo "======================================================"; read -p "请选择要调整顺序的链 (或 q): " choice; local chosen_chain=""; if [[ "$choice" -ge 2 && "$choice" -lt $menu_index ]]; then chosen_chain="${chains_to_list[$((choice-2))]}"; fi; case $choice in 1) reorder_input_chain_jumps ;; q|Q) break ;; *) if [[ -n "$chosen_chain" ]]; then reorder_rules_in_chain "$chosen_chain"; else echo -e "${RED}无效输入。${NC}"; sleep 1; fi ;; esac; done; }
function get_firewall_status() { if [[ $($IPTABLES_CMD -L INPUT -n 2>/dev/null | head -n 1 | awk -F '[() ]' '{print $5}') == "DROP" ]]; then echo "已开启 (安全)"; else echo "不安全 (危险)"; fi; }
function install_as_command() { echo -e "${BLUE}正在安装终端快捷命令...${NC}"; if cp -f "$0" "$SCRIPT_INSTALL_PATH"; then chmod +x "$SCRIPT_INSTALL_PATH"; echo -e "${GREEN}✓ 脚本已安装到: ${SCRIPT_INSTALL_PATH}${NC}"; else echo -e "${RED}✗ 脚本主体安装失败！${NC}"; return 1; fi; echo '#!/bin/bash' > "$SAFE_CMD_PATH"; echo "sudo $SCRIPT_INSTALL_PATH \"\$@\"" >> "$SAFE_CMD_PATH"; if chmod +x "$SAFE_CMD_PATH"; then echo -e "${GREEN}✓ 已创建 'ipt' 命令。${NC}"; else echo -e "${RED}✗ 创建 'ipt' 命令失败！${NC}"; fi; echo '#!/bin/bash' > "$F2B_CMD_PATH"; echo "sudo $SCRIPT_INSTALL_PATH --fail2ban" >> "$F2B_CMD_PATH"; if chmod +x "$F2B_CMD_PATH"; then echo -e "${GREEN}✓ 已创建 'f2b' 命令。${NC}"; else echo -e "${RED}✗ 创建 'f2b' 命令失败！${NC}"; fi; echo -e "\n${YELLOW}安装完成！现在您可以在终端的任何位置使用以下命令：${NC}"; echo -e "  - ${GREEN}sudo ipt${NC}     : 启动主防火墙菜单"; echo -e "  - ${GREEN}sudo f2b${NC}: 直接进入 Fail2ban 管理菜单"; }
function uninstall_command() { echo -e "${YELLOW}正在卸载终端快捷命令...${NC}"; if [ -f "$SAFE_CMD_PATH" ]; then rm -f "$SAFE_CMD_PATH"; echo -e "${GREEN}✓ 已移除 'ipt' 命令。${NC}"; fi; if [ -f "$F2B_CMD_PATH" ]; then rm -f "$F2B_CMD_PATH"; echo -e "${GREEN}✓ 已移除 'f2b' 命令。${NC}"; fi; if [ -f "$SCRIPT_INSTALL_PATH" ]; then rm -f "$SCRIPT_INSTALL_PATH"; echo -e "${GREEN}✓ 已移除脚本主体。${NC}"; fi; echo -e "${GREEN}卸载完成。${NC}"; }
function show_unified_menu() {
    local ssh_port; ssh_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}' | head -n1); ssh_port=${ssh_port:-22}; local icmp_status=$(check_icmp_status); local icmp_color="${RED}"; if [ "$icmp_status" == "允许" ]; then icmp_color="${GREEN}"; fi; local policy=$(check_default_policy); local policy_color="${GREEN}"; if [ "$policy" == "ACCEPT" ]; then policy_color="${RED}"; fi; local fwd_status=$(get_forwarding_status); local fwd_color="${RED}"; if [[ "$fwd_status" == "已开启" ]]; then fwd_color="${GREEN}"; fi; local fw_status=$(get_firewall_status); clear
    echo "======================================================"; echo -e "       IPTables 防火墙管理器 (V40.3.2 - ${YELLOW}${IP_VERSION} 智能守护模式${NC})"; echo -e " (防火墙: ${fw_status} | SSH:${ssh_port} | 策略:${policy_color}${policy}${NC} | 转发:${fwd_color}${fwd_status}${NC})"; echo "======================================================"
    echo -e "--- 主机防护 (INPUT) ---"; echo -e " 1. 新增 IP 到白名单"; echo -e " 2. 新增 IP 到黑名单"; echo -e " 3. 新增 [端口放行] 规则"; echo -e " 4. 新增 [端口封锁] 规则"; echo -e " 5. 黑白名单及端口策略删除"; echo -e " 6. ${BLUE}IP 封锁管理 (Geo-IP 黑名单)${NC}"; echo -e " 7. ${GREEN}IP 许可管理 (Geo-IP 白名单)${NC}"
    echo; echo -e "--- 出站管理 (OUTPUT) ---"; local menu_index=8; echo -e " ${menu_index}. 新增 OUTPUT 规则"; menu_index=$((menu_index+1)); echo -e " ${menu_index}. 删除 OUTPUT 规则"; menu_index=$((menu_index+1));
    # 删除了 FORWARD, NAT, Docker 的菜单项
    echo; echo -e "--- 系统与监控 ---"; echo -e " 20. 查看完整防火墙状态"; echo -e " 21. ${GREEN}查看连接与网络监控${NC}"; echo -e " 22. 切换 ICMP (Ping) 状态 (当前: ${icmp_color}${icmp_status}${NC})"; echo -e " 23. ${YELLOW}切换默认策略 (当前: ${policy_color}${policy}${NC})${NC}"; echo -e " 24. ${YELLOW}重置防火墙为默认结构 (谨慎操作)${NC}"; echo -e " 25. 手动储存所有规则"; echo -e " 26. ${RED}清除所有已建立的连接 (谨慎操作)${NC}"; echo -e " 27. ${YELLOW}调整规则与链路表顺序 (谨慎操作)${NC}"; echo -e " 28. ${YELLOW}Fail2ban 管理中心${NC}"; echo -e " 29. ${GREEN}安装/更新终端快捷命令 (ipt, f2b)${NC}"; echo -e " 30. ${RED}卸载终端快捷命令${NC}"; echo -e " 31. ${BLUE}备份与恢复规则${NC}"
    echo "------------------------------------------"; local switch_option_text=""; if [[ "$IP_VERSION" == "IPv4" ]]; then switch_option_text="切换到 IPv6 管理"; else switch_option_text="切换到 IPv4 管理"; fi; echo -e " s. ${YELLOW}${switch_option_text}${NC}"; echo -e " q. 退出"
    echo "======================================================"; read -p "请输入您的选择: " choice
}
function switch_protocol_and_reload() { if [[ "$IP_VERSION" == "IPv4" ]]; then IPTABLES_CMD="ip6tables"; IP_VERSION="IPv6"; RULES_FILE="$RULES_FILE_V6"; RULES_FILE_RHEL="$RULES_FILE_RHEL_V6"; SAVE_SERVICE_NAME="ip6tables"; SS_FAMILY_FLAG="-6"; ICMP_PROTO="icmpv6"; else IPTABLES_CMD="iptables"; IP_VERSION="IPv4"; RULES_FILE="$RULES_FILE_V4"; RULES_FILE_RHEL="$RULES_FILE_RHEL_V4"; SAVE_SERVICE_NAME="iptables"; SS_FAMILY_FLAG="-4"; ICMP_PROTO="icmp"; fi; echo -e "\n${YELLOW}正在切换到 ${IP_VERSION} 管理模式...${NC}"; load_or_initialize_firewall; echo -e "${GREEN}✓ 已成功加载 ${IP_VERSION} 规则。${NC}"; sleep 1; }

# --- 参数处理与脚本启动 ---
if [[ "$1" == "--fail2ban" ]]; then unattended_dep_deployment; manage_fail2ban_menu; exit 0; fi

# 正常启动流程
unattended_dep_deployment; select_protocol
if [[ "$IP_VERSION" == "IPv4" ]]; then echo -e "\n${BLUE}正在检查 ${IP_VERSION} 转发状态...${NC}"; check_and_enable_forwarding; sleep 1; fi
load_or_initialize_firewall

# 主循环
while true; do
    ensure_output_rule_exists
    show_unified_menu
    case $choice in
        1) add_to_list "白名单" "WHITELIST" "ACCEPT" ;; 2) add_to_list "黑名单" "BLACKLIST" "DROP" ;; 3) manage_port_rule "PORT_ALLOW" "ACCEPT" "放行" ;; 4) manage_port_rule "PORT_DENY" "DROP" "禁止" ;;
        5) interactive_delete_rule ;; 6) manage_geoip ;; 7) manage_geowhitelist ;; 8) add_chain_rule "OUTPUT" ;; 9) delete_chain_rule "OUTPUT" ;;
        # 10) add_chain_rule "FORWARD" ;; 11) delete_chain_rule "FORWARD" ;;
        # 12) if [[ "$IP_VERSION" == "IPv4" ]]; then add_port_forward_rule; fi ;;
        # 13) if [[ "$IP_VERSION" == "IPv4" ]]; then view_delete_port_forward_rules; fi ;;
        # 14) if [[ "$IP_VERSION" == "IPv4" ]]; then manage_docker_menu; fi ;;
        20) show_full_status ;; 21) view_connections ;; 22) toggle_icmp ;; 23) toggle_default_policy ;; 24) start_firewall ;; 25) save_all_rules ;; 26) flush_connections_safely ;;
        27) manage_rule_ordering_menu ;; 28) manage_fail2ban_menu ;; 29) install_as_command ;; 30) uninstall_command ;; 31) manage_backup_restore_menu ;;
        s|S) switch_protocol_and_reload; continue ;; q|Q) echo "正在退出..."; exit 0 ;; *) echo -e "${RED}无效输入...${NC}" ;;
    esac
    echo; read -n 1 -s -r -p "按任意键返回主菜单..."
done
