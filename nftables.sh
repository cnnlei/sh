#!/bin/bash

#================================================================
#
#   文件: nftables.sh
#   描述: Nftables 防火墙可视化管理脚本
#   作者: cnyun.de
#   版本: 1.0
#
#================================================================

# --- 颜色定义 ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m';
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0;0m';

# --- 脚本初始化检查 ---
if [[ $EUID -ne 0 ]]; then echo -e "${RED}错误：此脚本必须以 root 用户权限运行。${NC}"; exit 1; fi

# --- 依赖自动安装 ---
install_dependencies() {
    echo -e "${CYAN}--- 正在检查核心命令依赖 ---${NC}"
    local PKG_MANAGER=""
    local INSTALL_CMD=""
    local UPDATE_CMD=""

    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"
        UPDATE_CMD="apt-get update"
        INSTALL_CMD="apt-get install -y"
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"
        INSTALL_CMD="yum install -y"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
        UPDATE_CMD="pacman -Sy"
        INSTALL_CMD="pacman --noconfirm -S"
    else
        echo -e "${RED}错误: 未能识别出系统的包管理器 (apt, dnf, yum, pacman)。${NC}" >&2
        echo -e "${YELLOW}请您手动安装所需依赖后重试。${NC}" >&2
        # MODIFIED: Added 'sudo' to the manual check list
        for cmd in nft conntrack curl split awk ip ss pgrep systemctl bmon nethogs iftop socat realpath sudo; do
            if ! command -v $cmd &> /dev/null; then
                echo -e "\n${RED}错误：核心命令 '$cmd' 未找到。请先手动安装。${NC}" >&2
                exit 1
            fi
        done
        return 0
    fi

    declare -A CMD_TO_PKG_MAP
    case "$PKG_MANAGER" in
        apt)
            CMD_TO_PKG_MAP=(
                [nft]="nftables" [conntrack]="conntrack" [curl]="curl"
                [split]="coreutils" [awk]="gawk" [ip]="iproute2"
                [ss]="iproute2" [pgrep]="procps" [systemctl]="systemd"
                [bmon]="bmon" [nethogs]="nethogs" [iftop]="iftop" [socat]="socat"
                [realpath]="realpath" [sudo]="sudo" # MODIFIED: Added sudo package
            )
            ;;
        dnf|yum)
            CMD_TO_PKG_MAP=(
                [nft]="nftables" [conntrack]="conntrack-tools" [curl]="curl"
                [split]="coreutils" [awk]="gawk" [ip]="iproute"
                [ss]="iproute" [pgrep]="procps-ng" [systemctl]="systemd"
                [bmon]="bmon" [nethogs]="nethogs" [iftop]="iftop" [socat]="socat"
                [realpath]="coreutils" [sudo]="sudo" # MODIFIED: Added sudo package
            )
            ;;
        pacman)
            CMD_TO_PKG_MAP=(
                [nft]="nftables" [conntrack]="conntrack-tools" [curl]="curl"
                [split]="coreutils" [awk]="gawk" [ip]="iproute2"
                [ss]="iproute2" [pgrep]="procps-ng" [systemctl]="systemd"
                [bmon]="bmon" [nethogs]="nethogs" [iftop]="iftop" [socat]="socat"
                [realpath]="coreutils" [sudo]="sudo" # MODIFIED: Added sudo package
            )
            ;;
    esac

    local missing_pkgs=()
    # MODIFIED: Added 'sudo' to the commands to check
    local cmds_to_check=("nft" "conntrack" "curl" "split" "awk" "ip" "ss" "pgrep" "systemctl" "bmon" "nethogs" "iftop" "socat" "realpath" "sudo")

    for cmd in "${cmds_to_check[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            local pkg_name=${CMD_TO_PKG_MAP[$cmd]}
            if [[ -n "$pkg_name" && ! " ${missing_pkgs[@]} " =~ " ${pkg_name} " ]]; then
                echo -e "${YELLOW}  -> 检测到命令 '$cmd' 缺失 (由软件包 '${pkg_name}' 提供)${NC}"
                missing_pkgs+=("$pkg_name")
            fi
        fi
    done

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        echo -e "\n${CYAN}检测到以下缺失的依赖包: ${missing_pkgs[*]}${NC}"
        read -p "是否要自动安装? (Y/n): " confirm
        confirm=${confirm:-Y}
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            echo -e "${YELLOW}正在更新包列表并安装依赖...${NC}"
            if [[ -n "$UPDATE_CMD" ]]; then
                $UPDATE_CMD
                if [ $? -ne 0 ]; then
                    echo -e "${RED}错误: 包列表更新失败。请检查您的网络和软件源配置。${NC}"
                    exit 1
                fi
            fi
            $INSTALL_CMD "${missing_pkgs[@]}"
            if [ $? -ne 0 ]; then
                echo -e "${RED}错误: 依赖安装失败。请手动安装后重试。${NC}"
                exit 1
            else
                echo -e "${GREEN}依赖已成功安装。脚本将继续运行。${NC}\n"
                sleep 2
            fi
        else
            echo -e "${RED}用户取消安装。脚本无法继续。${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}所有核心依赖均已安装。${NC}\n"
    fi
}

# --- 脚本启动 ---
install_dependencies

# --- 全局变量定义 ---
TABLE_NAME="filter"; INPUT_CHAIN="input"; OUTPUT_CHAIN="output"; USER_CHAIN="USER_RULES";
USER_IP_WHITELIST="USER_IP_WHITELIST"; USER_IP_BLACKLIST="USER_IP_BLACKLIST";
USER_PORT_BLOCK="USER_PORT_BLOCK"; USER_PORT_ALLOW="USER_PORT_ALLOW";
USER_OUT_IP_BLOCK="USER_OUT_IP_BLOCK"; USER_OUT_PORT_BLOCK="USER_OUT_PORT_BLOCK";
F2B_TABLE_NAME="f2b-table"; # MODIFIED: Fail2ban专用表名
F2B_SSH_WHITELIST_SET_V4="F2B_SSH_WHITELIST_V4"; F2B_SSH_WHITELIST_SET_V6="F2B_SSH_WHITELIST_V6";
NFT_CONF_PATH="/etc/nftables.conf";
COUNTRY_IP_DIR="/root/guojia"; CUSTOM_IP_DIR="/root/zd_ip";
BACKUP_DIR="/root/nftables-backup";
SHORTCUT_NAME="nftsh";
# --- [新增] Docker 管理专用变量 ---
DOCKER_USER_CHAIN="DOCKER-USER"
DOCKER_USER_IP_WHITELIST="DOCKER_USER_IP_WHITELIST"
DOCKER_USER_IP_BLACKLIST="DOCKER_USER_IP_BLACKLIST"
DOCKER_USER_PORT_BLOCK="DOCKER_USER_PORT_BLOCK"
DOCKER_USER_PORT_ALLOW="DOCKER_USER_PORT_ALLOW"

# --- 辅助函数 ---
press_any_key() { echo -e "\n${CYAN}请按任意键返回...${NC}"; read -n 1 -s -r; }
validate_ip() { local ip=$1; local ip_family=$2; if [[ "$ip_family" == "ipv4" ]]; then [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && return 0; elif [[ "$ip_family" == "ipv6" ]]; then [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:?$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|^fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}$|^::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$|^([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$ ]] && return 0; fi; return 1; }
validate_ip_or_cidr() { local input="$1"; if [[ "$input" =~ ^@ ]]; then echo "set"; return 0; fi; if [[ "$input" == *":"* ]]; then [[ "$input" =~ ^([0-9a-fA-F:]+/[0-9]{1,3})|([0-9a-fA-F:]{2,})$ ]] && echo "ipv6" && return 0; else [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] && echo "ipv4" && return 0; fi; echo "invalid"; return 1; }
validate_and_format_ports() { local input="$1"; if [[ -z "$input" ]]; then echo ""; return 0; fi; if ! [[ "$input" =~ ^[0-9,-]+$ ]]; then echo "错误: 端口输入包含无效字符。" >&2; return 1; fi; local formatted_items=(); IFS=',' read -ra items <<< "$input"; for item in "${items[@]}"; do if [[ "$item" == *-* ]]; then local start=$(echo "$item" | cut -d- -f1); local end=$(echo "$item" | cut -d- -f2); if ! [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ && "$start" -ge 1 && "$start" -le 65535 && "$end" -ge 1 && "$end" -le 65535 && "$start" -le "$end" ]]; then echo "错误: 端口范围 '$item' 无效。" >&2; return 1; fi; formatted_items+=("$item"); else if ! [[ "$item" =~ ^[0-9]+$ && "$item" -ge 1 && "$item" -le 65535 ]]; then echo "错误: 端口号 '$item' 无效。" >&2; return 1; fi; formatted_items+=("$item"); fi; done; if [ ${#items[@]} -gt 1 ] || [[ "$input" == *-* ]]; then echo "{ $(echo "${formatted_items[*]}" | sed 's/ /, /g') }"; else echo "$input"; fi; return 0; }
select_specific_ip() {
    local ip_family=$1
    local ip_cmd="ip -o addr show"
    if [[ "$ip_family" == "ipv4" ]]; then
        ip_cmd="ip -4 -o addr show"
    elif [[ "$ip_family" == "ipv6" ]]; then
        ip_cmd="ip -6 -o addr show"
    fi

    mapfile -t ips < <($ip_cmd | awk '{split($4, a, "/"); printf "%-20s %s\n", $2, a[1]}')
    
    if [ ${#ips[@]} -eq 0 ]; then
        echo -e "\n${YELLOW}未找到任何可用的 ${ip_family^^} 地址。${NC}" >&2
        return 1
    fi

    while true; do
        echo -e "\n${CYAN}请选择要监听的本机IP地址 ('q'返回上一级):${NC}" >&2
        local i=1
        for ip_info in "${ips[@]}"; do
            echo -e " ${GREEN}$i)${NC} ${ip_info}" >&2
            ((i++))
        done
        read -p "请选择序号: " choice_ip
        if [[ $choice_ip =~ ^[qQ]$ ]]; then
            echo ""
            return 1
        fi
        if [[ "$choice_ip" =~ ^[0-9]+$ && "$choice_ip" -ge 1 && "$choice_ip" -le ${#ips[@]} ]]; then
            local selected_ip
            selected_ip=$(echo "${ips[$((choice_ip-1))]}" | awk '{$1=""; print $0}' | sed 's/^[ \t]*//')
            echo "$selected_ip"
            return 0
        else
            echo -e "${RED}无效选择, 请重新输入。${NC}" >&2
        fi
    done
}
flush_conntrack() {
    local ports_to_flush_str="$1" # 端口可以是 "80,443" 或 "all"

    # 获取当前SSH端口以避免断开连接
    local ssh_ports=()
    local raw_ssh_ports=$(ss -tlpn 2>/dev/null | grep 'sshd' | grep -oE ':[0-9]+' | sed 's/://g' | sort -u)
    if [[ -n "$raw_ssh_ports" ]]; then
        ssh_ports=($raw_ssh_ports)
    fi

    if [[ "$ports_to_flush_str" == "all" ]]; then
        echo -e "${YELLOW}--> 正在清理所有非SSH连接...${NC}"
        conntrack -F
        if [ ${#ssh_ports[@]} -gt 0 ]; then
             echo -e "${CYAN}  (此操作可能会短暂影响除SSH外的所有连接，但您当前的SSH会话是安全的)${NC}"
        fi
    elif [[ -n "$ports_to_flush_str" ]]; then
        local ports=($(echo "$ports_to_flush_str" | tr ',' ' '))
        echo -e "${YELLOW}--> 正在为指定端口执行连接清理: ${ports[*]}...${NC}"
        for p in "${ports[@]}"; do
            if [[ " ${ssh_ports[@]} " =~ " ${p} " ]]; then
                echo -e "${CYAN}  -> 跳过清理SSH端口: ${p}${NC}"
                continue
            fi
            # 执行命令，不检查返回值，因为没有连接可删时也会返回错误
            conntrack -D -p tcp --orig-port-dst "$p" &>/dev/null
            conntrack -D -p udp --orig-port-dst "$p" &>/dev/null
        done
    else
        # 如果没有指定端口，则不执行任何操作
        return 0
    fi
    
    echo -e "${GREEN}  连接清理操作已成功执行。${NC}"
}
apply_and_save_changes() {
    local op_success_code=${1}
    local entity=${2:-}
    local pause_after=${3:-true}
    local rule_type=${4:-""} # 'add_block', 'add_allow', 'del_block', 'del_allow'
    local ports_to_flush=${5:-""} # "80,443" 或 "all"

    if [ "$op_success_code" -ne 0 ]; then
        echo -e "\n${RED}失败: 操作 [${entity}] 失败。${NC}"
        if $pause_after; then press_any_key; fi
        return 1
    fi
    
    echo -e "\n${GREEN}成功: 操作 [${entity}] 已成功执行。${NC}"
    echo -e "${YELLOW}--> 正在自动保存所有规则...${NC}"
    nft list ruleset > ${NFT_CONF_PATH}
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}        规则已永久保存。${NC}"
    else
        echo -e "${RED}        错误: 规则保存失败!${NC}"
    fi

    if [[ "$rule_type" == "add_block" ]] || [[ "$rule_type" == "del_allow" ]]; then
        local flush_arg="all"
        if [[ -n "$ports_to_flush" ]]; then
            flush_arg="$ports_to_flush"
        fi
        flush_conntrack "$flush_arg"
    fi
    
    if $pause_after; then press_any_key; fi
}
# MODIFIED: This function's logic is now handled by the Fail2ban action file.
# It is kept here but effectively disabled to prevent adding conflicting rules.
ensure_ssh_whitelist_rules_exist() {
    # This function's original purpose was to add whitelist rules to the 'filter' table.
    # Per your request, this logic is now integrated directly into the Fail2ban action
    # file ('f2b-table'), making this function's logic obsolete and potentially harmful.
    # It is intentionally left empty.
    :
}
initialize_firewall() {
    if ! nft list chain inet "${TABLE_NAME}" "${USER_CHAIN}" &>/dev/null; then
        echo -e "${YELLOW}未检测到防火墙规则或结构已旧, 正在进行初始化...${NC}"
        nft flush ruleset
        nft add table inet ${TABLE_NAME}
        nft add chain inet ${TABLE_NAME} ${INPUT_CHAIN} '{ type filter hook input priority 0; policy drop; }'
        nft add chain inet ${TABLE_NAME} ${OUTPUT_CHAIN} '{ type filter hook output priority 0; policy accept; }'
        nft add chain inet ${TABLE_NAME} ${USER_CHAIN}
        nft add chain inet ${TABLE_NAME} ${USER_IP_WHITELIST}
        nft add chain inet ${TABLE_NAME} ${USER_IP_BLACKLIST}
        nft add chain inet ${TABLE_NAME} ${USER_PORT_BLOCK}
        nft add chain inet ${TABLE_NAME} ${USER_PORT_ALLOW}
        nft add chain inet ${TABLE_NAME} ${USER_OUT_IP_BLOCK}
        nft add chain inet ${TABLE_NAME} ${USER_OUT_PORT_BLOCK}

        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} ct state established,related accept comment "\"核心:允许已建立的连接\""
        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} iifname lo accept comment "\"核心:允许本地回环接口\""
        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} ip6 nexthdr icmpv6 accept comment "\"核心:允许核心ICMPv6功能\""
        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} ip protocol icmp icmp type echo-request accept comment "\"Allow IPv4 Ping\""
        local ssh_ports_to_add=$(ss -tlpn "sport = :*" 2>/dev/null | grep 'sshd' | grep -oE ':[0-9]+' | sed 's/://g' | sort -u | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$ssh_ports_to_add" ]]; then
            if [[ "$ssh_ports_to_add" == *,* ]]; then
                nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} tcp dport "{ ${ssh_ports_to_add} }" accept comment "\"核心:允许SSH\""
            else
                nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} tcp dport "$ssh_ports_to_add" accept comment "\"核心:允许SSH\""
            fi
        else
            nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} tcp dport 22 accept comment "\"核心:允许SSH(备用)\""
        fi

        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} jump ${USER_CHAIN} comment "\"跳转到用户入站规则主链\""
        nft add rule inet ${TABLE_NAME} ${OUTPUT_CHAIN} jump ${USER_OUT_IP_BLOCK} comment "\"跳转到用户出站IP黑名单\""
        nft add rule inet ${TABLE_NAME} ${OUTPUT_CHAIN} jump ${USER_OUT_PORT_BLOCK} comment "\"跳转到用户出站端口封锁\""

        nft add rule inet ${TABLE_NAME} ${USER_CHAIN} jump ${USER_IP_WHITELIST} comment "\"优先级1:IP白名单\""
        nft add rule inet ${TABLE_NAME} ${USER_CHAIN} jump ${USER_IP_BLACKLIST} comment "\"优先级2:IP黑名单\""
        nft add rule inet ${TABLE_NAME} ${USER_CHAIN} jump ${USER_PORT_ALLOW} comment "\"优先级4:端口放行\""
        nft add rule inet ${TABLE_NAME} ${USER_CHAIN} jump ${USER_PORT_BLOCK} comment "\"优先级3:端口封锁\""
        
        # MODIFIED: SSH Whitelist sets are no longer created here.
        # They are now created as part of the Fail2ban table (`f2b-table`) setup.

        echo -e "${GREEN}防火墙已初始化为全新的多链安全架构。${NC}"
        nft list ruleset > ${NFT_CONF_PATH}
        
        # --- [修改] 将手动提示改为自动设置开机自启 ---
        if ! systemctl is-enabled nftables.service &>/dev/null; then
            echo -e "\n${YELLOW}--> 检测到 nftables 服务未设置开机自启, 正在为您自动设置...${NC}"
            if systemctl enable nftables.service &>/dev/null; then
                echo -e "${GREEN}  -> 设置成功! 防火墙规则将在系统重启后自动加载。${NC}"
            else
                echo -e "${RED}  -> 错误: 设置开机自启失败。您可能需要手动执行 'systemctl enable nftables.service'。${NC}"
            fi
        else
            echo -e "\n${GREEN}--> nftables 服务已设置为开机自启, 无需操作。${NC}"
        fi
        sleep 2

    fi
    # MODIFIED: The compatibility check for old sets is no longer needed here.
    mkdir -p "${COUNTRY_IP_DIR}" "${CUSTOM_IP_DIR}"
}

# --- IP集管理核心功能 ---
process_downloaded_list() { local filepath=$1; local basename=$2; local type=$3; local set_name_v4="set_${type}_${basename}_v4"; local set_name_v6="set_${type}_${basename}_v6"; local v4_file="${filepath}.v4"; local v6_file="${filepath}.v6"; local batch_file="/tmp/nft_batch_$$_${RANDOM}.nft"; local chunk_prefix="/tmp/nft_chunk_$$_${RANDOM}_"; grep -v '^#' "$filepath" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' > "$v4_file"; grep -v '^#' "$filepath" | grep ':' > "$v6_file"; if [ -s "$v4_file" ]; then echo -e "${CYAN}--> 正在处理IPv4 Set: ${set_name_v4}...${NC}"; if nft list set inet "${TABLE_NAME}" "${set_name_v4}" &>/dev/null; then echo -e "${YELLOW}    Set已存在, 正在清空...${NC}"; nft flush set inet "${TABLE_NAME}" "${set_name_v4}"; else echo -e "${GREEN}    Set不存在, 正在创建...${NC}"; nft add set inet "${TABLE_NAME}" "${set_name_v4}" '{ type ipv4_addr; flags interval; }'; fi; split -l 500 "$v4_file" "$chunk_prefix"; local all_ok=true; for chunk in ${chunk_prefix}*; do { echo -n "add element inet ${TABLE_NAME} ${set_name_v4} { "; tr '\n' ',' < "$chunk" | sed 's/,$//'; echo " }"; } > "$batch_file"; if ! nft -f "$batch_file"; then echo -e "${RED}    处理块 ${chunk##*_} 失败。${NC}"; all_ok=false; break; fi; done; if $all_ok; then echo -e "${GREEN}    IPv4 Set填充成功。${NC}"; else echo -e "${RED}    IPv4 Set填充失败。${NC}"; fi; rm -f ${chunk_prefix}*; fi; if [ -s "$v6_file" ]; then echo -e "${CYAN}--> 正在处理IPv6 Set: ${set_name_v6}...${NC}"; if nft list set inet "${TABLE_NAME}" "${set_name_v6}" &>/dev/null; then echo -e "${YELLOW}    Set已存在, 正在清空...${NC}"; nft flush set inet "${TABLE_NAME}" "${set_name_v6}"; else echo -e "${GREEN}    Set不存在, 正在创建...${NC}"; nft add set inet "${TABLE_NAME}" "${set_name_v6}" '{ type ipv6_addr; flags interval; }'; fi; split -l 500 "$v6_file" "$chunk_prefix"; local all_ok=true; for chunk in ${chunk_prefix}*; do { echo -n "add element inet ${TABLE_NAME} ${set_name_v6} { "; tr '\n' ',' < "$chunk" | sed 's/,$//'; echo " }"; } > "$batch_file"; if ! nft -f "$batch_file"; then echo -e "${RED}    处理块 ${chunk##*_} 失败。${NC}"; all_ok=false; break; fi; done; if $all_ok; then echo -e "${GREEN}    IPv6 Set填充成功。${NC}"; else echo -e "${RED}    IPv6 Set填充失败。${NC}"; fi; rm -f ${chunk_prefix}*; fi; rm -f "$v4_file" "$v6_file" "$batch_file"; echo -e "${GREEN}IP集处理完成。${NC}"; }
download_country_list() { clear; echo -e "${BLUE}--- 下载国家IP列表 (GeoIP) [数据源: ipdeny.com] ---${NC}\n"; read -p "请输入两位国家代码 (例如: cn, us, jp): " country_code; country_code=$(echo "$country_code" | tr 'A-Z' 'a-z'); if ! [[ "$country_code" =~ ^[a-z]{2}$ ]]; then echo -e "${RED}错误: 国家代码格式不正确。${NC}"; press_any_key; return; fi; local filepath="${COUNTRY_IP_DIR}/${country_code^^}.txt"; local url_v4="http://www.ipdeny.com/ipblocks/data/countries/${country_code}.zone"; local url_v6="http://www.ipdeny.com/ipv6/ipaddresses/blocks/${country_code}.zone"; > "$filepath"; local v4_success=false; echo -e "${YELLOW}正在从 ${url_v4} 下载 IPv4 地址...${NC}"; if curl --fail -sSLo /tmp/ipv4_data "$url_v4" && [ -s "/tmp/ipv4_data" ]; then cat /tmp/ipv4_data >> "$filepath"; echo -e "${GREEN}IPv4 下载成功。${NC}"; v4_success=true; else echo -e "${RED}IPv4 下载失败 (可能该国家无IPv4数据)。${NC}"; fi; local v6_success=false; echo -e "${YELLOW}正在从 ${url_v6} 下载 IPv6 地址...${NC}"; if curl --fail -sSLo /tmp/ipv6_data "$url_v6" && [ -s "/tmp/ipv6_data" ]; then echo "" >> "$filepath"; cat /tmp/ipv6_data >> "$filepath"; echo -e "${GREEN}IPv6 下载成功。${NC}"; v6_success=true; else echo -e "${RED}IPv6 下载失败 (可能该国家无IPv6数据)。${NC}"; fi; rm -f /tmp/ipv4_data /tmp/ipv6_data; if $v4_success || $v6_success; then echo -e "\n${GREEN}数据已合并保存至 ${filepath}${NC}"; process_downloaded_list "$filepath" "${country_code^^}" "country"; else echo -e "\n${RED}IPv4 和 IPv6 数据均下载失败。${NC}"; rm -f "$filepath"; fi; press_any_key; }
download_custom_list() { clear; echo -e "${BLUE}--- 下载自定义IP列表 ---${NC}\n"; read -p "请输入列表的URL地址 ('q'返回): " url; if [[ $url =~ ^[qQ]$ ]]; then return; fi; read -p "请为该列表命名 (字母/数字/_): " name; name=$(echo "$name" | tr -cd '[:alnum:]_'); if [[ -z "$name" ]]; then echo -e "${RED}错误: 名称不能为空或包含非法字符。${NC}"; press_any_key; return; fi; local filepath="${CUSTOM_IP_DIR}/${name}.txt"; echo -e "${YELLOW}正在从 ${url} 下载...${NC}"; if curl --fail -sSLo "${filepath}.tmp" "$url" && [ -s "${filepath}.tmp" ]; then echo "# SOURCE_URL: ${url}" > "$filepath"; cat "${filepath}.tmp" >> "$filepath"; rm -f "${filepath}.tmp"; echo -e "${GREEN}下载成功, 已保存至 ${filepath}${NC}"; process_downloaded_list "$filepath" "$name" "custom"; else echo -e "${RED}下载失败。请检查URL和网络连接。${NC}"; rm -f "${filepath}.tmp"; fi; press_any_key; }
update_ip_set_from_source() { local set_to_update=$1; echo -e "\n${YELLOW}--- 正在更新IP集: ${set_to_update} ---${NC}"; local type=$(echo "$set_to_update" | awk -F_ '{print $2}'); local basename=$(echo "$set_to_update" | sed -E "s/set_${type}_//; s/_(v4|v6)$//"); local filepath=""; local success=false; if [[ "$type" == "country" ]]; then filepath="${COUNTRY_IP_DIR}/${basename}.txt"; if [ ! -f "$filepath" ]; then echo -e "${RED}错误: 未找到源文件 ${filepath}。无法更新。${NC}"; return 1; fi; local country_code=$(echo "$basename" | tr 'A-Z' 'a-z'); local url_v4="http://www.ipdeny.com/ipblocks/data/countries/${country_code}.zone"; local url_v6="http://www.ipdeny.com/ipv6/ipaddresses/blocks/${country_code}.zone"; > "$filepath"; echo -e "${CYAN}正在从源 [ipdeny.com] 重新下载...${NC}"; curl --fail -sSLo /tmp/ipv4_data "$url_v4" && cat /tmp/ipv4_data >> "$filepath" && success=true; echo "" >> "$filepath"; curl --fail -sSLo /tmp/ipv6_data "$url_v6" && cat /tmp/ipv6_data >> "$filepath" && success=true; rm -f /tmp/ipv4_data /tmp/ipv6_data; elif [[ "$type" == "custom" ]]; then filepath="${CUSTOM_IP_DIR}/${basename}.txt"; if [ ! -f "$filepath" ]; then echo -e "${RED}错误: 未找到源文件 ${filepath}。无法更新。${NC}"; return 1; fi; local source_url=$(grep '^# SOURCE_URL:' "$filepath" | head -n 1 | sed 's/# SOURCE_URL: //'); if [[ -z "$source_url" ]]; then echo -e "${RED}错误: 未能在 ${filepath} 中找到源URL。${NC}"; echo -e "${YELLOW}此列表可能是用旧版脚本创建的, 无法自动更新。请删除后重新添加。${NC}"; return 1; fi; echo -e "${CYAN}正在从源 [${source_url}] 重新下载...${NC}"; if curl --fail -sSLo "${filepath}.tmp" "$source_url" && [ -s "${filepath}.tmp" ]; then echo "# SOURCE_URL: ${source_url}" > "$filepath"; cat "${filepath}.tmp" >> "$filepath"; rm -f "${filepath}.tmp"; success=true; else echo -e "${RED}从自定义URL下载失败。${NC}"; rm -f "${filepath}.tmp"; fi; else echo -e "${RED}错误: 未知的IP集类型 '${type}'。${NC}"; return 1; fi; if $success && [ -s "$filepath" ]; then echo -e "${GREEN}源文件已更新。正在重新处理并加载到nftables...${NC}"; process_downloaded_list "$filepath" "$basename" "$type"; else echo -e "${RED}更新失败: 下载后的源文件为空或下载过程出错。${NC}"; return 1; fi; }
is_set_in_use() { local set_name=$1; if nft --handle list ruleset | grep -q "@${set_name}"; then return 0; else return 1; fi; }
delete_set_and_referencing_rules() { local set_name=$1; echo -e "${YELLOW}正在智能删除IP集 ${set_name}...${NC}"; local rules_deleted=0; local current_table=""; local current_chain=""; while IFS= read -r line; do if [[ "$line" =~ ^[[:space:]]*table[[:space:]]+inet[[:space:]]+([a-zA-Z0-9_-]+) ]]; then current_table="${BASH_REMATCH[1]}"; current_chain=""; continue; fi; if [[ "$line" =~ ^[[:space:]]*chain[[:space:]]+([a-zA-Z0-9_-]+) ]]; then current_chain="${BASH_REMATCH[1]}"; continue; fi; if [[ "$line" =~ "@${set_name}" && "$line" =~ handle[[:space:]]+([0-9]+) ]]; then local handle="${BASH_REMATCH[1]}"; if [[ -n "$current_table" && -n "$current_chain" && -n "$handle" ]]; then echo -e "${CYAN}  -> 发现引用规则 (Table: ${current_table}, Chain: ${current_chain}, Handle: ${handle}), 正在删除...${NC}"; if nft delete rule inet "$current_table" "$current_chain" handle "$handle"; then ((rules_deleted++)); else echo -e "${RED}  -> 错误: 删除引用规则失败 (Handle: ${handle})。操作中止。${NC}"; return 1; fi; fi; fi; done < <(nft --handle list ruleset); if [ $rules_deleted -gt 0 ]; then echo -e "${GREEN}  -> 已成功删除 ${rules_deleted} 条引用规则。${NC}"; fi; nft delete set inet "${TABLE_NAME}" "${set_name}"; if [ $? -eq 0 ]; then echo -e "${GREEN}  -> 已成功删除nftables set: ${set_name}。${NC}"; return 0; else echo -e "${RED}  -> 删除nftables set: ${set_name} 失败。${NC}"; return 1; fi; }
view_delete_lists() { while true; do clear; echo -e "${BLUE}--- 浏览 / 更新 / 删除 IP 集 ---${NC}\n"; mapfile -t all_sets < <(nft list sets 2>/dev/null | awk '/set (set_country_|set_custom_)/ {print $2}' | sort); if [ ${#all_sets[@]} -eq 0 ]; then echo -e "${YELLOW}当前没有任何已创建的IP集。${NC}"; press_any_key; break; fi; echo -e "${CYAN}当前已创建的IP集:${NC}"; local i=1; for set_name in "${all_sets[@]}"; do local display_name=$(echo "$set_name" | sed -E 's/set_(country|custom)_//; s/_(v4|v6)$//'); local type=$(echo "$set_name" | awk -F_ '{print $2}'); local version=$(echo "$set_name" | awk -F_ '{print $NF}'); echo -e " ${GREEN}[$i]${NC} - 名称: ${display_name}, 类型: ${type^}, 版本: ${version^^} ${CYAN}(Set: ${set_name})${NC}"; ((i++)); done; echo -e "\n${PURPLE}------------------------[ 操作 ]------------------------${NC}"; echo -e " ${GREEN}u <编号>${NC}    - 更新指定的IP集 (例如: u 1 3)"; echo -e " ${GREEN}d <编号>${NC}    - 删除指定的IP集 (例如: d 2 4)"; echo -e " ${GREEN}ua${NC}          - ${YELLOW}更新所有${NC} IP集"; echo -e " ${GREEN}da${NC}          - ${RED}删除所有${NC} IP集"; echo -e "\n ${GREEN}q.${NC}           - 返回"; echo -e "${PURPLE}------------------------------------------------------${NC}"; read -p "请输入您的操作和编号: " action_input; if [[ $action_input =~ ^[qQ]$ ]]; then break; fi; local action=$(echo "$action_input" | awk '{print tolower($1)}'); local choices_str=$(echo "$action_input" | cut -d' ' -f2-); if [[ "$action" == "ua" || "$action" == "updateall" ]]; then echo -e "\n${YELLOW}准备更新所有 ${#all_sets[@]} 个IP集...${NC}"; local all_indices=(); for ((j=0; j<${#all_sets[@]}; j++)); do all_indices+=($((j+1))); done; choices_str="${all_indices[*]}"; action="u"; elif [[ "$action" == "da" || "$action" == "deleteall" ]]; then echo -ne "${RED}警告: 您确定要删除所有 ${#all_sets[@]} 个IP集和它们的源文件吗? (y/N): ${NC}"; read confirm; if [[ ! "$confirm" =~ ^[yY]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; continue; fi; echo -e "\n${RED}准备删除所有 ${#all_sets[@]} 个IP集...${NC}"; local all_indices=(); for ((j=0; j<${#all_sets[@]}; j++)); do all_indices+=($((j+1))); done; choices_str="${all_indices[*]}"; action="d"; fi; read -ra choices <<< "$choices_str"; if [ ${#choices[@]} -eq 0 ]; then continue; fi; local sorted_choices=($(for i in "${choices[@]}"; do echo "$i"; done | sort -nur)); local operation_failed=false; case "$action" in u|update) echo -e "\n${YELLOW}准备更新IP集 (编号: ${sorted_choices[*]})...${NC}"; for choice in "${sorted_choices[@]}"; do local index=$((choice-1)); if [[ "$choice" -ge 1 && "$choice" -le ${#all_sets[@]} ]]; then local set_to_update="${all_sets[$index]}"; update_ip_set_from_source "$set_to_update"; if [ $? -ne 0 ]; then operation_failed=true; fi; else echo -e "${RED}无效编号: $choice${NC}"; fi; done; if $operation_failed; then apply_and_save_changes 1 "IP集更新操作" true; else apply_and_save_changes 0 "IP集更新操作" true; fi; ;; d|delete) echo -e "\n${YELLOW}准备删除IP集 (编号: ${sorted_choices[*]})...${NC}"; local sets_to_delete_names=(); for choice in "${sorted_choices[@]}"; do local index=$((choice-1)); if [[ "$choice" -ge 1 && "$choice" -le ${#all_sets[@]} ]]; then sets_to_delete_names+=("${all_sets[$index]}"); fi; done; for set_to_delete in "${sets_to_delete_names[@]}"; do local proceed_with_delete=false; if is_set_in_use "$set_to_delete"; then echo -ne "${RED}警告: IP集 '${set_to_delete}' 正在被规则使用。删除它将同时删除相关规则。您确定吗? (y/N): ${NC}"; read -r confirm_delete; if [[ "$confirm_delete" =~ ^[yY]$ ]]; then echo -e "${YELLOW}用户已确认, 继续删除...${NC}"; proceed_with_delete=true; else echo -e "${YELLOW}操作已取消: IP集 '${set_to_delete}' 未被删除。${NC}"; fi; else echo -e "${CYAN}IP集 '${set_to_delete}' 未被使用, 将直接删除...${NC}"; proceed_with_delete=true; fi; if ! $proceed_with_delete; then continue; fi; delete_set_and_referencing_rules "$set_to_delete"; if [ $? -eq 0 ]; then local basename=$(echo "$set_to_delete" | sed -E 's/_(v4|v6)$//'); local counterpart_v4="${basename}_v4"; local counterpart_v6="${basename}_v6"; local other_set_exists=false; if nft list set inet ${TABLE_NAME} ${counterpart_v4} &>/dev/null; then other_set_exists=true; fi; if nft list set inet ${TABLE_NAME} ${counterpart_v6} &>/dev/null; then other_set_exists=true; fi; if ! $other_set_exists; then echo -e "${CYAN}  -> 未发现此IP集的其他版本 (v4/v6)，将尝试删除源文件。${NC}"; local type=$(echo "$set_to_delete" | awk -F_ '{print $2}'); local name=$(echo "$basename" | sed "s/set_${type}_//"); local file_to_delete=""; if [[ "$type" == "country" ]]; then file_to_delete="${COUNTRY_IP_DIR}/${name}.txt"; else file_to_delete="${CUSTOM_IP_DIR}/${name}.txt"; fi; if [ -f "$file_to_delete" ]; then rm -f "$file_to_delete"; echo -e "${GREEN}  -> 已删除源文件: ${file_to_delete}${NC}"; fi; fi; else operation_failed=true; fi; done; if $operation_failed; then apply_and_save_changes 1 "删除IP集操作" true "del_block"; else apply_and_save_changes 0 "删除IP集操作" true "del_block"; fi; ;; *) echo -e "${RED}无效操作。请输入 'u', 'd', 'ua', 'da', 或 'q'。${NC}"; sleep 2; ;; esac; done; }
ipset_manager_menu() { while true; do clear; echo -e "${PURPLE}======================================================${NC}"; echo -e "                                      ${CYAN}IP 集管理中心${NC}"; echo -e "${PURPLE}======================================================${NC}"; echo -e " ${GREEN}1.${NC} 下载国家IP列表 (GeoIP)"; echo -e " ${GREEN}2.${NC} 下载自定义IP列表"; echo -e " ${GREEN}3.${NC} 浏览/更新/删除 IP 集"; echo -e "\n ${GREEN}q.${NC} 返回主菜单"; echo -e "${PURPLE}------------------------------------------------------${NC}"; read -p "请输入您的选项: " choice; case $choice in 1) download_country_list ;; 2) download_custom_list ;; 3) view_delete_lists ;; q|Q) break ;; *) echo -e "\n${RED}无效选项。${NC}"; sleep 1 ;; esac; done; }

# --- 交互式选择函数 ---
select_from_ipset() {
    local mode=${1:-"default"} # 可选参数: 'include_all'
    
    # 基础命令, 获取所有用户可操作的 set
    local base_cmd="nft list sets 2>/dev/null | awk '/set (set_country_|set_custom_|F2B_SSH_WHITELIST_)/ {print \$2}'"

    # 默认情况下，我们排除专用的SSH白名单，因为它们通常是“目标”而不是“来源”
    if [[ "$mode" == "include_all" ]]; then
        # 仅在极少数需要时才包含所有 set
        mapfile -t sets < <(eval "$base_cmd" | sort)
    else
        # 默认行为：过滤掉 F2B_SSH_WHITELIST_*
        mapfile -t sets < <(eval "$base_cmd" | grep -v '^F2B_SSH_WHITELIST_')
    fi

    if [ ${#sets[@]} -eq 0 ]; then
        echo -e "\n${YELLOW}当前没有任何可用的IP集 (已排除SSH白名单)。${NC}" >&2
        echo -e "${YELLOW}请先通过 [IP 集管理] 下载。${NC}" >&2
        return 1
    fi
    
    while true; do
        echo -e "\n${CYAN}请选择要操作的IP集 ('q'返回):${NC}" >&2
        local i=1
        for s in "${sets[@]}"; do
            local ip_ver="IPv4"
            if [[ "$s" == *_v6 ]] || [[ "$s" == *_V6 ]]; then ip_ver="IPv6"; fi
            local purpose=""
            if [[ "$s" == F2B_SSH* ]]; then purpose="${PURPLE}[SSH白名单专用]${NC} "; fi
            echo -e " ${GREEN}$i)${NC} ${purpose}$s ${YELLOW}[${ip_ver}]${NC}" >&2
            ((i++))
        done
        read -p "请选择序号: " choice
        if [[ $choice =~ ^[qQ]$ ]]; then return 1; fi
        if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#sets[@]} ]]; then
            echo "${sets[$((choice-1))]}"
            return 0
        else
            echo -e "${RED}无效选择, 请重新输入。${NC}" >&2
        fi
    done
}
select_host_target() { local ip_type=${1:-""}; local direction=$2; local target_type=""; local target_value=""; while true; do echo -e "\n${CYAN}请选择此规则的应用目标:${NC}" >&2; echo -e " 1) 所有IP与接口 (默认)" >&2; if [[ "$direction" == "in" ]]; then echo -e " 2) 指定的目标IP地址" >&2; echo -e " 3) 指定的输入网络接口" >&2; elif [[ "$direction" == "out" ]]; then echo -e " 2) 指定的源IP地址" >&2; echo -e " 3) 指定的输出网络接口" >&2; fi; echo -e " q) 返回" >&2; local choice_target; read -p "#? (默认: 1): " choice_target; choice_target=${choice_target:-1}; case $choice_target in 1) echo ":"; return 0;; 2) local ip_cmd="ip -o addr show"; if [[ "$ip_type" == "ipv4" ]]; then ip_cmd="ip -4 -o addr show"; elif [[ "$ip_type" == "ipv6" ]]; then ip_cmd="ip -6 -o addr show"; fi; mapfile -t ips < <($ip_cmd | awk '!/ lo / {split($4, a, "/"); printf "%-20s %s\n", $2, a[1]}'); if [ ${#ips[@]} -eq 0 ]; then echo -e "\n${YELLOW}未找到可用的、与源IP版本匹配的本机IP地址。${NC}" >&2; return 1; fi; while true; do echo -e "\n${CYAN}请选择此规则绑定的本机IP地址 ('q'返回上一级):${NC}" >&2; local i=1; for ip_info in "${ips[@]}"; do echo -e " ${GREEN}$i)${NC} ${ip_info}" >&2; ((i++)); done; read -p "请选择序号: " choice_ip; if [[ $choice_ip =~ ^[qQ]$ ]]; then break; fi; if [[ "$choice_ip" =~ ^[0-9]+$ && "$choice_ip" -ge 1 && "$choice_ip" -le ${#ips[@]} ]]; then target_value=$(echo "${ips[$((choice_ip-1))]}" | awk '{$1=""; print $0}' | sed 's/^[ \t]*//'); if [[ "$direction" == "in" ]]; then echo "daddr:${target_value}"; else echo "saddr:${target_value}"; fi; return 0; else echo -e "${RED}无效选择, 请重新输入。${NC}" >&2; fi; done ;; 3) mapfile -t interfaces < <(ip -o link show | awk -F': ' '!/ lo/ {print $2}' | sed 's/@.*//' | sort -u); if [ ${#interfaces[@]} -eq 0 ]; then echo -e "\n${YELLOW}未找到可用的网络接口。${NC}" >&2; return 1; fi; while true; do echo -e "\n${CYAN}请选择此规则绑定的网络接口 ('q'返回上一级):${NC}" >&2; local i=1; for iface in "${interfaces[@]}"; do echo -e " ${GREEN}$i)${NC} ${iface}" >&2; ((i++)); done; read -p "请选择序号: " choice_iface; if [[ $choice_iface =~ ^[qQ]$ ]]; then break; fi; if [[ "$choice_iface" =~ ^[0-9]+$ && "$choice_iface" -ge 1 && "$choice_iface" -le ${#interfaces[@]} ]]; then if [[ "$direction" == "in" ]]; then echo "iifname:${interfaces[$((choice_iface-1))]}"; else echo "oifname:${interfaces[$((choice_iface-1))]}"; fi; return 0; else echo -e "${RED}无效选择, 请重新输入。${NC}" >&2; fi; done ;; [qQ]) return 1 ;; *) echo -e "${RED}无效选择, 请重新输入。${NC}" >&2;; esac; done; }

# --- 规则添加/删除功能 ---
add_rule_ip_based() { local direction=$1; local action=$2; local title=$3; local target_chain=""; local rule_ip_prop; local ip_input=""; local is_set=false; local final_status=0; local ip_type=""; local rule_type=""; if [[ "$direction" == "in" ]]; then if [[ "$action" == "accept" ]]; then target_chain="${USER_IP_WHITELIST}"; rule_type="add_allow"; else target_chain="${USER_IP_BLACKLIST}"; rule_type="add_block"; fi; rule_ip_prop="saddr"; elif [[ "$direction" == "out" ]]; then target_chain="${USER_OUT_IP_BLOCK}"; action="drop"; rule_ip_prop="daddr"; rule_type="add_block"; else echo -e "${RED}错误: 无效的规则方向。${NC}"; press_any_key; return; fi; clear; echo -e "${BLUE}--- ${title} ---${NC}\n"; echo -e "${CYAN}请选择操作对象:${NC}"; echo " 1) 手动输入IP/网段 (默认)"; echo " 2) 从已有的IP集中选择"; local choice_obj; read -p "#? (默认: 1): " choice_obj; choice_obj=${choice_obj:-1}; local prompt=""; if [[ "$direction" == "in" ]]; then prompt="请输入源IP地址或网段 ('q'返回): "; else prompt="请输入目标IP地址或网段 ('q'返回): "; fi; if [[ "$choice_obj" == "2" ]]; then ip_input=$(select_from_ipset); if [ $? -ne 0 ]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; is_set=true; if [[ "$ip_input" == *_v6 ]] || [[ "$ip_input" == *_V6 ]]; then ip_type="ipv6"; else ip_type="ipv4"; fi; else while true; do read -p "$prompt" ip_input; if [[ $ip_input =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; ip_type=$(validate_ip_or_cidr "$ip_input"); if [[ "$ip_type" != "invalid" ]]; then break; else echo -e "${RED}IP地址格式错误。${NC}"; fi; done; fi; while true; do echo -e "\n${CYAN}请选择协议:${NC}"; echo -e " 1) 所有协议 (默认)"; echo -e " 2) TCP"; echo -e " 3) UDP"; echo -e " 4) ICMP"; echo -e " 5) ICMPv6"; echo -e " 6) 手动输入"; echo -e " q) 返回"; read -p "#? (默认: 1): " choice; choice=${choice:-1}; case $choice in 1) protocol=""; break;; 2) protocol="tcp"; break;; 3) protocol="udp"; break;; 4) protocol="icmp"; break;; 5) protocol="icmpv6"; break;; 6) read -p "协议名: " protocol; break;; [qQ]) echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return ;; *) echo -e "${RED}无效选择, 请重新输入。${NC}";; esac; done; local port_input=""; local formatted_ports=""; if [[ -n "$protocol" && "$protocol" != "icmp" && "$protocol" != "icmpv6" ]]; then while true; do echo -e "\n${CYAN}支持格式 - 单个:80, 多个:80,443, 范围:1000-2000${NC}"; read -p "请输入端口('q'返回,留空为所有): " port_input; if [[ $port_input =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; formatted_ports=$(validate_and_format_ports "$port_input"); if [ $? -eq 0 ]; then break; else echo -e "${RED}${formatted_ports}${NC}"; fi; done; fi; local target_info; target_info=$(select_host_target "$ip_type" "$direction"); if [ $? -ne 0 ] || [[ -z "$target_info" ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; local target_type=$(echo "$target_info" | cut -d: -f1); local target_value=$(echo "$target_info" | cut -d: -f2-); read -p "请输入备注 (可选, 'q'取消): " comment; if [[ $comment =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; local base_cmd=("nft" "insert" "rule" "inet" "${TABLE_NAME}" "${target_chain}"); local entity_desc="${title} ${ip_input}"; if [[ -n "$target_value" ]]; then entity_desc+=" -> ${target_type}:\"${target_value}\""; fi; if [[ -n "$protocol" ]]; then entity_desc+=" [协议:${protocol}]"; fi; if [[ -n "$port_input" ]]; then entity_desc+=" [端口:${port_input}]"; fi; local cmd_args=("${base_cmd[@]}"); local ip_prefix="ip"; if [[ "$ip_type" == "ipv6" ]]; then ip_prefix="ip6"; fi; if [[ -n "$target_value" ]]; then cmd_args+=("$ip_prefix" "$target_type" "\"$target_value\""); fi; if $is_set; then cmd_args+=("$ip_prefix" "$rule_ip_prop" "@$ip_input"); else cmd_args+=("$ip_prefix" "$rule_ip_prop" "$ip_input"); fi; if [[ -n "$protocol" ]]; then if [[ -n "$formatted_ports" ]]; then cmd_args+=("$protocol" "dport" "$formatted_ports"); else cmd_args+=("meta" "l4proto" "$protocol"); fi; fi; local rule_comment="${comment:-Rule_for_${ip_input}}"; cmd_args+=("$action" "comment" "\"$rule_comment\""); echo -e "${YELLOW}执行: ${cmd_args[*]}${NC}"; "${cmd_args[@]}"; final_status=$?; apply_and_save_changes $final_status "$entity_desc" "true" "$rule_type" "$port_input"; }
add_rule_port_based() { local direction=$1; local action=$2; local title=$3; local target_chain=""; local final_status=0; local ip_input="" ip_type="" is_set=false; local rule_type=""; if [[ "$direction" == "in" ]]; then if [[ "$action" == "accept" ]]; then target_chain="${USER_PORT_ALLOW}"; rule_type="add_allow"; else target_chain="${USER_PORT_BLOCK}"; rule_type="add_block"; fi; elif [[ "$direction" == "out" ]]; then target_chain="${USER_OUT_PORT_BLOCK}"; action="drop"; rule_type="add_block"; else echo -e "${RED}错误: 无效的规则方向。${NC}"; press_any_key; return; fi; clear; echo -e "${BLUE}--- ${title} ---${NC}\n"; while true; do echo -e "${CYAN}支持格式 - 单个:80, 多个:80,443, 范围:1000-2000${NC}"; read -p "请输入要操作的端口 (输入 'q' 返回): " port_input; if [[ $port_input =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; formatted_ports=$(validate_and_format_ports "$port_input"); if [[ $? -eq 0 && -n "$formatted_ports" ]]; then break; else echo -e "${RED}输入无效或为空。${NC}"; fi; done; local ip_prop_text; [[ "$direction" == "in" ]] && ip_prop_text="来源" || ip_prop_text="目标"; echo -e "\n${CYAN}请选择此规则的IP${ip_prop_text}:${NC}"; echo " 1) 所有IP (默认)"; echo " 2) 指定单个IP/网段"; echo " 3) 从已有的IP集中选择"; local choice_ip_source; read -p "#? (默认: 1): " choice_ip_source; choice_ip_source=${choice_ip_source:-1}; case $choice_ip_source in 2) local prompt="请输入${ip_prop_text}IP地址或网段 ('q'返回): "; while true; do read -p "$prompt" ip_input; if [[ $ip_input =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; ip_type=$(validate_ip_or_cidr "$ip_input"); if [[ "$ip_type" != "invalid" ]]; then break; else echo -e "${RED}IP地址格式错误。${NC}"; fi; done ;; 3) ip_input=$(select_from_ipset); if [ $? -ne 0 ]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; is_set=true; if [[ "$ip_input" == *_v6 ]] || [[ "$ip_input" == *_V6 ]]; then ip_type="ipv6"; else ip_type="ipv4"; fi ;; *) ip_input="" ;; esac; local target_info; target_info=$(select_host_target "$ip_type" "$direction"); if [ $? -ne 0 ] || [[ -z "$target_info" ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; local target_type=$(echo "$target_info" | cut -d: -f1); local target_value=$(echo "$target_info" | cut -d: -f2-); while true; do echo -e "\n${CYAN}请选择协议:${NC}"; echo -e " 1) All (TCP+UDP) (默认)"; echo -e " 2) TCP"; echo -e " 3) UDP"; echo -e " q) 返回"; read -p "#? (默认: 1. All): " choice; choice=${choice:-1}; case $choice in 1) protocols_to_add=("tcp" "udp"); protocol_desc="TCP+UDP"; break;; 2) protocols_to_add=("tcp"); protocol_desc="TCP"; break;; 3) protocols_to_add=("udp"); protocol_desc="UDP"; break;; [qQ]) echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return;; *) echo -e "${RED}无效选择。${NC}";; esac; done; read -p "请输入备注 (可选, 'q'取消): " comment; if [[ $comment =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi; local command_verb; if [[ "$action" == "accept" ]]; then command_verb="add"; else command_verb="insert"; fi; local entity_desc="${title} 端口:${port_input}"; if [[ -n "$ip_input" ]]; then entity_desc+=" (IP ${ip_prop_text}:${ip_input})"; fi; if [[ -n "$target_value" ]]; then entity_desc+=" -> ${target_type}:\"${target_value}\""; fi; entity_desc+=" [协议: ${protocol_desc}]"; for proto in "${protocols_to_add[@]}"; do local full_comment="${comment:-${action^}_Port_$(echo "$port_input" | sed 's/,/_/g')}_${proto}}"; local base_cmd_args=("nft" "${command_verb}" "rule" "inet" "${TABLE_NAME}" "${target_chain}"); if [[ -n "$target_value" ]]; then local host_ip_version=$(validate_ip_or_cidr "$target_value"); if [[ "$host_ip_version" == "ipv6" ]]; then base_cmd_args+=("ip6"); elif [[ "$host_ip_version" == "ipv4" ]]; then base_cmd_args+=("ip"); fi; base_cmd_args+=("$target_type" "\"$target_value\""); fi; if [[ -n "$ip_input" ]]; then local ip_prop; [[ "$direction" == "in" ]] && ip_prop="saddr" || ip_prop="daddr"; local ip_prefix; [[ "$ip_type" == "ipv6" ]] && ip_prefix="ip6" || ip_prefix="ip"; base_cmd_args+=("$ip_prefix" "$ip_prop"); if $is_set; then base_cmd_args+=("@$ip_input"); else base_cmd_args+=("$ip_input"); fi; fi; base_cmd_args+=("$proto" "dport" "$formatted_ports" "$action" "comment" "\"$full_comment\""); echo -e "${YELLOW}执行命令: ${base_cmd_args[*]}${NC}"; "${base_cmd_args[@]}"; if [ $? -ne 0 ]; then final_status=1; fi; done; apply_and_save_changes $final_status "$entity_desc" "true" "$rule_type" "$port_input"; }
# [第二部分开始]

# [请用这个修复了“错误字符”和“table名缺失”bug的最终版本，完整替换掉旧函数]
edit_rule_interactive() {
    local index=$1
    local rule_text="${all_rules_text[$index]}"
    local handle="${all_rules_handle[$index]}"
    local chain="${all_rules_chain[$index]}"

    # --- 第1步: 将现有规则解析成各个组件 ---
    local saddr=$(echo "$rule_text" | grep -oP 'ip saddr \K[^ ]+|ip6 saddr \K[^ ]+' | sed 's/}//')
    local daddr=$(echo "$rule_text" | grep -oP 'ip daddr \K[^ ]+|ip6 daddr \K[^ ]+' | sed 's/}//')
    local iifname=$(echo "$rule_text" | grep -oP 'iifname \K"[^"]+"' | tr -d '"')
    local oifname=$(echo "$rule_text" | grep -oP 'oifname \K"[^"]+"' | tr -d '"')
    local protocol=$(echo "$rule_text" | grep -oP '(tcp|udp|icmp|icmpv6)(?= dport| sport| type| accept| drop| reject)')
    local dport=$(echo "$rule_text" | grep -oP 'dport \K({ [^}]+ }|[^ ]+)' | sed 's/[{}]//g; s/ //g')
    local sport=$(echo "$rule_text" | grep -oP 'sport \K({ [^}]+ }|[^ ]+)' | sed 's/[{}]//g; s/ //g')
    local comment=$(echo "$rule_text" | grep -oP 'comment \K".*"' | tr -d '"')
    local action=$(echo "$rule_text" | grep -oP '(accept|drop|reject)')

    # --- 核心逻辑：严格根据链名称是否包含 "_OUT_" 来判断规则方向 ---
    local direction="in"
    if [[ "$chain" == *"_OUT_"* ]]; then
        direction="out"
    fi

    while true; do
        clear
        echo -e "${BLUE}--- 交互式编辑规则 #${BASH_REMATCH[1]}$((index + 1)) ---${NC}"
        echo -e "${CYAN}所属表/链:${NC} ${TABLE_NAME} / ${chain}"
        echo -e "${CYAN}当前规则:${NC} $rule_text\n"
        echo -e "${PURPLE}--- 请选择要编辑的项目 ---${NC}"

        if [[ "$direction" == "in" ]]; then
            # --- 入站规则菜单 (saddr=外部, daddr=本机) ---
            echo -e " ${GREEN}1)${NC} 编辑外部源IP: ${YELLOW}${saddr:-Any}${NC}"
            local local_target_in="${daddr:-${iifname}}"
            echo -e " ${GREEN}2)${NC} 编辑本机目标: ${YELLOW}${local_target_in:-Any}${NC}"
            local menu_offset=2
            if [[ -n "$sport" ]]; then ((menu_offset++)); echo -e " ${GREEN}${menu_offset})${NC} 编辑源端口: ${YELLOW}${sport}${NC}"; fi
            if [[ -n "$dport" ]]; then ((menu_offset++)); echo -e " ${GREEN}${menu_offset})${NC} 编辑目标端口: ${YELLOW}${dport}${NC}"; fi
            ((menu_offset++)); echo -e " ${GREEN}${menu_offset})${NC} 编辑备注: ${YELLOW}${comment}${NC}"
        else
            # --- 出站规则菜单 (saddr=本机, daddr=外部) ---
            local local_target_out="${saddr:-${oifname}}"
            echo -e " ${GREEN}1)${NC} 编辑本机源: ${YELLOW}${local_target_out:-Any}${NC}"
            echo -e " ${GREEN}2)${NC} 编辑外部目标IP: ${YELLOW}${daddr:-Any}${NC}"
            local menu_offset=2
            if [[ -n "$sport" ]]; then ((menu_offset++)); echo -e " ${GREEN}${menu_offset})${NC} 编辑源端口: ${YELLOW}${sport}${NC}"; fi
            if [[ -n "$dport" ]]; then ((menu_offset++)); echo -e " ${GREEN}${menu_offset})${NC} 编辑目标端口: ${YELLOW}${dport}${NC}"; fi
            ((menu_offset++)); echo -e " ${GREEN}${menu_offset})${NC} 编辑备注: ${YELLOW}${comment}${NC}"
        fi

        echo -e "\n ${GREEN}s) ${CYAN}保存并应用更改${NC}"
        echo -e " ${GREEN}q) ${RED}放弃更改并返回${NC}"
        echo -e "${PURPLE}-----------------------------${NC}"
        read -p "请选择操作: " edit_choice

        local operation=""
        if [[ "$edit_choice" =~ ^[0-9]+$ ]]; then
            # 重新编写选择逻辑，使其更健壮
            local options_map=()
            if [[ "$direction" == "in" ]]; then
                options_map+=("外部IP")
                options_map+=("本机IP/接口")
                if [[ -n "$sport" ]]; then options_map+=("源端口"); fi
                if [[ -n "$dport" ]]; then options_map+=("目标端口"); fi
                options_map+=("备注")
            else # out
                options_map+=("本机IP/接口")
                options_map+=("外部IP")
                if [[ -n "$sport" ]]; then options_map+=("源端口"); fi
                if [[ -n "$dport" ]]; then options_map+=("目标端口"); fi
                options_map+=("备注")
            fi
            if [[ "$edit_choice" -ge 1 && "$edit_choice" -le ${#options_map[@]} ]]; then
                operation="${options_map[$((edit_choice-1))]}"
            fi
        fi

        case "$edit_choice" in
            [1-9]*)
                if [[ -z "$operation" ]]; then echo -e "${RED}无效选择。${NC}"; sleep 1; continue; fi

                case "$operation" in
                    "外部IP")
                        local prompt_text=$([[ "$direction" == "in" ]] && echo "源" || echo "目标")
                        echo -e "\n${CYAN}--- 正在编辑外部${prompt_text}IP (可以是IP, IP段, 或IP集) ---${NC}"
                        echo "1) 手动输入新 IP/CIDR"; echo "2) 从 IP 集选择"
                        read -p "请选择 (1-2): " type
                        if [[ "$type" == "1" ]]; then
                            read -p "请输入新的外部${prompt_text} IP/CIDR: " new_ip
                            if [[ -n "$new_ip" && "$(validate_ip_or_cidr "$new_ip")" == "invalid" ]]; then echo -e "${RED}IP/CIDR 格式无效。${NC}"; sleep 2; continue; fi
                            [[ "$direction" == "in" ]] && saddr=$new_ip || daddr=$new_ip
                        elif [[ "$type" == "2" ]]; then
                            new_ip_set=$(select_from_ipset)
                            if [ $? -eq 0 ]; then [[ "$direction" == "in" ]] && saddr="@${new_ip_set}" || daddr="@${new_ip_set}"; fi
                        fi
                        ;;
                    "本机IP/接口")
                        local prompt_text=$([[ "$direction" == "in" ]] && echo "目标" || echo "源")
                        echo -e "\n${CYAN}--- 正在编辑本机${prompt_text} (可以是本机IP或网卡) ---${NC}"
                        local target_info=$(select_host_target "" "$direction")
                        if [ $? -eq 0 ]; then
                            if [[ "$direction" == "in" ]]; then daddr=""; iifname=""; else saddr=""; oifname=""; fi
                            local target_type=$(echo "$target_info" | cut -d: -f1); local target_value=$(echo "$target_info" | cut -d: -f2-)
                            if [[ "$target_type" == "daddr" ]]; then daddr=$target_value;
                            elif [[ "$target_type" == "saddr" ]]; then saddr=$target_value;
                            elif [[ "$target_type" == "iifname" ]]; then iifname=$target_value;
                            elif [[ "$target_type" == "oifname" ]]; then oifname=$target_value;
                            fi
                        fi
                        ;;
                    "源端口"|"目标端口")
                        local port_type=$([[ "$operation" == "源端口" ]] && echo "sport" || echo "dport")
                        echo -e "\n${CYAN}--- 正在编辑${port_type} ---${NC}"
                        read -p "请输入新端口 (单个:80, 多个:80,443, 范围:1000-2000): " new_port_input
                        formatted_ports=$(validate_and_format_ports "$new_port_input")
                        if [ $? -eq 0 ]; then
                            if [[ "$port_type" == "sport" ]]; then sport=$(echo "$formatted_ports" | sed 's/[{}]//g; s/ //g');
                            else dport=$(echo "$formatted_ports" | sed 's/[{}]//g; s/ //g'); fi
                        else echo -e "${RED}${formatted_ports}${NC}"; sleep 2;
                        fi
                        ;;
                    "备注")
                        echo -e "\n${CYAN}--- 正在编辑备注 ---${NC}"; read -p "请输入新备注: " comment
                        ;;
                esac
                ;;
            s|S)
                local cmd_str="nft replace rule inet ${TABLE_NAME} ${chain} handle ${handle}"
                local remote_ip=$([[ "$direction" == "in" ]] && echo "$saddr" || echo "$daddr")
                local local_ip=$([[ "$direction" == "in" ]] && echo "$daddr" || echo "$saddr")
                local ip_prefix="ip"
                if [[ "$(validate_ip_or_cidr "$remote_ip")" == "ipv6" || "$(validate_ip_or_cidr "$local_ip")" == "ipv6" ]]; then
                    ip_prefix="ip6"
                fi

                if [[ "$direction" == "in" ]]; then
                    if [[ -n "$iifname" ]]; then cmd_str+=" iifname \\\"$iifname\\\""; fi
                    if [[ -n "$daddr" ]]; then cmd_str+=" $ip_prefix daddr $daddr"; fi
                    if [[ -n "$saddr" ]]; then cmd_str+=" $ip_prefix saddr $saddr"; fi
                else # out
                    if [[ -n "$oifname" ]]; then cmd_str+=" oifname \\\"$oifname\\\""; fi
                    if [[ -n "$saddr" ]]; then cmd_str+=" $ip_prefix saddr $saddr"; fi
                    if [[ -n "$daddr" ]]; then cmd_str+=" $ip_prefix daddr $daddr"; fi
                fi

                if [[ -n "$protocol" ]]; then
    # 智能判断：如果规则里有具体的端口，才直接使用协议名称
    if [[ -n "$sport" || -n "$dport" ]]; then
        cmd_str+=" $protocol"
        if [[ -n "$sport" ]]; then cmd_str+=" sport $(validate_and_format_ports "$sport")"; fi
        if [[ -n "$dport" ]]; then cmd_str+=" dport $(validate_and_format_ports "$dport")"; fi
    else
        # 如果规则里没有端口（即匹配所有端口），必须使用 'meta l4proto' 语法
        cmd_str+=" meta l4proto $protocol"
    fi
fi

                cmd_str+=" $action comment \\\"$comment\\\""

                echo -e "\n${YELLOW}准备执行替换命令...${NC}"; echo "$cmd_str"
                read -p "确认应用以上更改吗? (Y/n): " confirm_apply
                confirm_apply=${confirm_apply:-Y}
                if [[ "$confirm_apply" =~ ^[yY]$ ]]; then
                    if eval "$cmd_str"; then
                        apply_and_save_changes 0 "编辑规则 #${BASH_REMATCH[1]}$((index + 1))" false
                    else
                        apply_and_save_changes 1 "编辑规则 #${BASH_REMATCH[1]}$((index + 1))" false
                    fi
                    return 0
                else
                    echo -e "${YELLOW}操作已取消。${NC}"; sleep 1
                fi
                ;;
            q|Q)
                echo -e "\n${YELLOW}已放弃所有更改。${NC}"; return 1
                ;;
            *)
                echo -e "${RED}无效选择。${NC}"; sleep 1
                ;;
        esac
    done
}
# [请用下面的代码替换掉您原有的整个同名函数]
edit_delete_rule_visual() {
    local user_chains=("${USER_IP_WHITELIST}" "${USER_IP_BLACKLIST}" "${USER_PORT_BLOCK}" "${USER_PORT_ALLOW}" "${USER_OUT_IP_BLOCK}" "${USER_OUT_PORT_BLOCK}")

    while true; do
        clear
        echo -e "${BLUE}--- 删除/排序/编辑 用户自定义规则 (终极修正版) ---${NC}\n"
        local i=1
        # 在函数作用域内声明数组，以便其他函数可以访问
        all_rules_text=()
        all_rules_handle=()
        all_rules_chain=()
        all_rules_action=()
        all_rules_ports=()
        declare -A chain_indices

        echo -e "${CYAN}当前可操作的所有用户规则 (已按优先级排序):${NC}"
        for chain_name in "${user_chains[@]}"; do
            local all_lines_in_chain=()
            mapfile -t all_lines_in_chain < <(nft --handle list chain inet ${TABLE_NAME} "${chain_name}")
            
            local rules_in_chain=()
            for line in "${all_lines_in_chain[@]}"; do
                if ! [[ "$line" =~ ^[[:space:]]*chain ]]; then
                    rules_in_chain+=("$line")
                fi
            done
            
            if [ ${#rules_in_chain[@]} -eq 0 ]; then
                continue
            fi

            echo -e "${PURPLE}--- Chain: ${chain_name} (规则 #${i} 到 #$((i + ${#rules_in_chain[@]} - 1))) ---${NC}"
            chain_indices[$chain_name, "start"]=$i
            
            for rule in "${rules_in_chain[@]}"; do
                local handle=$(echo "$rule" | awk '/handle/ {print $NF}')
                if [[ -n "$handle" ]]; then
                    echo -e "${GREEN}[$i]${NC} $rule"
                    local action=$(echo "$rule" | awk '{ for(j=1; j<=NF; j++) { if ($j == "accept" || $j == "drop") { print $j; break; } } }')
                    local ports=$(echo "$rule" | grep -oP '(dport|sport)\s*\{?\s*[\d,-]+\s*\}?|(dport|sport)\s*\d+' | sed -E 's/(dport|sport)\s*\{?\s*//; s/\s*\}?//; s/,\s*/,/g')
                    all_rules_text+=("$rule")
                    all_rules_handle+=("$handle")
                    all_rules_chain+=("$chain_name")
                    all_rules_action+=("$action")
                    all_rules_ports+=("$ports")
                    ((i++))
                fi
            done
            chain_indices[$chain_name, "end"]=$((i-1))
        done

        if [ ${#all_rules_handle[@]} -eq 0 ]; then
            echo -e "\n${YELLOW}没有用户添加的规则可供操作。${NC}"; press_any_key; break
        fi

        echo -e "\n${CYAN}操作提示: 'd <编号>'(删除), 'm <编号>'(移动), 'e <编号>'(编辑), 'da'(全删), 'q'(返回).${NC}"
        read -p "请输入您的操作和编号: " action_input

        if [[ $action_input =~ ^[qQ]$ ]]; then break; fi

        local action=$(echo "$action_input" | awk '{print tolower($1)}')
        local choices_str=$(echo "$action_input" | cut -d' ' -f2-)

        case "$action" in
            da|deleteall)
                read -p "警告: 您确定要删除所有 ${#all_rules_handle[@]} 条用户规则吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    for chain_name in "${user_chains[@]}"; do nft flush chain inet "${TABLE_NAME}" "$chain_name"; done
                    apply_and_save_changes 0 "删除所有用户规则" false "del_allow" "all"
                    echo -e "${GREEN}所有规则已删除, 正在刷新...${NC}"; sleep 1
                else
                    echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1
                fi
                continue
                ;;
            d|delete)
                read -ra choices <<< "$choices_str"
                if [ ${#choices[@]} -eq 0 ]; then echo -e "\n${RED}输入为空或未提供编号。${NC}"; sleep 1; continue; fi
                
                local valid_choices=true
                for choice in "${choices[@]}"; do
                    if ! [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#all_rules_handle[@]} ]]; then
                        echo -e "\n${RED}输入错误: '$choice' 不是一个有效的编号。${NC}"; sleep 2; valid_choices=false; break
                    fi
                done
                if ! $valid_choices; then continue; fi

                local sorted_choices=($(for i in "${choices[@]}"; do echo "$i"; done | sort -nur))
                echo -e "${YELLOW}准备删除规则编号: ${sorted_choices[*]}...${NC}"
                local final_success=0; local deleted_count=0; local ports_to_flush_set=() rule_type_to_set=""
                for choice in "${sorted_choices[@]}"; do
                    local index=$((choice-1))
                    local handle_to_delete=${all_rules_handle[$index]}
                    local chain_to_delete_from=${all_rules_chain[$index]}
                    local action_of_rule=${all_rules_action[$index]}
                    local ports_of_rule=${all_rules_ports[$index]}
                    
                    nft delete rule inet "${TABLE_NAME}" "${chain_to_delete_from}" handle "${handle_to_delete}"
                    if [ $? -eq 0 ]; then
                        ((deleted_count++));
                        if [[ "$action_of_rule" == "accept" ]]; then rule_type_to_set="del_allow"; fi
                        if [[ -n "$ports_of_rule" ]]; then ports_to_flush_set+=($ports_of_rule); fi
                    else
                        final_success=1
                    fi
                done
                local ports_str=$(IFS=,; echo "${ports_to_flush_set[*]}")
                apply_and_save_changes $final_success "删除 ${deleted_count} 条规则" false "$rule_type_to_set" "$ports_str"
                echo -e "${GREEN}操作完成, 正在刷新列表...${NC}"; sleep 1
                ;;
            m|move)
                read -ra choices <<< "$choices_str"
                if [ ${#choices[@]} -ne 1 ]; then
                    echo -e "\n${RED}错误: '移动' 操作只需一个参数: 'm <要移动的规则编号>'。${NC}"; sleep 2; continue
                fi
                local source_choice=${choices[0]}
                if ! [[ "$source_choice" =~ ^[0-9]+$ && "$source_choice" -ge 1 && "$source_choice" -le ${#all_rules_handle[@]} ]]; then
                    echo -e "\n${RED}输入错误: '$source_choice' 不是一个有效的编号。${NC}"; sleep 2; continue
                fi
                
                local source_index=$((source_choice-1))
                local source_chain=${all_rules_chain[$source_index]}
                local chain_start_idx=${chain_indices[$source_chain, "start"]}
                local chain_end_idx=${chain_indices[$source_chain, "end"]}

                clear
                echo -e "${BLUE}--- 移动规则 #${source_choice} ---${NC}"
                echo -e "${YELLOW}当前规则:${NC} ${all_rules_text[$source_index]}"
                echo -e "${CYAN}所在链:${NC} ${source_chain} (范围: #${chain_start_idx} - #${chain_end_idx})\n"
                
                echo -e "${PURPLE}--- 请选择移动方式 ---${NC}"
                if [[ "$source_choice" -ne "$chain_start_idx" ]]; then
                    echo -e " ${GREEN}t${NC}    - 置顶 (移至 #${chain_start_idx} 位置)"
                    echo -e " ${GREEN}u${NC}    - 上移一位"
                fi
                if [[ "$source_choice" -ne "$chain_end_idx" ]]; then
                    echo -e " ${GREEN}b${NC}    - 置底 (移至 #${chain_end_idx} 之后)"
                    echo -e " ${GREEN}d${NC}    - 下移一位"
                fi
                echo -e " ${GREEN}s <编号>${NC}  - 与规则 <编号> 交换位置"
                echo -e " ${GREEN}bp <编号>${NC} - 移至规则 <编号> 之前 (Before Position)"
                echo -e " ${GREEN}ap <编号>${NC} - 移至规则 <编号> 之后 (After Position)"
                echo -e "\n ${GREEN}q${NC} - 取消移动"
                echo -e "${PURPLE}----------------------${NC}"

                read -p "请输入移动指令: " move_cmd_input
                if [[ $move_cmd_input =~ ^[qQ]$ ]]; then continue; fi

                local move_action=$(echo "$move_cmd_input" | awk '{print tolower($1)}')
                local dest_choice=$(echo "$move_cmd_input" | awk '{print $2}')

                local source_handle=${all_rules_handle[$source_index]}
                local rule_body=$(echo "${all_rules_text[$source_index]}" | sed 's/ handle [0-9]*$//')
                local final_status=-1 # -1:未执行, 0:成功, 1:失败
                local op_desc=""

                # --- 核心移动逻辑 ---
                case "$move_action" in
                    t|top)
                        if [[ "$source_choice" -ne "$chain_start_idx" ]]; then
                            local target_handle=${all_rules_handle[$((chain_start_idx-1))]}
                            echo -e "\n${YELLOW}正在置顶规则 #${source_choice}...${NC}"
                            nft insert rule inet "${TABLE_NAME}" "${source_chain}" handle "${target_handle}" ${rule_body} && final_status=0
                            op_desc="置顶规则 #${source_choice}"
                        fi
                        ;;
                    b|bottom)
                        if [[ "$source_choice" -ne "$chain_end_idx" ]]; then
                            echo -e "\n${YELLOW}正在置底规则 #${source_choice}...${NC}"
                            nft add rule inet "${TABLE_NAME}" "${source_chain}" ${rule_body} && final_status=0
                            op_desc="置底规则 #${source_choice}"
                        fi
                        ;;
                    u|up)
                        if [[ "$source_choice" -ne "$chain_start_idx" ]]; then
                            local target_handle=${all_rules_handle[$((source_index-1))]}
                            echo -e "\n${YELLOW}正在上移规则 #${source_choice}...${NC}"
                            nft insert rule inet "${TABLE_NAME}" "${source_chain}" handle "${target_handle}" ${rule_body} && final_status=0
                            op_desc="上移规则 #${source_choice}"
                        fi
                        ;;
                    d|down)
                        if [[ "$source_choice" -ne "$chain_end_idx" ]]; then
                            local target_handle=${all_rules_handle[$((source_index+1))]}
                            echo -e "\n${YELLOW}正在下移规则 #${source_choice}...${NC}"
                            nft add rule inet "${TABLE_NAME}" "${source_chain}" handle "${target_handle}" ${rule_body} && final_status=0
                            op_desc="下移规则 #${source_choice}"
                        fi
                        ;;
                    s|swap|bp|before|ap|after)
                        if ! [[ "$dest_choice" =~ ^[0-9]+$ && "$dest_choice" -ge "$chain_start_idx" && "$dest_choice" -le "$chain_end_idx" ]]; then
                            echo -e "\n${RED}目标编号 #${dest_choice} 无效或不在同一链内。${NC}"; sleep 2; continue
                        fi
                        if [[ "$source_choice" -eq "$dest_choice" ]]; then
                            echo -e "\n${YELLOW}源和目标编号相同, 无需操作。${NC}"; sleep 2; continue
                        fi
                        local dest_index=$((dest_choice-1))
                        local dest_handle=${all_rules_handle[$dest_index]}
                        local dest_body=$(echo "${all_rules_text[$dest_index]}" | sed 's/ handle [0-9]*$//')
                        
                        if [[ "$move_action" == "s" || "$move_action" == "swap" ]]; then
                            echo -e "\n${YELLOW}正在交换规则 #${source_choice} 和 #${dest_choice}...${NC}"
                            nft replace rule inet "${TABLE_NAME}" "${source_chain}" handle ${dest_handle} ${rule_body} && \
                            nft replace rule inet "${TABLE_NAME}" "${source_chain}" handle ${source_handle} ${dest_body} && final_status=0
                            op_desc="交换规则 #${source_choice} <-> #${dest_choice}"
                        elif [[ "$move_action" == "bp" || "$move_action" == "before" ]]; then
                            echo -e "\n${YELLOW}正在移动规则 #${source_choice} 到 #${dest_choice} 之前...${NC}"
                            nft insert rule inet "${TABLE_NAME}" "${source_chain}" handle ${dest_handle} ${rule_body} && final_status=0
                            op_desc="移动规则 #${source_choice} -> #${dest_choice} 之前"
                        elif [[ "$move_action" == "ap" || "$move_action" == "after" ]]; then
                            echo -e "\n${YELLOW}正在移动规则 #${source_choice} 到 #${dest_choice} 之后...${NC}"
                            nft add rule inet "${TABLE_NAME}" "${source_chain}" handle ${dest_handle} ${rule_body} && final_status=0
                            op_desc="移动规则 #${source_choice} -> #${dest_choice} 之后"
                        fi
                        ;;
                    *)
                        echo -e "\n${RED}无效的移动指令。${NC}"; sleep 1; continue
                        ;;
                esac

                # --- 执行与收尾 ---
                if [[ "$final_status" -eq 0 ]]; then
                    if [[ "$move_action" != "s" && "$move_action" != "swap" ]]; then
                        nft delete rule inet "${TABLE_NAME}" "${source_chain}" handle "${source_handle}"
                        if [ $? -ne 0 ]; then
                           echo -e "${RED}严重错误: 新规则已添加, 但删除旧规则失败! 请手动检查。${NC}"; final_status=1
                        fi
                    fi
                    apply_and_save_changes $final_status "$op_desc" false
                elif [[ "$final_status" -eq -1 ]]; then
                    : # 没有执行任何操作，不做处理
                else
                    echo -e "${RED}操作失败: 无法执行移动。${NC}"
                fi
                echo -e "${GREEN}操作完成, 正在刷新列表...${NC}"; sleep 1
                ;;
            e|edit) # <--- 编辑选项
                read -ra choices <<< "$choices_str"
                if [ ${#choices[@]} -ne 1 ]; then
                    echo -e "\n${RED}错误: '编辑' 操作只需一个参数: 'e <要编辑的规则编号>'。${NC}"; sleep 2; continue
                fi
                local choice_to_edit=${choices[0]}
                 if ! [[ "$choice_to_edit" =~ ^[0-9]+$ && "$choice_to_edit" -ge 1 && "$choice_to_edit" -le ${#all_rules_handle[@]} ]]; then
                    echo -e "\n${RED}输入错误: '$choice_to_edit' 不是一个有效的编号。${NC}"; sleep 2; continue
                fi
                
                edit_rule_interactive $((choice_to_edit-1))
                # 不论编辑成功或取消，都刷新一下列表
                echo -e "${GREEN}正在刷新列表...${NC}"; sleep 1
                ;;
            *)
                echo -e "\n${RED}无效操作。请输入 'd', 'm', 'e' 或 'da'。${NC}"
                sleep 2
                ;;
        esac
    done
}
view_full_status() { clear; echo -e "${BLUE}--- 查看完整防火墙状态 ---${NC}\n"; nft list ruleset; press_any_key; }

reset_firewall() {
    clear
    echo -e "${BLUE}--- 重置防火墙为默认结构 ---${NC}\n"
    echo -e "${RED}警告：此操作将清除所有规则！${NC}"
    read -p "您确定要继续吗? (y/N): " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        nft flush ruleset
        initialize_firewall
        apply_and_save_changes 0 "重置防火墙" false "del_allow" "all" # 重置相当于删除所有允许规则

        local f2b_handled=false
        if command -v fail2ban-client &>/dev/null; then
            f2b_handled=true
            echo -e "\n${PURPLE}--- 联动修复 ---${NC}"
            echo -e "${CYAN}检测到 Fail2ban 已安装，将自动为您重新应用兼容性配置...${NC}"
            f2b_reapply_config
        fi

        # --- [新增] Docker 兼容性处理 ---
        local docker_handled=false
        if command -v docker &>/dev/null && systemctl is-active docker &>/dev/null; then
            docker_handled=true
            echo -e "\n${PURPLE}--- Docker 兼容性处理 ---${NC}"
            echo -e "${CYAN}检测到 Docker 正在运行, 将重启服务以自动重建其防火墙规则...${NC}"
            if systemctl restart docker; then
                echo -e "${GREEN}Docker 重启成功。Docker 的网络规则已重新生成。${NC}"
            else
                echo -e "${RED}错误: Docker 服务重启失败。您可能需要手动重启。${NC}"
            fi
            press_any_key
        fi

        # 如果没有执行任何特殊处理（如f2b或docker），则在此处暂停
        if ! $f2b_handled && ! $docker_handled; then
            press_any_key
        fi
    else
        echo -e "${YELLOW}操作已取消。${NC}"
        press_any_key
    fi
}

# --- 连接管理功能 ---
clear_connections() { while true; do clear; echo -e "${BLUE}--- 连接清理中心 ---${NC}\n"; echo -e "请选择清理模式:"; echo -e " ${GREEN}1.${NC} 清除所有连接 (排除SSH)"; echo -e " ${GREEN}2.${NC} 按端口清除连接"; echo -e " ${GREEN}3.${NC} 按进程清除连接"; echo -e " ${GREEN}q.${NC} 返回主菜单"; echo -e "${PURPLE}------------------------------------------------------${NC}"; read -p "请输入您的选项: " choice; case $choice in 1) flush_conntrack "all"; press_any_key; ;; 2) local port_input_successful=false; while true; do echo -e "\n${CYAN}支持格式 - 单个:80, 多个:80,443, 范围:1000-2000${NC}"; read -p "请输入要清除连接的端口 (输入 'q' 返回): " port_input; if [[ $port_input =~ ^[qQ]$ ]]; then break; fi; local formatted_ports=$(validate_and_format_ports "$port_input"); if [[ $? -eq 0 && -n "$formatted_ports" ]]; then flush_conntrack "$port_input"; port_input_successful=true; break; else echo -e "${RED}输入无效或为空。${NC}"; fi; done; if $port_input_successful; then press_any_key; fi; ;; 3) read -p "请输入进程名 (多个用空格分隔, 'q'返回): " process_names; if [[ $process_names =~ ^[qQ]$ ]]; then continue; fi; local pids=(); local ports=(); local found_process=false; for p in $process_names; do local current_pids=($(pgrep -f "$p")); if [ ${#current_pids[@]} -eq 0 ]; then echo -e "${RED}警告: 未找到进程 '${p}'。${NC}" >&2; continue; fi; found_process=true; pids+=("${current_pids[@]}"); done; if [ "$found_process" == "false" ]; then press_any_key; continue; fi; echo -e "\n${YELLOW}正在查找相关端口...${NC}"; for pid in "${pids[@]}"; do local current_ports=$(ss -tnlp "pid=$pid" | awk 'NR>1 {split($4, a, ":"); print a[length(a)]}' | sort -u); if [[ -n "$current_ports" ]]; then echo -e "  - 进程 ID ${GREEN}${pid}${NC} 关联端口: ${current_ports}"; ports+=($(echo "$current_ports" | tr '\n' ' ')); fi; done; if [ ${#ports[@]} -eq 0 ]; then echo -e "${YELLOW}未找到任何与指定进程关联的开放端口。${NC}"; else ports=($(echo "${ports[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')); local ports_str=$(IFS=,; echo "${ports[*]}"); echo -e "${CYAN}发现所有关联端口: ${ports[*]}.${NC}"; flush_conntrack "$ports_str"; fi; press_any_key; ;; q|Q) break; ;; *) echo -e "\n${RED}无效选项，请重新输入。${NC}"; sleep 2; ;; esac; done; }
toggle_ipv4_ping() {
    clear
    echo -e "${BLUE}--- 切换 IPv4 ICMP (Ping) 状态 (终极净化版) ---${NC}\n"

    # --- 1. 获取所有相关状态 ---
    local current_policy=$(nft list chain inet ${TABLE_NAME} ${INPUT_CHAIN} 2>/dev/null | grep -o 'policy \w*' | awk '{print $2}')
    local PING_ACCEPT_COMMENT="Allow IPv4 Ping"
    local PING_DROP_COMMENT="Block IPv4 Ping (Policy-Accept-Mode)"

    # 分别查找 accept 规则和 drop 规则的句柄
    local accept_handle=$(nft --handle list chain inet "${TABLE_NAME}" "${INPUT_CHAIN}" | grep "comment \"${PING_ACCEPT_COMMENT}\"" | awk '{print $NF}')
    local drop_handle=$(nft --handle list chain inet "${TABLE_NAME}" "${INPUT_CHAIN}" | grep "comment \"${PING_DROP_COMMENT}\"" | awk '{print $NF}')

    echo -e "${CYAN}检测到当前入站策略为: ${YELLOW}${current_policy}${NC}\n"

    # --- 2. 根据当前策略，执行净化和切换 ---
    if [[ "$current_policy" == "drop" ]]; then
        # === 当前是 DROP 策略模式 (白名单逻辑) ===

        # 关键净化：如果发现了不该存在的 drop 规则，立即删除它！
        if [[ -n "$drop_handle" ]]; then
            echo -e "${YELLOW}检测到残留的 'accept-mode' 规则，正在自动清理...${NC}"
            nft delete rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "${drop_handle}"
        fi

        # 执行正常的切换逻辑
        if [[ -n "$accept_handle" ]]; then
            echo -e "${YELLOW}当前 Ping 是 [允许] 的，正在切换为 [阻断]...${NC}"
            nft delete rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "${accept_handle}"
            apply_and_save_changes $? "阻断 IPv4 Ping"
        else
            echo -e "${YELLOW}当前 Ping 是 [阻断] 的，正在切换为 [允许]...${NC}"
            nft add rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" ip protocol icmp icmp type echo-request accept comment "\"${PING_ACCEPT_COMMENT}\""
            apply_and_save_changes $? "允许 IPv4 Ping"
        fi

    else # policy 为 accept 的情况
        # === 当前是 ACCEPT 策略模式 (黑名单逻辑) ===

        # 关键净化：如果发现了不该存在的 accept 规则，立即删除它！
        if [[ -n "$accept_handle" ]]; then
            echo -e "${YELLOW}检测到残留的 'drop-mode' 规则，正在自动清理...${NC}"
            nft delete rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "${accept_handle}"
        fi

        # 执行正常的切换逻辑
        if [[ -n "$drop_handle" ]]; then
            echo -e "${YELLOW}当前 Ping 是 [阻断] 的，正在切换为 [允许]...${NC}"
            nft delete rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "${drop_handle}"
            apply_and_save_changes $? "允许 IPv4 Ping (移除阻断规则)"
        else
            echo -e "${YELLOW}当前 Ping 是 [允许] 的，正在切换为 [阻断]...${NC}"
            nft add rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" ip protocol icmp icmp type echo-request drop comment "\"${PING_DROP_COMMENT}\""
            apply_and_save_changes $? "阻断 IPv4 Ping (添加阻断规则)"
        fi
    fi
}

toggle_default_policy() {
    clear
    echo -e "${BLUE}--- 切换入站链 (INPUT) 默认策略 ---${NC}\n"

    local current_policy=$(nft list chain inet ${TABLE_NAME} ${INPUT_CHAIN} 2>/dev/null | grep -o 'policy \w*' | awk '{print $2}')

    if [[ "$current_policy" == "drop" ]]; then
        echo -e "${RED}====================[ 严重安全警告 ]====================${NC}"
        echo -e "${YELLOW}您正准备将防火墙的默认入站策略从 ${GREEN}DROP (拒绝)${YELLOW} 切换为 ${RED}ACCEPT (接受)${YELLOW}。${NC}"
        echo -e "${YELLOW}这是一个极其危险的操作，它意味着：${NC}"
        echo -e "${RED}  1. 所有未被明确阻止的端口都将向全网开放！${NC}"
        echo -e "${RED}  2. 您的服务器将从“默认安全”变为“默认不安全”。${NC}"
        echo -e "${RED}  3. 任何忘记添加黑名单的服务都将直接暴露，极大增加被攻击风险。${NC}"
        echo -e "${PURPLE}======================================================${NC}"
        read -p "我已了解全部风险, 确定要切换到 ACCEPT 模式吗? (请输入 'yes' 确认): " confirm

        if [[ "$confirm" == "yes" ]]; then
            echo -e "\n${YELLOW}正在切换策略为 ${RED}ACCEPT${YELLOW}...${NC}"
            nft chain inet "${TABLE_NAME}" "${INPUT_CHAIN}" { type filter hook input priority 0 \; policy accept \; }
            apply_and_save_changes $? "切换默认策略为 ACCEPT(危险)"
        else
            echo -e "\n${GREEN}操作已取消，防火墙策略保持为安全的 DROP 模式。${NC}"
            press_any_key
        fi
    else
        echo -e "${GREEN}当前策略为 ${RED}ACCEPT(危险)${GREEN}, 正在切换回安全的 ${GREEN}DROP${GREEN} 模式...${NC}"
        nft chain inet "${TABLE_NAME}" "${INPUT_CHAIN}" { type filter hook input priority 0 \; policy drop \; }
        apply_and_save_changes $? "切换默认策略为 DROP"
    fi
}
# [请将这个新函数完整地添加到您的脚本中]
toggle_forward_policy() {
    clear
    echo -e "${BLUE}--- 切换转发链 (FORWARD) 默认策略 ---${NC}\n"

    # 定义“绿色通道”规则的唯一备注
    local FORWARD_CT_ACCEPT_COMMENT="核心:允许转发已建立的连接"

    # 获取当前策略和“绿色通道”规则的句柄
    local current_policy=$(nft list chain inet ${TABLE_NAME} ${FORWARD_CHAIN} 2>/dev/null | grep -o 'policy \w*' | awk '{print $2}')
    local ct_rule_handle=$(nft --handle list chain inet "${TABLE_NAME}" "${FORWARD_CHAIN}" | grep "${FORWARD_CT_ACCEPT_COMMENT}" | awk '{print $NF}')

    if [[ "$current_policy" == "accept" ]]; then
        echo -e "${YELLOW}您准备将转发策略从 ${GREEN}ACCEPT (默认/兼容模式)${YELLOW} 切换为 ${RED}DROP (默认拒绝/更严格模式)${YELLOW}。${NC}"
        echo -e "此操作将会："
        echo -e "  1. 设置 ${FORWARD_CHAIN} 链的默认策略为 ${RED}DROP${NC}。"
        echo -e "  2. ${GREEN}自动在链的顶部添加一条规则，以允许“已建立/相关”的连接通过${NC}，确保容器出站网络正常。"
        echo -e "  3. ${RED}切换后，所有未经您明确放行的新转发流量（如访问容器）都将被拒绝。${NC}"
        read -p "我已了解影响, 确定要切换到 DROP 模式吗? (y/N): " confirm

        if [[ "$confirm" =~ ^[yY]$ ]]; then
            echo -e "\n${YELLOW}正在切换策略为 ${RED}DROP${YELLOW}...${NC}"
            local final_status=0
            # 首先，如果“绿色通道”规则不存在，就添加它
            if [[ -z "$ct_rule_handle" ]]; then
                echo -e "${CYAN}  -> 正在添加“已建立连接”的放行规则...${NC}"
                nft insert rule inet "${TABLE_NAME}" "${FORWARD_CHAIN}" ct state established,related accept comment "\"${FORWARD_CT_ACCEPT_COMMENT}\"" || final_status=1
            fi
            # 然后，更改策略
            if [[ "$final_status" -eq 0 ]]; then
                nft chain inet "${TABLE_NAME}" "${FORWARD_CHAIN}" { policy drop \; } || final_status=1
            fi
            apply_and_save_changes $final_status "切换转发策略为 DROP (严格)"
        else
            echo -e "\n${GREEN}操作已取消。${NC}"; press_any_key
        fi
    else # current policy is drop
        echo -e "${GREEN}当前策略为 ${RED}DROP(严格)${GREEN}, 正在切换回 ${GREEN}ACCEPT (默认/兼容模式)${GREEN}...${NC}"
        read -p "确认切换吗? (y/N): " confirm
         if [[ "$confirm" =~ ^[yY]$ ]]; then
            local final_status=0
            # 首先，更改策略
            nft chain inet "${TABLE_NAME}" "${FORWARD_CHAIN}" { policy accept \; } || final_status=1
            # 然后，如果“绿色通道”规则存在，就移除它（在ACCEPT模式下不再需要）
            if [[ -n "$ct_rule_handle" ]]; then
                echo -e "${CYAN}  -> 正在移除“已建立连接”的放行规则...${NC}"
                nft delete rule inet "${TABLE_NAME}" "${FORWARD_CHAIN}" handle "$ct_rule_handle" || final_status=1
            fi
            apply_and_save_changes $final_status "切换转发策略为 ACCEPT (兼容)"
        else
            echo -e "\n${GREEN}操作已取消。${NC}"; press_any_key
        fi
    fi
}

# --- Fail2ban & SSH Manager ---
# MODIFIED: Major changes to implement your desired logic.
# The action files now create the SSH whitelist sets and rules directly within the f2b-table.
f2b_reapply_config() {
    echo -e "\n${YELLOW}--> 正在应用终极版 Fail2ban 修复方案 (定制版)...${NC}"
    
    # 1. 停止服务，确保环境干净
    echo -e "${CYAN}  -> 正在停止 Fail2ban 服务...${NC}"
    systemctl stop fail2ban

    # 2. 强制覆盖action文件，使用已知正确的、无依赖的硬编码版本
    echo -e "${CYAN}  -> 正在强制覆盖 nftables-multiport.conf...${NC}"
    sudo tee /etc/fail2ban/action.d/nftables-multiport.conf << EOF >/dev/null
[Definition]
# This file was programmatically generated by nftables.sh (v1.0 - Custom)
# Places SSH Whitelist rules directly into the Fail2ban chain.

actionstart = nft 'add table inet ${F2B_TABLE_NAME}'
              nft 'add set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V4} { type ipv4_addr; flags interval; }'
              nft 'add set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V6} { type ipv6_addr; flags interval; }'
              nft 'add set inet ${F2B_TABLE_NAME} addr-set-v4-<name> { type ipv4_addr; flags interval; }'
              nft 'add set inet ${F2B_TABLE_NAME} addr-set-v6-<name> { type ipv6_addr; flags interval; }'
              nft 'add chain inet ${F2B_TABLE_NAME} f2b-chain-<name> { type filter hook input priority -1; }'
              nft 'add rule inet ${F2B_TABLE_NAME} f2b-chain-<name> ip saddr @${F2B_SSH_WHITELIST_SET_V4} accept'
              nft 'add rule inet ${F2B_TABLE_NAME} f2b-chain-<name> ip6 saddr @${F2B_SSH_WHITELIST_SET_V6} accept'
              nft 'add rule inet ${F2B_TABLE_NAME} f2b-chain-<name> ip saddr @addr-set-v4-<name> reject'
              nft 'add rule inet ${F2B_TABLE_NAME} f2b-chain-<name> ip6 saddr @addr-set-v6-<name> reject'

actionstop = nft 'delete table inet ${F2B_TABLE_NAME}'

actioncheck = nft 'list table inet ${F2B_TABLE_NAME}'

actionban = if [ "<family>" = "inet6" ]; then nft 'add element inet ${F2B_TABLE_NAME} addr-set-v6-<name> { <ip> }'; else nft 'add element inet ${F2B_TABLE_NAME} addr-set-v4-<name> { <ip> }'; fi

actionunban = if [ "<family>" = "inet6" ]; then nft 'delete element inet ${F2B_TABLE_NAME} addr-set-v6-<name> { <ip> }'; else nft 'delete element inet ${F2B_TABLE_NAME} addr-set-v4-<name> { <ip> }'; fi

[Init]
# Default values for multiport action
name = sshd
port = ssh
protocol = tcp
EOF
    
    echo -e "${CYAN}  -> 正在强制覆盖 nftables-allports.conf...${NC}"
    sudo tee /etc/fail2ban/action.d/nftables-allports.conf << EOF >/dev/null
[Definition]
# This file was programmatically generated by nftables.sh (v1.0 - Custom)
# Places SSH Whitelist rules directly into the Fail2ban chain.

actionstart = nft 'add table inet ${F2B_TABLE_NAME}'
              nft 'add set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V4} { type ipv4_addr; flags interval; }'
              nft 'add set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V6} { type ipv6_addr; flags interval; }'
              nft 'add set inet ${F2B_TABLE_NAME} addr-set-v4-<name> { type ipv4_addr; flags interval; }'
              nft 'add set inet ${F2B_TABLE_NAME} addr-set-v6-<name> { type ipv6_addr; flags interval; }'
              nft 'add chain inet ${F2B_TABLE_NAME} f2b-chain-<name> { type filter hook input priority -1; }'
              nft 'add rule inet ${F2B_TABLE_NAME} f2b-chain-<name> ip saddr @${F2B_SSH_WHITELIST_SET_V4} accept'
              nft 'add rule inet ${F2B_TABLE_NAME} f2b-chain-<name> ip6 saddr @${F2B_SSH_WHITELIST_SET_V6} accept'
              nft 'add rule inet ${F2B_TABLE_NAME} f2b-chain-<name> ip saddr @addr-set-v4-<name> reject'
              nft 'add rule inet ${F2B_TABLE_NAME} f2b-chain-<name> ip6 saddr @addr-set-v6-<name> drop'

actionstop = nft 'delete table inet ${F2B_TABLE_NAME}'

actioncheck = nft 'list table inet ${F2B_TABLE_NAME}'

actionban = if [ "<family>" = "inet6" ]; then nft 'add element inet ${F2B_TABLE_NAME} addr-set-v6-<name> { <ip> }'; else nft 'add element inet ${F2B_TABLE_NAME} addr-set-v4-<name> { <ip> }'; fi

actionunban = if [ "<family>" = "inet6" ]; then nft 'delete element inet ${F2B_TABLE_NAME} addr-set-v6-<name> { <ip> }'; else nft 'delete element inet ${F2B_TABLE_NAME} addr-set-v4-<name> { <ip> }'; fi

[Init]
# Default values for allports action
name = sshd
EOF

    # 3. 智能生成一份干净的 jail.local
    echo -e "${CYAN}  -> 正在生成全新的 jail.local...${NC}"
    local jail_local_path="/etc/fail2ban/jail.local"
    
    # 检测日志后端
    local sshd_backend_config_line=""
    if [ -f /var/log/auth.log ]; then # Debian/Ubuntu
        sshd_backend_config_line="logpath = /var/log/auth.log"
        echo -e "${GREEN}    -> 自动检测到 SSH 日志路径为 (文件): /var/log/auth.log${NC}"
    elif [ -f /var/log/secure ]; then # RHEL/CentOS
        sshd_backend_config_line="logpath = /var/log/secure"
        echo -e "${GREEN}    -> 自动检测到 SSH 日志路径为 (文件): /var/log/secure${NC}"
    elif command -v journalctl &>/dev/null; then
        sshd_backend_config_line="backend = systemd"
        echo -e "${GREEN}    -> 未找到传统日志文件, 自动配置为 systemd 后端进行监控。${NC}"
    else
        sshd_backend_config_line="logpath = %(sshd_log)s"
        echo -e "${YELLOW}警告: 未能检测到明确的日志文件或systemd, 使用Fail2ban默认值。${NC}"
    fi

    # 写入全新的 jail.local
    cat << EOF | sudo tee "$jail_local_path" > /dev/null
[DEFAULT]
# 使用我们强制覆盖的、已知正确的action
banaction = nftables-multiport
banaction_allports = nftables-allports

[sshd]
enabled = true
${sshd_backend_config_line}
maxretry = 3
findtime = 10m
bantime = 1d
EOF

    # 4. 清理旧的防火墙状态并重启
    echo -e "${CYAN}  -> 正在清理旧的防火墙规则...${NC}"
    nft delete table inet ${F2B_TABLE_NAME} &>/dev/null
    
    echo -e "\n${YELLOW}--> 正在重启 Fail2ban 服务以应用全新配置...${NC}"
    if ! systemctl restart fail2ban; then
        echo -e "${RED}错误：Fail2ban 服务重启失败！${NC}"
        echo -e "${YELLOW}请手动执行 'journalctl -u fail2ban -n 50' 查看错误日志。${NC}"
        press_any_key
        return 1
    fi
    
    echo -e "${GREEN}终极修复已成功应用，Fail2ban 正在以最兼容的模式运行！${NC}"
    press_any_key
    return 0
}

install_fail2ban() {
    clear
    echo -e "${BLUE}--- Fail2ban 一键安装与配置 ---${NC}\n"
    read -p "未检测到 Fail2ban, 是否开始一键安装并为SSH配置nftables防护? (Y/n): " confirm
    confirm=${confirm:-Y}
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        echo -e "\n${YELLOW}操作已取消。${NC}"
        press_any_key
        return 1
    fi

    local PKG_MANAGER=""
    local INSTALL_CMD=""
    if command -v apt-get &>/dev/null; then PKG_MANAGER="apt"; INSTALL_CMD="apt-get install -y";
    elif command -v dnf &>/dev/null; then PKG_MANAGER="dnf"; INSTALL_CMD="dnf install -y";
    elif command -v yum &>/dev/null; then PKG_MANAGER="yum"; INSTALL_CMD="yum install -y";
    elif command -v pacman &>/dev/null; then PKG_MANAGER="pacman"; INSTALL_CMD="pacman --noconfirm -S";
    fi

    if [[ -z "$PKG_MANAGER" ]]; then
        echo -e "\n${RED}错误: 无法确定包管理器, 请手动安装 Fail2ban 后重试。${NC}"
        press_any_key
        return 1
    fi

    echo -e "\n${YELLOW}--> 正在使用 $PKG_MANAGER 安装 fail2ban...${NC}"
    if ! $INSTALL_CMD fail2ban; then
        echo -e "\n${RED}错误: Fail2ban 安装失败, 请检查您的软件源。${NC}"
        press_any_key
        return 1
    fi
    echo -e "${GREEN}Fail2ban 安装成功。${NC}"

    f2b_reapply_config
    
    if ! systemctl is-active --quiet fail2ban; then return 1; fi
    
    return 0
}

f2b_manual_action() {
    local action=$1 
    local action_text=$2
    
    clear
    echo -e "${BLUE}--- Fail2ban 手动${action_text} ---${NC}\n"

    mapfile -t jails < <(fail2ban-client status | grep "Jail list:" | sed -e 's/.*Jail list:[ \t]*//' -e 's/,//g')
    if [ ${#jails[@]} -eq 0 ]; then
        echo -e "${RED}错误: 未找到任何活动的 Fail2ban Jail。${NC}"; press_any_key; return
    fi
    echo -e "${CYAN}请选择要操作的 Jail:${NC}"
    local i=1
    for j in "${jails[@]}"; do
        echo -e " ${GREEN}$i)${NC} $j"
        ((i++))
    done
    read -p "请选择序号 [默认: sshd]: " choice
    local jail
    if [[ -z "$choice" ]]; then
        jail="sshd"
    elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#jails[@]} ]]; then
        jail="${jails[$((choice-1))]}"
    else
        echo -e "${RED}无效选择。${NC}"; press_any_key; return
    fi
    echo -e "${CYAN}选定的 Jail: ${YELLOW}${jail}${NC}\n"

    echo -e "${CYAN}请选择${action_text}对象类型:${NC}"
    echo -e " ${GREEN}1)${NC} 单个IP或CIDR网段"
    echo -e " ${GREEN}2)${NC} 从IP集批量${action_text}"
    read -p "请选择 [1-2]: " type_choice
    
    case $type_choice in
        1)
            local target
            while true; do
                read -p "请输入要${action_text}的IP或CIDR ('q'取消): " target
                if [[ "$target" =~ ^[qQ]$ ]] || [[ -z "$target" ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
                if [[ "$(validate_ip_or_cidr "$target")" != "invalid" ]]; then
                    break
                else
                    echo -e "${RED}错误: 输入的不是有效的IP地址或CIDR网段。请重新输入。${NC}"
                fi
            done

            echo -e "\n${YELLOW}正在对 ${target} 执行 ${action}...${NC}"
            if fail2ban-client set "$jail" "$action" "$target"; then
                echo -e "${GREEN}成功！${NC}"
            else
                echo -e "${RED}失败！请检查IP格式或Jail名称。${NC}"
            fi
            ;;
        2)
            local ip_set
            ip_set=$(select_from_ipset)
            if [ $? -ne 0 ]; then return; fi

            echo -e "\n${YELLOW}正在从IP集 @${ip_set} 读取IP列表...${NC}"
            mapfile -t ips_to_process < <(nft list set inet "${TABLE_NAME}" "${ip_set}" 2>/dev/null | grep -oP '(?<={ ).*(?= })' | tr -d ' ' | tr ',' '\n')
            
            if [ ${#ips_to_process[@]} -eq 0 ]; then
                echo -e "${RED}错误: IP集 @${ip_set} 为空或不存在。${NC}"; press_any_key; return
            fi
            
            echo -e "${CYAN}将要对来自 @${ip_set} 的 ${#ips_to_process[@]} 个IP/网段执行${action_text}操作。${NC}"
            read -p "此操作可能需要一些时间，是否继续? (y/N): " confirm
            if [[ ! "$confirm" =~ ^[yY]$ ]]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi
            
            local success_count=0
            local fail_count=0
            for ip in "${ips_to_process[@]}"; do
                echo -ne "     -> ${action_text} ${ip}... "
                if fail2ban-client set "$jail" "$action" "$ip" >/dev/null; then
                    echo -e "${GREEN}成功${NC}"
                    ((success_count++))
                else
                    echo -e "${RED}失败${NC}"
                    ((fail_count++))
                fi
            done
            echo -e "\n${GREEN}操作完成。成功: ${success_count}, 失败: ${fail_count}${NC}"
            ;;
        *) echo -e "${RED}无效选择。${NC}" ;;
    esac
    press_any_key
}

f2b_change_params() {
    local jail_local_path="/etc/fail2ban/jail.local"
    
    clear
    echo -e "${BLUE}--- 更改 Fail2ban 核心参数 (针对 [sshd] jail) ---${NC}\n"

    get_param_value() {
        awk -v key="$1" '
            /^\[sshd\]/ { in_section=1; next }
            /^\s*\[/ { in_section=0 }
            in_section && $1 == key {
                value = $3
                for (i=4; i<=NF; i++) {
                    value = value " " $i
                }
                sub(/[ \t]*#.*/, "", value)
                print value
                exit
            }
        ' "$jail_local_path" 2>/dev/null
    }
    
    format_f2b_time_display() {
        local value="$1"
        if [[ -z "$value" ]]; then
            echo "默认"
        elif [[ "$value" =~ ^[0-9]+$ ]]; then
            echo "${value}s"
        else
            echo "$value"
        fi
    }

    local current_maxretry=$(get_param_value "maxretry")
    local current_findtime=$(get_param_value "findtime")
    local current_bantime=$(get_param_value "bantime")

    local display_findtime=$(format_f2b_time_display "$current_findtime")
    local display_bantime=$(format_f2b_time_display "$current_bantime")

    echo -e "${YELLOW}当前配置值 (如果为空, 则表示使用Fail2ban全局默认值):${NC}"
    echo -e " - 最大尝试次数 (maxretry): ${GREEN}${current_maxretry:-默认}${NC}"
    echo -e " - 时间频率 (findtime):   ${GREEN}${display_findtime}${NC}"
    echo -e " - 封禁时间 (bantime):   ${GREEN}${display_bantime}${NC}"
    echo -e "\n${CYAN}请输入新值, 或直接按Enter保留当前设置。输入 'default' 可清除设置。${NC}"
    echo -e "${CYAN}时间单位: s(秒), m(分), h(时), d(天)。例如: 10m, 12h, 1d。纯数字默认为秒。${NC}"

    local new_maxretry new_findtime new_bantime changed=false

    while true; do
        read -p "新 'maxretry' (数字, 'q'取消) [${current_maxretry:-默认}]: " new_maxretry
        if [[ "$new_maxretry" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        new_maxretry=${new_maxretry:-$current_maxretry}
        if [[ -z "$new_maxretry" ]]; then break; fi
        if [[ "$new_maxretry" =~ ^[0-9]+$ ]] || [[ "$new_maxretry" == "default" ]]; then break; fi
        echo -e "${RED}错误: 'maxretry' 必须是一个纯数字或 'default'。${NC}"
    done

    while true; do
        read -p "新 'findtime' (时间, 'q'取消) [${display_findtime}]: " new_findtime
        if [[ "$new_findtime" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        new_findtime=${new_findtime:-$current_findtime}
        if [[ -z "$new_findtime" ]]; then break; fi
        if [[ "$new_findtime" =~ ^[0-9]+[smhd]?$ ]] || [[ "$new_findtime" == "default" ]]; then break; fi
        echo -e "${RED}错误: 'findtime' 格式无效。请使用数字+单位 (s,m,h,d) 或 'default'。${NC}"
    done

    while true; do
        read -p "新 'bantime' (时间, 'q'取消) [${display_bantime}]: " new_bantime
        if [[ "$new_bantime" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        new_bantime=${new_bantime:-$current_bantime}
        if [[ -z "$new_bantime" ]]; then break; fi
        if [[ "$new_bantime" =~ ^[0-9]+[smhd]?$ ]] || [[ "$new_bantime" == "default" ]]; then break; fi
        echo -e "${RED}错误: 'bantime' 格式无效。请使用数字+单位 (s,m,h,d) 或 'default'。${NC}"
    done

    if [[ "$new_maxretry" != "$current_maxretry" ]] || \
       [[ "$new_findtime" != "$current_findtime" ]] || \
       [[ "$new_bantime" != "$current_bantime" ]]; then
        changed=true
    fi

    if $changed; then
        echo -e "\n${YELLOW}检测到配置变更, 正在从头生成全新的 jail.local 文件...${NC}"
        
        [[ "$new_maxretry" == "default" ]] && new_maxretry=""
        [[ "$new_findtime" == "default" ]] && new_findtime=""
        [[ "$new_bantime" == "default" ]] && new_bantime=""

        local backend_line="backend = systemd"
        if [ -f "$jail_local_path" ]; then
             if grep -q "^\s*backend\s*=" "$jail_local_path" 2>/dev/null; then
                backend_line=$(grep "^\s*backend\s*=" "$jail_local_path")
             elif grep -q "^\s*logpath\s*=" "$jail_local_path" 2>/dev/null; then
                backend_line=$(grep "^\s*logpath\s*=" "$jail_local_path")
             fi
        fi

        {
            echo "[DEFAULT]"
            echo "banaction = nftables-multiport"
            echo "banaction_allports = nftables-allports"
            echo ""
            echo "[sshd]"
            echo "enabled = true"
            echo "$backend_line"
            if [[ -n "$new_maxretry" ]]; then echo "maxretry = $new_maxretry"; fi
            if [[ -n "$new_findtime" ]]; then echo "findtime = $new_findtime"; fi
            if [[ -n "$new_bantime" ]]; then echo "bantime = $new_bantime"; fi
        } > "$jail_local_path"

        if fail2ban-client reload; then
            echo -e "${GREEN}Fail2ban已成功重载新配置。${NC}"
        else
            echo -e "${RED}Fail2ban重载失败！请检查配置或服务日志 'journalctl -u fail2ban'。${NC}"
            echo -e "${YELLOW}为方便排查, 以下是脚本刚刚生成的 jail.local 的【确切内容】:${NC}"
            echo -e "--- START OF FILE ---"
            cat -A "$jail_local_path"
            echo -e "--- END OF FILE ---"
        fi
    else
        echo -e "\n${CYAN}配置未发生变化, 无需重载。${NC}"
    fi
    press_any_key
}

# MODIFIED: All nft commands now point to the f2b-table for whitelist management.
ssh_whitelist_manager() {
    if ! systemctl is-active --quiet fail2ban; then
        echo -e "${RED}错误: Fail2ban服务未运行, 无法安全管理白名单。${NC}"; press_any_key; return
    fi
    
    # ensure_ssh_whitelist_rules_exist is now obsolete

    while true; do
        clear
        echo -e "${BLUE}--- SSH 白名单管理 (内置于Fail2ban链) ---${NC}\n"
        echo -e "${YELLOW}此处的IP将被Fail2ban链优先放行, 不会触发封禁。${NC}\n"
        
        mapfile -t whitelist_v4 < <(nft list set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V4} 2>/dev/null | grep -oP '(?<={ ).*(?= })' | tr -d ' ' | tr ',' '\n' | sort -u)
        mapfile -t whitelist_v6 < <(nft list set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V6} 2>/dev/null | grep -oP '(?<={ ).*(?= })' | tr -d ' ' | tr ',' '\n' | sort -u)
        
        local all_ips=("${whitelist_v4[@]}" "${whitelist_v6[@]}")
        
        if [ ${#all_ips[@]} -eq 0 ]; then
            echo -e "${CYAN}当前SSH白名单为空。${NC}"
        else
            echo -e "${CYAN}当前SSH白名单列表:${NC}"
            local i=1
            for ip in "${whitelist_v4[@]}"; do echo -e " ${GREEN}$i)${NC} ${ip} ${YELLOW}[IPv4]${NC}"; ((i++)); done
            for ip in "${whitelist_v6[@]}"; do echo -e " ${GREEN}$i)${NC} ${ip} ${YELLOW}[IPv6]${NC}"; ((i++)); done
        fi

        echo -e "\n${PURPLE}--------------------[ 操作 ]--------------------${NC}"
        echo -e " ${GREEN}1.${NC} 添加 IP/CIDR 到白名单"
        echo -e " ${GREEN}2.${NC} 从现有 IP集 批量添加"
        echo -e " ${GREEN}3.${NC} ${RED}从白名单中删除${NC}"
        echo -e "\n ${GREEN}q.${NC} 返回"
        echo -e "${PURPLE}----------------------------------------------${NC}"
        read -p "请输入选项: " choice
        
        case $choice in
            1)
                read -p "请输入要添加的IP/CIDR: " ip_input
                local ip_type=$(validate_ip_or_cidr "$ip_input")
                if [[ "$ip_type" == "ipv4" ]]; then
                    nft add element inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V4} "{ ${ip_input} }"
                    apply_and_save_changes $? "添加IPv4到SSH白名单: ${ip_input}" false
                elif [[ "$ip_type" == "ipv6" ]]; then
                    nft add element inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V6} "{ ${ip_input} }"
                    apply_and_save_changes $? "添加IPv6到SSH白名单: ${ip_input}" false
                else
                    echo -e "${RED}IP地址格式无效。${NC}"; sleep 1
                fi
                sleep 1
                ;;
            2)
                local source_set=$(select_from_ipset)
                if [ $? -ne 0 ]; then continue; fi
                
                local dest_set=""
                if [[ "$source_set" == *_v4 ]]; then
                    dest_set=${F2B_SSH_WHITELIST_SET_V4}
                elif [[ "$source_set" == *_v6 ]]; then
                    dest_set=${F2B_SSH_WHITELIST_SET_V6}
                else
                    echo -e "${RED}选择的IP集名称不规范 (非_v4或_v6结尾)。${NC}"; sleep 2; continue;
                fi
                
                echo -e "${YELLOW}正在从 @${source_set} 批量添加到 @${dest_set}...${NC}"
                # MODIFIED: Points to TABLE_NAME for user sets, but F2B_TABLE_NAME for destination set
                local elements=$(nft list set inet ${TABLE_NAME} ${source_set} | grep "elements = " | sed -e 's/.*elements = //')
                if [[ -n "$elements" ]]; then
                    nft add element inet ${F2B_TABLE_NAME} ${dest_set} "$elements"
                    apply_and_save_changes $? "从IP集 @${source_set} 添加到SSH白名单" false
                else
                    echo -e "${YELLOW}源IP集为空, 无操作。${NC}"; sleep 1
                fi
                sleep 1
                ;;
            3)
                if [ ${#all_ips[@]} -eq 0 ]; then echo -e "${RED}白名单为空, 无法删除。${NC}"; sleep 1; continue; fi
                
                read -p "请输入要删除的编号 (多选请用空格隔开, 或输入'da'删除所有): " del_input
                if [[ -z "$del_input" ]]; then continue; fi

                if [[ "${del_input,,}" == "da" || "${del_input,,}" == "deleteall" ]]; then
                    read -p "警告：您确定要删除所有SSH白名单IP吗? (y/N): " confirm
                    if [[ "$confirm" =~ ^[yY]$ ]]; then
                        nft flush set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V4}
                        nft flush set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V6}
                        apply_and_save_changes $? "清空所有SSH白名单" false
                    else
                        echo -e "${YELLOW}操作已取消。${NC}"
                    fi
                else
                    read -ra choices <<< "$del_input"
                    local valid_choices=true
                    for item in "${choices[@]}"; do
                        if ! [[ "$item" =~ ^[0-9]+$ && "$item" -ge 1 && "$item" -le ${#all_ips[@]} ]]; then
                            echo -e "${RED}输入错误: '$item' 不是有效编号。${NC}"; valid_choices=false; break
                        fi
                    done
                    if ! $valid_choices; then sleep 2; continue; fi

                    local sorted_choices=($(for i in "${choices[@]}"; do echo "$i"; done | sort -nur))
                    local deleted_count=0
                    local final_status=0
                    echo -e "${YELLOW}准备删除编号: ${sorted_choices[*]}...${NC}"
                    for choice in "${sorted_choices[@]}"; do
                        local index=$((choice-1))
                        local ip_to_delete=${all_ips[$index]}
                        local ip_type=$(validate_ip_or_cidr "$ip_to_delete")
                        local target_set=""
                        if [[ "$ip_type" == "ipv4" ]]; then target_set=${F2B_SSH_WHITELIST_SET_V4};
                        elif [[ "$ip_type" == "ipv6" ]]; then target_set=${F2B_SSH_WHITELIST_SET_V6}; fi
                        
                        if [[ -n "$target_set" ]]; then
                            nft delete element inet ${F2B_TABLE_NAME} ${target_set} "{ ${ip_to_delete} }"
                            if [ $? -eq 0 ]; then ((deleted_count++)); else final_status=1; fi
                        fi
                    done
                    apply_and_save_changes $final_status "从SSH白名单删除 ${deleted_count} 个条目" false
                fi
                sleep 1
                ;;
            q|Q) break ;;
            *) echo -e "\n${RED}无效选项。${NC}"; sleep 1 ;;
        esac
    done
}

# [最终的、功能最完善的 ssh_change_port 函数]
ssh_change_port() {
    local ssh_config="/etc/ssh/sshd_config"
    local jail_local="/etc/fail2ban/jail.local"
    clear
    echo -e "${BLUE}--- 一键安全切换 SSH 端口 ---${NC}\n"
    
    if [ ! -f "$ssh_config" ]; then
        echo -e "${RED}错误: 未找到SSH配置文件: ${ssh_config}${NC}"; press_any_key; return
    fi
    
    local current_port
    current_port=$(grep -i "^\s*Port\s" "$ssh_config" | awk '{print $2}' | tail -n 1)
    [[ -z "$current_port" ]] && current_port=22
    
    echo -e "${YELLOW}当前SSH端口为: ${GREEN}${current_port}${NC}"
    
    local new_port
    while true; do
        read -p "请输入新的SSH端口号 (1-65535, 'q'取消): " new_port
        if [[ "$new_port" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        if ! [[ "$new_port" =~ ^[0-9]+$ && "$new_port" -ge 1 && "$new_port" -le 65535 ]]; then echo -e "${RED}无效端口号。${NC}";
        elif [ "$new_port" -eq "$current_port" ]; then echo -e "${RED}新端口不能与当前端口相同。${NC}";
        elif ss -tlnp | grep -q ":${new_port}\s"; then echo -e "${RED}端口 ${new_port} 已被其他进程占用。${NC}";
        else break; fi
    done
    
    echo -e "\n${RED}========================[ 严重警告 ]========================${NC}"
    echo -e "${YELLOW}您确定要将SSH端口从 ${GREEN}${current_port}${YELLOW} 更改为 ${GREEN}${new_port}${YELLOW} 吗?${NC}"
    read -p "请输入 'yes' 以确认继续: " confirm
    if [[ "$confirm" != "yes" ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi

    echo -e "\n${YELLOW}1. 正在备份并修改SSH配置...${NC}"
    cp "$ssh_config" "${ssh_config}.bak.$(date +%F-%T)"
    if grep -q -i "^\s*Port\s" "$ssh_config"; then sed -i "s/^\s*Port\s.*/Port ${new_port}/" "$ssh_config"; else echo -e "\nPort ${new_port}" >> "$ssh_config"; fi
    echo -e "${GREEN}  -> 完成。${NC}"

    echo -e "\n${YELLOW}2. 正在更新 nftables 防火墙规则...${NC}"
    
    # 新增逻辑：检查并继承“仅IPv4”状态
    local is_ipv4_only=false
    local old_rule_text=$(nft --handle list chain inet "${TABLE_NAME}" "${INPUT_CHAIN}" | grep '"核心:允许SSH' | head -n 1)
    if [[ "$old_rule_text" == *"meta nfproto ipv4"* ]]; then
        is_ipv4_only=true
        echo -e "${CYAN}  -> 检测到当前SSH规则为“仅IPv4”模式，将保持此设置。${NC}"
    fi

    # 使用修正后的grep查找所有相关的旧规则
    local ssh_rule_handles=($(nft --handle list chain inet "${TABLE_NAME}" "${INPUT_CHAIN}" | grep '"核心:允许SSH' | awk '{print $NF}'))
    if [ ${#ssh_rule_handles[@]} -gt 0 ]; then
        for handle in "${ssh_rule_handles[@]}"; do
            echo -e "${CYAN}  -> 删除旧规则 (Handle: ${handle})...${NC}"
            nft delete rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "$handle"
        done
    fi
    
    echo -e "${CYAN}  -> 正在将新端口规则添加到正确位置...${NC}"
    local jump_handle=$(nft --handle list chain inet "${TABLE_NAME}" "${INPUT_CHAIN}" | grep '"跳转到用户入站规则主链"' | awk '{print $NF}')
    local final_status=0

    # 根据之前检测到的状态，添加正确的规则
    if $is_ipv4_only; then
        local comment="\"核心:允许SSH (IPv4 Only)\""
        if [[ -n "$jump_handle" ]]; then
            nft insert rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "$jump_handle" meta nfproto ipv4 tcp dport "$new_port" accept comment "$comment" || final_status=1
        else
            nft add rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" meta nfproto ipv4 tcp dport "$new_port" accept comment "$comment" || final_status=1
        fi
    else
        local comment="\"核心:允许SSH\""
        if [[ -n "$jump_handle" ]]; then
            nft insert rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "$jump_handle" tcp dport "$new_port" accept comment "$comment" || final_status=1
        else
            nft add rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" tcp dport "$new_port" accept comment "$comment" || final_status=1
        fi
    fi
    apply_and_save_changes $final_status "更新SSH端口防火墙规则" false
    echo -e "${GREEN}  -> 完成。${NC}"

    echo -e "\n${YELLOW}3. 正在更新 Fail2ban 配置...${NC}"
    if [ -f "$jail_local" ] && grep -q '\[sshd\]' "$jail_local"; then if awk '/\[sshd\]/{f=1} f && /port\s*=/ {print; f=0}' "$jail_local" | grep -q port; then sed -i "/\[sshd\]/,/\[.*\]/ s/^\s*port\s*=.*/port = ${new_port}/" "$jail_local"; else sed -i "/\[sshd\]/a port = ${new_port}" "$jail_local"; fi; echo -e "${GREEN}  -> 完成。${NC}"; else echo -e "${YELLOW}  -> 未找到 [sshd] jail 配置, 跳过。${NC}"; fi
    
    echo -e "\n${YELLOW}4. 正在重启服务...${NC}"
    echo -e "${CYAN}  -> 重启 sshd 服务...${NC}"
    if ! systemctl restart sshd; then
        echo -e "${RED}!!!!!!!!!! SSH服务重启失败 !!!!!!!!!!"
        echo -e "错误: 无法启动SSH服务。配置可能存在问题。"
        echo -e "请立即手动检查: journalctl -xeu sshd"
        echo -e "配置文件备份在: ${ssh_config}.bak.*"
        echo -e "防火墙规则已回滚, 您当前连接应该安全。请勿断开！${NC}"
        # 回滚防火墙操作
        local old_rule_body=""
        if $is_ipv4_only; then old_rule_body="meta nfproto ipv4 tcp dport ${current_port} accept comment '\"核心:允许SSH (IPv4 Only)\"'"; else old_rule_body="tcp dport ${current_port} accept comment '\"核心:允许SSH\"'"; fi
        if [[ -n "$jump_handle" ]]; then nft insert rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "$jump_handle" $old_rule_body; else nft add rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" $old_rule_body; fi
        apply_and_save_changes 0 "SSH端口修改失败, 回滚防火墙" false
        press_any_key; return
    fi
    echo -e "${CYAN}  -> 重启 fail2ban 服务...${NC}"
    systemctl restart fail2ban
    
    echo -e "\n${GREEN}==================[ 操作成功 ]==================${NC}"
    echo -e "${GREEN}SSH端口已成功切换为: ${CYAN}${new_port}${NC}"
    echo -e "${YELLOW}您当前的SSH会话不会中断。${NC}"
    echo -e "${RED}请立即使用新端口 ${new_port} 尝试建立新连接以确认配置无误！${NC}"
    press_any_key
}

# MODIFIED: Whitelist sets are now flushed from f2b-table.
reset_fail2ban_data() {
    clear
    echo -e "${BLUE}--- 彻底重置 Fail2ban 所有数据 ---${NC}\n"

    if ! command -v fail2ban-client &>/dev/null; then
        echo -e "${YELLOW}Fail2ban 未安装, 无需重置。${NC}"; press_any_key; return
    fi

    echo -e "${RED}========================[ 极度危险操作警告 ]========================${NC}"
    echo -e "${YELLOW}您正准备彻底清空 Fail2ban 的所有数据, 此操作不可逆！${NC}"
    echo -e "将会执行以下操作:"
    echo -e " 1. 停止 Fail2ban 服务。"
    echo -e " 2. ${RED}删除 Fail2ban 在 Nftables 中创建的表、链和集。${NC}"
    echo -e " 3. ${RED}清空脚本为SSH创建的优先白名单 (F2B_SSH_WHITELIST sets)。${NC}"
    echo -e " 4. ${RED}删除 Fail2ban 的封禁历史数据库。${NC}"
    echo -e " 5. ${RED}删除 Fail2ban 的所有日志文件。${NC}"
    echo -e " 6. ${RED}清空 Fail2ban 配置文件中的内部白名单 (ignoreip)。${NC}"
    echo -e " 7. 重启服务, 让 Fail2ban 重建一个全新的、空的状态。"
    echo -e "${PURPLE}======================================================================${NC}"
    read -p "我已了解全部风险并确认要重置, 请输入 'yes' 以继续: " confirm

    if [[ "$confirm" != "yes" ]]; then
        echo -e "\n${GREEN}操作已取消, 数据未被改动。${NC}"; press_any_key; return
    fi

    echo -e "\n${YELLOW}1. 正在停止 Fail2ban 服务...${NC}"
    if ! systemctl stop fail2ban; then
        echo -e "${RED}错误：停止 Fail2ban 服务失败, 为安全起见, 操作中止。${NC}"
        echo -e "${YELLOW}请手动检查服务状态: systemctl status fail2ban${NC}"; press_any_key; return
    fi
    echo -e "${GREEN} -> 服务已成功停止。${NC}"
    sleep 1

    echo -e "\n${YELLOW}2. 正在清理 Nftables 中的 Fail2ban 规则...${NC}"
    if nft list table inet ${F2B_TABLE_NAME} &>/dev/null; then
        nft delete table inet ${F2B_TABLE_NAME}
        echo -e "${GREEN} -> 已成功删除 Nftables table: '${F2B_TABLE_NAME}'。${NC}"
    else
        echo -e "${CYAN} -> Nftables table '${F2B_TABLE_NAME}' 不存在, 跳过。${NC}"
    fi

    echo -e "\n${YELLOW}3. 正在清空脚本创建的SSH优先白名单...${NC}"
    if nft list set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V4} &>/dev/null; then
        nft flush set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V4}
        echo -e "${GREEN} -> 已清空 set: ${F2B_SSH_WHITELIST_SET_V4}${NC}"
    fi
    if nft list set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V6} &>/dev/null; then
        nft flush set inet ${F2B_TABLE_NAME} ${F2B_SSH_WHITELIST_SET_V6}
        echo -e "${GREEN} -> 已清空 set: ${F2B_SSH_WHITELIST_SET_V6}${NC}"
    fi
    
    apply_and_save_changes 0 "清理所有Fail2ban相关Nftables规则" false

    echo -e "\n${YELLOW}4. 正在删除 Fail2ban 数据库...${NC}"
    local db_path="/var/lib/fail2ban/fail2ban.sqlite3"
    if [ -f "$db_path" ]; then
        if rm -f "$db_path"; then echo -e "${GREEN} -> 数据库 '${db_path}' 已成功删除。${NC}"; else echo -e "${RED} -> 删除数据库失败！请检查权限。${NC}"; fi
    else
        echo -e "${CYAN} -> 数据库不存在, 跳过。${NC}"
    fi

    echo -e "\n${YELLOW}5. 正在删除 Fail2ban 日志...${NC}"
    if ls /var/log/fail2ban.log* 1> /dev/null 2>&1; then
        if rm -f /var/log/fail2ban.log*; then echo -e "${GREEN} -> 日志文件 '/var/log/fail2ban.log*' 已成功删除。${NC}"; else echo -e "${RED} -> 删除日志失败！请检查权限。${NC}"; fi
    else
        echo -e "${CYAN} -> 日志文件不存在, 跳过。${NC}"
    fi
    
    echo -e "\n${YELLOW}6. 正在清理 Fail2ban 配置文件中的内部白名单 (ignoreip)...${NC}"
    local config_path="/etc/fail2ban/jail.local"
    if [ -f "$config_path" ]; then
        sed -i '/^\s*ignoreip\s*=/d' "$config_path"
        if [ $? -eq 0 ]; then echo -e "${GREEN} -> 已从 '${config_path}' 中移除 'ignoreip' 配置行。${NC}"; else echo -e "${RED} -> 移除 'ignoreip' 配置失败！${NC}"; fi
    else
        echo -e "${CYAN} -> 配置文件 '${config_path}' 不存在, 跳过。${NC}"
    fi

    echo -e "\n${YELLOW}7. 正在重启 Fail2ban 服务以完成重置...${NC}"
    systemctl start fail2ban
    sleep 2
    if systemctl is-active --quiet fail2ban; then
        echo -e "\n${GREEN}==================[ 重置成功 ]==================${NC}"
        echo -e "${GREEN}Fail2ban 已被重置为全新状态, 所有历史数据已清除。${NC}"
        echo -e "${CYAN}服务已重启并会自动重新创建规则和文件。${NC}"
    else
        echo -e "\n${RED}!!!!!!!!!! 重置后服务启动失败 !!!!!!!!!!"
        echo -e "${RED}请立即手动检查服务状态: journalctl -xeu fail2ban${NC}"
    fi
    press_any_key
}

get_ssh_defense_policy_status() {
    local POLICY_COMMENT="F2B-POLICY:DROP-ALL-OTHERS"
    if nft list chain inet "$TABLE_NAME" "$INPUT_CHAIN" 2>/dev/null | grep -q "$POLICY_COMMENT"; then
        echo -e "${RED}(当前: Drop)${NC}"
    else
        echo -e "${GREEN}(当前: Accept)${NC}"
    fi
}

toggle_ssh_defense_policy() {
    clear
    echo -e "${BLUE}--- 切换 SSH 防御策略 ---${NC}\n"
    local POLICY_COMMENT="F2B-POLICY:DROP-ALL-OTHERS"
    local DROP_RULE_HANDLE=$(nft --handle list chain inet "$TABLE_NAME" "$INPUT_CHAIN" 2>/dev/null | grep "$POLICY_COMMENT" | awk '{print $NF}')

    local ssh_ports=$(ss -tlpn "sport = :*" 2>/dev/null | grep 'sshd' | grep -oE ':[0-9]+' | sed 's/://g' | sort -u | tr '\n' ',' | sed 's/,$//')
    if [[ -z "$ssh_ports" ]]; then ssh_ports="22"; fi
    
    local formatted_ssh_ports
    if [[ "$ssh_ports" == *,* ]]; then formatted_ssh_ports="{ ${ssh_ports} }"; else formatted_ssh_ports="$ssh_ports"; fi

    if [[ -n "$DROP_RULE_HANDLE" ]]; then
        # Currently in Drop mode, switch to Accept
        echo -e "${YELLOW}当前为 [Drop] 模式 (仅白名单), 正在切换回 [Accept] 标准模式...${NC}"
        nft delete rule inet "$TABLE_NAME" "$INPUT_CHAIN" handle "$DROP_RULE_HANDLE"
        apply_and_save_changes $? "切换SSH防御策略为 [Accept]"
    else
        # Currently in Accept mode, switch to Drop
        echo -e "${RED}========================[ 警告 ]========================${NC}"
        echo -e "${YELLOW}您正准备切换到 [Drop] 防御模式 (白名单唯一模式)。${NC}"
        echo -e "此模式激活后:"
        echo -e " 1. ${RED}只有${NC}在 “SSH白名单” 中的IP地址才能连接SSH端口 (${ssh_ports})。"
        echo -e " 2. ${RED}所有其他IP${NC}的连接请求将被直接丢弃(Drop)，不会触发Fail2ban。"
        echo -e " 3. 这是一种更严格的安全策略。"
        echo -e "${YELLOW}在切换前，请务必确认您常用的IP地址已加入SSH白名单！${NC}"
        echo -e "${PURPLE}======================================================${NC}"
        read -p "我已了解风险, 确定要切换到 [Drop] 模式吗? (请输入 'yes' 确认): " confirm

        if [[ "$confirm" == "yes" ]]; then
            echo -e "\n${CYAN}  -> 正在确保SSH白名单规则存在...${NC}"
            # ensure_ssh_whitelist_rules_exist is obsolete, but the logic below finds another anchor point
            
            local f2b_chain_handle=$(nft --handle list chain inet "$TABLE_NAME" "$INPUT_CHAIN" 2>/dev/null | grep 'f2b-chain' | awk '{print $NF}')
            local insertion_handle=""
            local insertion_point_desc=""

            if [[ -n "$f2b_chain_handle" ]]; then
                insertion_handle=$f2b_chain_handle
                insertion_point_desc="Fail2ban 链"
            else
                insertion_handle=$(nft --handle list chain inet "$TABLE_NAME" "$INPUT_CHAIN" 2>/dev/null | grep '"核心:允许SSH"' | awk '{print $NF}')
                insertion_point_desc="核心SSH规则"
            fi

            if [[ -n "$insertion_handle" ]]; then
                echo -e "\n${YELLOW}正在基于 [${insertion_point_desc}] 插入 Drop 规则...${NC}"
                nft insert rule inet "$TABLE_NAME" "$INPUT_CHAIN" handle "$insertion_handle" tcp dport "$formatted_ssh_ports" drop comment "\"$POLICY_COMMENT\""
                apply_and_save_changes $? "切换SSH防御策略为 [Drop]" "true" "add_block" "$ssh_ports"
            else
                echo -e "\n${RED}致命错误: 未找到任何可用于插入规则的关键锚点 (Fail2ban链 或 核心SSH规则)。${NC}"
                echo -e "${YELLOW}您的防火墙可能处于不完整的状态。建议重置防火墙。${NC}"
                press_any_key
            fi
        else
            echo -e "\n${GREEN}操作已取消。${NC}"
            press_any_key
        fi
    fi
}

# --- 新增函数：用于清理Fail2ban日志 ---
clear_fail2ban_log() {
    clear
    echo -e "${BLUE}--- 手动清理 Fail2ban 日志 ---${NC}\n"
    local log_file="/var/log/fail2ban.log"

    if [ ! -f "$log_file" ]; then
        echo -e "${YELLOW}日志文件 '${log_file}' 不存在, 无需清理。${NC}"
        press_any_key
        return
    fi

    echo -e "${RED}====================[ 操作警告 ]====================${NC}"
    echo -e "${YELLOW}您确定要清空 Fail2ban 的主日志文件 (${log_file}) 吗?${NC}"
    echo -e "${RED}此操作不可撤销，但不会影响已封禁的IP。${NC}"
    echo -e "${PURPLE}======================================================${NC}"
    read -p "请输入 'yes' 以确认清空: " confirm

    if [[ "$confirm" == "yes" ]]; then
        echo -e "\n${YELLOW}正在清空日志文件...${NC}"
        # 使用 truncate 或 > 来清空文件，而不是删除，这样服务可以无缝继续写入
        if truncate -s 0 "$log_file"; then
            echo -e "${GREEN}日志文件已成功清空！${NC}"
        else
            echo -e "${RED}错误: 清空日志文件失败！请检查文件权限。${NC}"
        fi
    else
        echo -e "\n${GREEN}操作已取消。${NC}"
    fi
    press_any_key
}

# --- 新增函数: 获取IPv6 SSH开关状态 (全新重写版) ---
get_ipv6_ssh_status() {
    # 查找包含特定注释的规则, 这是最可靠的判断方式
    if nft --handle list chain inet "${TABLE_NAME}" "${INPUT_CHAIN}" 2>/dev/null | grep -q 'comment "核心:允许SSH (IPv4 Only)"'; then
        # 如果找到了带 (IPv4 Only) 注释的规则, 说明已关闭
        echo -e "${GREEN}(当前: 关闭)${NC}"
    else
        # 否则, 只要核心SSH规则存在, 就认为是打开状态
        echo -e "${RED}(当前: 打开)${NC}"
    fi
}

# --- 新增函数: 切换IPv6 SSH开关 (最终完美原子化版) ---
toggle_ipv6_ssh() {
    clear
    echo -e "${BLUE}--- 切换 IPv6 SSH 访问状态 ---${NC}\n"

    local COMMENT_IPV4_ONLY="核心:允许SSH (IPv4 Only)"
    local COMMENT_INET="核心:允许SSH"
    
    # 查找核心SSH规则的完整行和句柄
    local CORE_SSH_RULE_LINE=$(nft --handle list chain inet "${TABLE_NAME}" "${INPUT_CHAIN}" 2>/dev/null | grep 'comment "核心:允许SSH')
    if [[ -z "$CORE_SSH_RULE_LINE" ]]; then
        echo -e "${RED}致命错误: 未能找到核心SSH放行规则！操作无法进行。${NC}"; press_any_key; return
    fi
    local SSH_RULE_HANDLE=$(echo "$CORE_SSH_RULE_LINE" | awk '{print $NF}')

    # 使用 ss 命令从系统直接获取准确的SSH端口, 这是最可靠的方式
    local ssh_ports_raw=$(ss -tlpn "sport = :*" 2>/dev/null | grep 'sshd' | grep -oE ':[0-9]+' | sed 's/://g' | sort -u | tr '\n' ',' | sed 's/,$//')
    if [[ -z "$ssh_ports_raw" ]]; then ssh_ports_raw="22"; fi

    # 格式化端口以适应nftables (单个: 22, 多个: { 22, 8022 })
    local ssh_ports_formatted
    if [[ "$ssh_ports_raw" == *,* ]]; then
        ssh_ports_formatted="{ $(echo "$ssh_ports_raw" | sed 's/,/, /g') }"
    else
        ssh_ports_formatted="$ssh_ports_raw"
    fi

    # 判断当前状态并执行相反操作
    if [[ "$CORE_SSH_RULE_LINE" == *"(IPv4 Only)"* ]]; then
        # --- 当前是关闭状态, 需要打开 (替换为通用规则) ---
        echo -e "${YELLOW}当前 IPv6 SSH 为 [关闭] 状态, 正在切换为 ${RED}[打开]${YELLOW}...${NC}"
        read -p "您确定要允许通过 IPv6 访问 SSH 吗? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            echo -e "\n${GREEN}操作已取消。${NC}"; press_any_key; return
        fi
        
        # 使用 replace 原子化替换规则
        nft replace rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "${SSH_RULE_HANDLE}" \
            tcp dport "${ssh_ports_formatted}" accept comment "\"${COMMENT_INET}\""
            
        apply_and_save_changes $? "打开 (启用) IPv6 SSH"

    else
        # --- 当前是打开状态, 需要关闭 (替换为仅IPv4规则) ---
        echo -e "${YELLOW}当前 IPv6 SSH 为 ${RED}[打开]${YELLOW} 状态, 正在切换为 ${GREEN}[关闭]${YELLOW}...${NC}"
        read -p "您确定要继续吗? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return
        fi
        
        # 使用 replace 原子化替换规则, 明确指定 meta nfproto ipv4
        nft replace rule inet "${TABLE_NAME}" "${INPUT_CHAIN}" handle "${SSH_RULE_HANDLE}" \
            meta nfproto ipv4 tcp dport "${ssh_ports_formatted}" accept comment "\"${COMMENT_IPV4_ONLY}\""
        
        local ports_to_flush=$(echo "$ssh_ports_formatted" | tr -d '{} ')
        # 关闭IPv6访问相当于增加了一个“区块”，需要清理现有连接
        apply_and_save_changes $? "关闭 (禁用) IPv6 SSH" "true" "add_block" "$ports_to_flush"
    fi
}

fail2ban_ssh_manager_menu() {
    if ! command -v fail2ban-client &>/dev/null; then
        install_fail2ban
        return
    fi
    
    while true; do
        if ! systemctl is-active --quiet fail2ban; then
            clear
            echo -e "${RED}错误: Fail2ban 服务当前未运行。${NC}"
            echo -e "${YELLOW}这可能是由于配置错误或服务启动失败。${NC}\n"
            echo -e "您可以尝试以下操作:"
            echo -e " ${GREEN}1.${NC} 尝试启动服务"
            echo -e " ${GREEN}2.${NC} 查看服务日志 (排查问题)"
            echo -e " ${GREEN}9.${NC} ${YELLOW}修复/重新应用默认配置${NC}"
            echo -e "\n ${GREEN}q.${NC} 返回主菜单"
            read -p "请选择: " recovery_choice
            case $recovery_choice in
                1) 
                    echo -e "\n${YELLOW}正在尝试启动 Fail2ban...${NC}"
                    systemctl start fail2ban
                    sleep 1
                    if systemctl is-active --quiet fail2ban; then
                        echo -e "${GREEN}服务启动成功！${NC}"
                    else
                        echo -e "${RED}服务启动失败！${NC}"
                    fi
                    press_any_key
                    ;;
                2)
                    clear
                    echo -e "${CYAN}--- Fail2ban 服务日志 (最近50条) ---${NC}\n"
                    journalctl -u fail2ban -n 50 --no-pager
                    press_any_key
                    ;;
                9) f2b_reapply_config ;;
                q|Q) break ;;
                *) echo -e "${RED}无效选择。${NC}"; sleep 1 ;;
            esac
            continue 
        fi

        local action_file="/etc/fail2ban/action.d/nftables-multiport.conf"
        local config_ok=false
        if [ -f "$action_file" ] && grep -q "# This file was programmatically generated by nftables.sh" "$action_file"; then
            config_ok=true
        fi

        if ! $config_ok && [ -f "/etc/fail2ban/jail.conf" ]; then
            clear
            echo -e "${YELLOW}============================[ 配置健康检查 ]============================${NC}"
            echo -e "${YELLOW}警告: 检测到您的Fail2ban动作配置不是由本脚本生成的最新版本,${NC}"
            echo -e "${YELLOW}      可能存在我们之前遇到的兼容性问题。${NC}"
            echo -e "${PURPLE}======================================================================${NC}"
            read -p "是否立即为您应用终极修复方案以确保最佳兼容性? (Y/n): " fix_confirm
            fix_confirm=${fix_confirm:-Y}
            if [[ "$fix_confirm" =~ ^[yY]$ ]]; then
                f2b_reapply_config
                continue
            fi
        fi

        clear
        local defense_policy_status=$(get_ssh_defense_policy_status)
        local ipv6_ssh_status=$(get_ipv6_ssh_status)
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "                          ${CYAN}Fail2ban 与 SSH 综合管理中心${NC}"
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "${BLUE}--- Fail2ban 管理 ---${NC}"
        echo -e " ${GREEN}1.${NC} 查看服务状态与统计"
        echo -e " ${GREEN}2.${NC} 查询 IP 是否被封禁 (支持CIDR)"
        echo -e " ${GREEN}3.${NC} ${YELLOW}手动封禁 IP / IP段 / IP集${NC}"
        echo -e " ${GREEN}4.${NC} ${CYAN}手动解封 IP / IP段 / IP集${NC}"
        echo -e " ${GREEN}5.${NC} 查看 Fail2ban 详细日志"
        echo -e " ${GREEN}6.${NC} ${RED}手动清理 Fail2ban 详细日志${NC}"
        echo -e " ${GREEN}7.${NC} ${YELLOW}更改 Fail2ban 核心参数${NC}"
        
        echo -e "\n${BLUE}--- SSH & 综合管理 ---${NC}"
        echo -e " ${GREEN}8.${NC} ${CYAN}SSH 白名单管理 (内置于Fail2ban链)${NC}"
        echo -e " ${GREEN}9.${NC} ${RED}一键安全切换 SSH 端口${NC}"
        echo -e " ${GREEN}10.${NC} 切换SSH防御策略 ${defense_policy_status}"
        echo -e " ${GREEN}11.${NC} 切换IPv6 SSH状态 ${ipv6_ssh_status}"
        
        echo -e "\n${BLUE}--- 维护 & 修复 ---${NC}"
        echo -e " ${GREEN}12.${NC} ${YELLOW}修复/重新应用默认配置${NC}"
        echo -e " ${GREEN}13.${NC} ${RED}彻底重置 Fail2ban (清空所有数据)${NC}"
        
        echo -e "\n${PURPLE}------------------------------------------------------${NC}"
        echo -e " ${GREEN}q.${NC} 返回主菜单"
        echo -e "${PURPLE}------------------------------------------------------${NC}"
        read -p "请输入您的选项: " choice
        case $choice in
            1)
                clear
                echo -e "${CYAN}--- Fail2ban 服务状态与统计 ---${NC}\n"

                echo -e "${BLUE}--- Systemd 服务状态 ---${NC}"
                systemctl status fail2ban --no-pager
                echo

                echo -e "${BLUE}--- Fail2ban 守护进程状态 (全局) ---${NC}"
                fail2ban-client status
                echo

                echo -e "${YELLOW}--- 各项防护策略(Jail)详情 ---${NC}"
                local jails=$(fail2ban-client status | grep "Jail list:" | sed -e 's/.*Jail list:[ \t]*//' -e 's/,//g')
                
                if [[ -z "$jails" ]]; then
                    echo -e "${CYAN}未发现任何活动的 Jail。${NC}"
                else
                    for jail in $jails; do
                        echo -e "\n${PURPLE}--------------------[ Jail: $jail ]--------------------${NC}"
                        fail2ban-client status "$jail"
                    done
                fi
                press_any_key
                ;;
            2)
                read -p "请输入要查询的IP地址: " ip_to_check
                if [[ -z "$ip_to_check" ]]; then continue; fi

                if ! validate_ip "$ip_to_check" "ipv4" && ! validate_ip "$ip_to_check" "ipv6"; then
                    echo -e "\n${RED}错误: 输入的IP地址格式不正确。${NC}"
                    sleep 2
                    continue
                fi
                
                clear
                echo -e "${CYAN}--- 查询 IP: ${ip_to_check} 的封禁状态 ---${NC}\n"

                local jails
                mapfile -t jails < <(fail2ban-client status | grep "Jail list:" | sed -e 's/.*Jail list:[ \t]*//' -e 's/,//g')
                local found_globally=false

                for jail in "${jails[@]}"; do
                    local banned_entries
                    mapfile -t banned_entries < <(fail2ban-client status "$jail" 2>/dev/null | grep 'Banned IP list:' | sed 's/.*Banned IP list:[ \t]*//')

                    if [ ${#banned_entries[@]} -eq 0 ]; then
                        continue
                    fi

                    for entry in ${banned_entries[@]}; do
                        if [[ "$ip_to_check" == "$entry" ]]; then
                            found_globally=true
                            break
                        fi

                        if [[ "$entry" == *"/"* ]] && command -v python3 &>/dev/null; then
                            if python3 -c "import ipaddress, sys; print(ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2], strict=False))" "$ip_to_check" "$entry" 2>/dev/null | grep -q "True"; then
                                found_globally=true
                                break
                            fi
                        fi
                    done

                    if $found_globally; then
                        echo -e "状态: ${RED}已封禁${NC} (于 Jail: ${YELLOW}$jail${NC})"
                        break
                    fi
                done

                if ! $found_globally; then
                    echo -e "状态: ${GREEN}未封禁${NC}"
                fi
                press_any_key
                ;;
            3) f2b_manual_action "banip" "封禁" ;;
            4) f2b_manual_action "unbanip" "解封" ;;
            5)
                clear
                echo -e "${CYAN}--- 查看 Fail2ban 日志 (/var/log/fail2ban.log) ---${NC}"
                echo -e "${YELLOW}使用 '↑'/'↓' 浏览, 按 'q' 退出...${NC}"
                sleep 2
                less /var/log/fail2ban.log
                ;;
            6) clear_fail2ban_log ;;
            7) f2b_change_params ;;
            8) ssh_whitelist_manager ;;
            9) ssh_change_port ;;
            10) toggle_ssh_defense_policy ;;
            11) toggle_ipv6_ssh ;;
            12) f2b_reapply_config ;;
            13) reset_fail2ban_data ;;
            q|Q) break ;;
            *) echo -e "\n${RED}无效选项。${NC}"; sleep 1 ;;
        esac
    done
}

# --- Socat Port Forwarding Manager ---
add_socat_rule() {
    clear
    echo -e "${BLUE}--- 新增 Socat 端口转发规则 (输入'q'可随时取消) ---${NC}\n"
    
    local listen_port dest_host dest_port protocol listen_family dest_family listen_ip=""
    
    while true; do
        read -p "请输入要监听的公网端口 (例如 80): " listen_port
        if [[ "$listen_port" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        if [[ "$listen_port" =~ ^[0-9]+$ && "$listen_port" -ge 1 && "$listen_port" -le 65535 ]]; then
            break
        else
            echo -e "${RED}错误: 无效的端口号。请输入 1-65535 之间的数字。${NC}"
        fi
    done

    while true; do
        echo -e "\n${CYAN}请选择监听地址类型 (Listen Family):${NC}"
        echo -e " ${GREEN}1)${NC} IPv4 [默认]"
        echo -e " ${GREEN}2)${NC} IPv6"
        read -p "请选择 [1-2]: " family_choice
        if [[ "$family_choice" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        family_choice=${family_choice:-1}
        case $family_choice in
            1) listen_family="ipv4"; break ;;
            2) listen_family="ipv6"; break ;;
            *) echo -e "${RED}无效选择。${NC}" ;;
        esac
    done

    while true; do
        echo -e "\n${CYAN}请选择监听地址:${NC}"
        echo -e " ${GREEN}1)${NC} 监听所有地址 (0.0.0.0 or ::) [默认]"
        echo -e " ${GREEN}2)${NC} 监听指定的一个本机IP地址"
        read -p "请选择 [1-2]: " listen_addr_choice
        if [[ "$listen_addr_choice" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        listen_addr_choice=${listen_addr_choice:-1}
        if [[ "$listen_addr_choice" == "1" ]]; then
            listen_ip=""
            break
        elif [[ "$listen_addr_choice" == "2" ]]; then
            listen_ip=$(select_specific_ip "$listen_family")
            if [ $? -ne 0 ]; then
                echo -e "\n${YELLOW}未选择IP地址, 操作已取消。${NC}"; press_any_key; return
            fi
            break
        else
            echo -e "${RED}无效选择。${NC}"
        fi
    done
    
    while true; do
        echo -e "\n${CYAN}请选择目标地址类型 (Destination Family):${NC}"
        echo -e " ${GREEN}1)${NC} IPv4 [默认]"
        echo -e " ${GREEN}2)${NC} IPv6"
        read -p "请选择 [1-2]: " family_choice
        if [[ "$family_choice" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        family_choice=${family_choice:-1}
        case $family_choice in
            1) dest_family="ipv4"; break ;;
            2) dest_family="ipv6"; break ;;
            *) echo -e "${RED}无效选择。${NC}" ;;
        esac
    done

    local default_dest_host="127.0.0.1"
    if [[ "$dest_family" == "ipv6" ]]; then default_dest_host="::1"; fi
    
    while true; do
        read -p "请输入目标主机IP地址 [默认: ${default_dest_host}]: " dest_host
        if [[ "$dest_host" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        dest_host=${dest_host:-$default_dest_host}
        if validate_ip "$dest_host" "$dest_family"; then
            break
        else
            echo -e "${RED}错误: IP地址格式与您选择的目标类型 (${dest_family}) 不匹配。${NC}"
        fi
    done
    
    while true; do
        read -p "请输入目标主机的端口 (例如 8080): " dest_port
        if [[ "$dest_port" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        if [[ "$dest_port" =~ ^[0-9]+$ && "$dest_port" -ge 1 && "$dest_port" -le 65535 ]]; then
            break
        else
            echo -e "${RED}错误: 无效的端口号。请输入 1-65535 之间的数字。${NC}"
        fi
    done
    
    while true; do
        echo -e "\n${CYAN}请选择转发协议:${NC}"
        echo -e " ${GREEN}1)${NC} TCP (适用于网页, SSH, 大多数应用) [默认]"
        echo -e " ${GREEN}2)${NC} UDP (适用于游戏, DNS, 某些流媒体)"
        read -p "请选择 [1-2]: " proto_choice
        if [[ "$proto_choice" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
        proto_choice=${proto_choice:-1}
        case $proto_choice in
            1) protocol="TCP"; break ;;
            2) protocol="UDP"; break ;;
            *) echo -e "${RED}无效选择。${NC}" ;;
        esac
    done

    local safe_dest_host=${dest_host//[.:]/}
    local safe_listen_ip_part=""
    if [[ -n "$listen_ip" ]]; then
        safe_listen_ip_part="$(echo ${listen_ip} | tr -d '.:')-"
    fi
    local service_name="socat-proxy-$(echo "$protocol" | tr 'A-Z' 'a-z')-l${listen_family}-d${dest_family}-${safe_listen_ip_part}${listen_port}-to-${safe_dest_host}-${dest_port}.service"
    local service_path="/etc/systemd/system/${service_name}"
    
    local listen_addr_desc="ANY"
    if [[ -n "$listen_ip" ]]; then
        listen_addr_desc="${listen_ip}"
    fi
    local description="Socat ${protocol}/${listen_family} -> ${protocol}/${dest_family} Proxy: ${listen_addr_desc}:${listen_port} to ${dest_host}:${dest_port}"

    if [ -f "$service_path" ]; then
        echo -e "\n${RED}错误: 完全相同的转发规则已存在。${NC}"
        press_any_key; return
    fi
    
    echo -e "\n${YELLOW}即将创建以下转发服务:${NC}"
    echo -e "  - ${CYAN}服务名称:${NC} ${service_name}"
    echo -e "  - ${CYAN}转发规则:${NC} ${listen_addr_desc}:${listen_port} (${protocol}/${listen_family}) -> ${dest_host}:${dest_port} (${protocol}/${dest_family})"
    read -p "确认创建吗? (Y/n): " confirm
    if [[ "$confirm" =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return; fi
    confirm=${confirm:-Y}

    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        echo -e "${YELLOW}操作已取消。${NC}"
        press_any_key
        return
    fi

    local listen_family_socat=$([[ "$listen_family" == "ipv6" ]] && echo "6" || echo "4")
    local dest_family_socat=$([[ "$dest_family" == "ipv6" ]] && echo "6" || echo "4")
    
    local listen_part="${protocol}${listen_family_socat}-LISTEN:${listen_port}"
    if [[ -n "$listen_ip" ]]; then
        listen_part+=",bind=${listen_ip}"
    fi
    listen_part+=",fork,reuseaddr"

    local exec_start_cmd="/usr/bin/socat ${listen_part} ${protocol}${dest_family_socat}:${dest_host}:${dest_port}"
    
    cat > "$service_path" << EOF
[Unit]
Description=${description}
After=network.target

[Service]
Type=simple
ExecStart=${exec_start_cmd}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    echo -e "\n${CYAN}正在重载 systemd 并启动服务...${NC}"
    systemctl daemon-reload
    if systemctl enable --now "${service_name}"; then
        echo -e "${GREEN}服务已成功创建并启动！${NC}"
        echo -e "\n${RED}====================[ 重要提示 ]====================${NC}"
        echo -e "${YELLOW}转发服务已启动, 但防火墙尚未放行端口 ${listen_port} (${protocol})。${NC}"
        echo -e "${YELLOW}请返回主菜单, 使用选项 ${GREEN}[4] ${NC}${GREEN}新增[入站端口放行]规则${YELLOW},${NC}"
        echo -e "${YELLOW}来允许外部流量访问此端口。${NC}"
        echo -e "${PURPLE}======================================================${NC}"
    else
        echo -e "${RED}错误: 服务创建或启动失败。${NC}"
        echo -e "${YELLOW}请尝试使用 'journalctl -u ${service_name}' 查看错误日志。${NC}"
        rm -f "$service_path"
        systemctl daemon-reload
    fi
    press_any_key
}

view_socat_rules() {
    while true; do
        clear
        echo -e "${BLUE}--- 查看/管理 Socat 转发规则 ---${NC}\n"
        
        mapfile -t services < <(find /etc/systemd/system/ -name "socat-proxy-*.service" -printf "%f\n" | sort -u)
        
        if [ ${#services[@]} -eq 0 ]; then
            echo -e "${YELLOW}当前没有已创建的 Socat 转发规则。${NC}"
            press_any_key
            break
        fi

        echo -e "${CYAN}当前已配置的转发规则:${NC}"
        local i=1
        for service in "${services[@]}"; do
            local description
            description=$(grep -oP 'Description=\K.*' "/etc/systemd/system/${service}")
            local status
            if systemctl is-active --quiet "$service"; then
                status="${GREEN}[运行中]${NC}"
            else
                status="${RED}[已停止]${NC}"
            fi
            echo -e " ${GREEN}[$i]${NC} - ${description} ${status}"
            ((i++))
        done
        
        echo -e "\n${PURPLE}---------------------------------[ 操作 ]---------------------------------${NC}"
        echo -e " ${GREEN}d <编号>${NC}    - ${RED}删除${NC}指定规则 (可多选, 如: d 1 3)"
        echo -e " ${GREEN}da${NC}          - ${RED}删除所有${NC}规则"
        echo -e " ${GREEN}stop <编号>${NC} - 停止指定规则 (可多选)"
        echo -e " ${GREEN}start <编号>${NC}- 启动指定规则 (可多选)"
        echo -e "\n ${GREEN}q.${NC}           - 返回"
        echo -e "${PURPLE}--------------------------------------------------------------------------${NC}"
        read -p "请输入您的操作和编号: " action_input
        
        if [[ $action_input =~ ^[qQ]$ ]]; then break; fi

        local action
        action=$(echo "$action_input" | awk '{print tolower($1)}')
        
        if [[ "$action" == "da" ]]; then
            read -p "警告: 您确定要永久删除所有 ${#services[@]} 条转发规则吗? (y/N): " confirm
            if [[ "$confirm" =~ ^[yY]$ ]]; then
                echo -e "${YELLOW}正在删除所有规则...${NC}"
                for service_to_manage in "${services[@]}"; do
                    systemctl disable --now "$service_to_manage" &>/dev/null
                    rm -f "/etc/systemd/system/${service_to_manage}"
                done
                systemctl daemon-reload
                echo -e "${GREEN}所有规则已成功删除。${NC}"
            else
                echo -e "${YELLOW}操作已取消。${NC}"
            fi
            sleep 1; continue
        fi

        local choices_str
        choices_str=$(echo "$action_input" | cut -d' ' -f2-)
        read -ra choices <<< "$choices_str"

        if [ ${#choices[@]} -eq 0 ]; then
            echo -e "\n${RED}无效输入, 未提供编号。${NC}"; sleep 1
            continue
        fi
        
        local valid_choices=true
        for choice in "${choices[@]}"; do
            if ! [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#services[@]} ]]; then
                echo -e "\n${RED}输入错误: '$choice' 不是一个有效的编号。${NC}"; sleep 2
                valid_choices=false; break
            fi
        done
        if ! $valid_choices; then continue; fi

        local sorted_choices
        sorted_choices=($(for i in "${choices[@]}"; do echo "$i"; done | sort -nur))

        for choice in "${sorted_choices[@]}"; do
            local index=$((choice-1))
            local service_to_manage="${services[$index]}"

            case "$action" in
                d|delete)
                    echo -e "${YELLOW}正在删除规则 [${choice}] (${service_to_manage})...${NC}"
                    systemctl disable --now "$service_to_manage" &>/dev/null
                    rm -f "/etc/systemd/system/${service_to_manage}"
                    ;;
                stop)
                    echo -e "${YELLOW}正在停止服务 [${choice}]...${NC}"
                    systemctl stop "$service_to_manage"
                    ;;
                start)
                    echo -e "${YELLOW}正在启动服务 [${choice}]...${NC}"
                    systemctl start "$service_to_manage"
                    ;;
                *)
                    echo -e "\n${RED}无效的操作。${NC}"; sleep 1; break
                    ;;
            esac
        done
        
        if [[ "$action" == "d" || "$action" == "delete" ]]; then
            systemctl daemon-reload
            echo -e "${GREEN}删除操作已完成。正在刷新列表...${NC}"
        else
            echo -e "${GREEN}操作已完成。正在刷新列表...${NC}"
        fi
        sleep 1
    done
}



socat_manager_menu() {
    while true; do
        clear
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "                       ${CYAN}轻量级端口转发 (Socat) 中心${NC}"
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "${YELLOW}此功能通过 systemd 管理 socat 进程, 实现持久化端口转发。${NC}"
        echo -e " ${GREEN}1.${NC} 添加新的转发规则"
        echo -e " ${GREEN}2.${NC} 查看/管理现有规则"
        echo -e "\n ${GREEN}q.${NC} 返回主菜单"
        echo -e "${PURPLE}------------------------------------------------------${NC}"
        read -p "请输入您的选项: " choice
        case $choice in
            1) add_socat_rule ;;
            2) view_socat_rules ;;
            q|Q) break ;;
            *) echo -e "\n${RED}无效选项。${NC}"; sleep 1 ;;
        esac
    done
}

detailed_network_monitor_menu() {
    while true; do
        clear
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "                                      ${CYAN}超级网络监控中心${NC}"
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "${YELLOW}提供四个维度、预设好最佳参数的实时监控工具:${NC}"
        echo -e " ${GREEN}1.${NC} ${CYAN}按进程+连接监控 (nethogs)${NC}"
        echo -e "    - ${NC}查看哪个【程序】正在连接，以及它的速度和目标地址。"
        echo -e " ${GREEN}2.${NC} ${CYAN}按流量+流向监控 (iftop)${NC}"
        echo -e "    - ${NC}查看本机与哪个【IP】之间的流量最大，分析带宽占用。"
        echo -e " ${GREEN}3.${NC} ${CYAN}按网卡状态监控 (bmon)${NC}"
        echo -e "    - ${NC}图形化显示【网卡】的实时流量、速率和硬件错误统计。"
        echo -e " ${GREEN}4.${NC} ${CYAN}全连接状态快照 (ss)${NC}"
        echo -e "    - ${NC}查看【所有】网络连接的详细技术状态，每秒刷新。"
        echo -e "\n ${GREEN}q.${NC} 返回主菜单"
        echo -e "${PURPLE}------------------------------------------------------${NC}"
        read -p "请选择监控工具: " choice
        
        case $choice in
            1)
                clear
                echo -e "${CYAN}正在启动 nethogs (详细模式)...${NC}"
                echo -e "${YELLOW}此模式可同时看到进程名、速度、本地和远程端口。按 'q' 退出。${NC}"
                sleep 2
                nethogs -d 1 -v 3
                ;;
            2)
                clear
                local default_iface
                default_iface=$(ip -o route get 8.8.8.8 | sed -n 's/.*dev \([^\ ]*\).*/\1/p')
                if [[ -z "$default_iface" ]]; then
                    echo -e "${RED}错误: 无法自动检测到默认网络接口。${NC}"
                    press_any_key
                    continue
                fi
                echo -e "${CYAN}正在启动 iftop (监控接口: ${default_iface})...${NC}"
                echo -e "${YELLOW}此模式可看到IP对之间的实时流量，按 'q' 退出。${NC}"
                sleep 2
                iftop -i "${default_iface}" -nNPB -s 1
                ;;
            3)
                clear
                echo -e "${CYAN}正在启动 bmon (兼容模式)...${NC}"
                echo -e "${YELLOW}bmon 将以最大兼容性模式启动。${NC}"
                echo -e "${YELLOW}启动后请手动使用 [↑/↓] 选择网卡, [d]看详情, [g]看图表, [q]退出。${NC}"
                sleep 3
                TERM=xterm bmon
                ;;
            4)
                clear
                echo -e "${CYAN}正在启动 ss (全连接状态快照)...${NC}"
                echo -e "${YELLOW}此模式显示所有连接的内核级详细信息，每秒刷新并高亮变化。按 'Ctrl+C' 退出。${NC}"
                sleep 2
                watch -n 1 -d "ss -tunaepimo"
                ;;
            q|Q)
                break
                ;;
            *)
                echo -e "\n${RED}无效选项。${NC}"; sleep 1
                ;;
        esac
    done
}

# --- 备份与恢复 ---
backup_rules() {
    clear
    echo -e "${BLUE}--- 备份当前防火墙规则 ---${NC}\n"
    local backup_path
    read -e -p "请输入备份目录 [默认: ${BACKUP_DIR}]: " backup_path
    backup_path=${backup_path:-$BACKUP_DIR}

    if ! mkdir -p "$backup_path"; then
        echo -e "\n${RED}错误: 无法创建备份目录 '${backup_path}'。请检查权限。${NC}"
        press_any_key
        return
    fi
    
    local backup_file="nftables-rules-$(date +%Y%m%d-%H%M%S).bak"
    local full_path="${backup_path}/${backup_file}"
    
    echo -e "\n${YELLOW}正在将当前规则备份到:${NC} ${CYAN}${full_path}${NC}"
    if nft list ruleset > "$full_path"; then
        echo -e "\n${GREEN}备份成功！${NC}"
    else
        echo -e "\n${RED}备份失败。${NC}"
    fi
    press_any_key
}

restore_rules() {
    clear
    echo -e "${BLUE}--- 从文件恢复防火墙规则 ---${NC}\n"
    local backup_path
    read -e -p "请输入备份所在目录 [默认: ${BACKUP_DIR}]: " backup_path
    backup_path=${backup_path:-$BACKUP_DIR}
    
    if [ ! -d "$backup_path" ]; then
        echo -e "\n${RED}错误: 目录 '${backup_path}' 不存在。${NC}"
        press_any_key
        return
    fi

    mapfile -t backups < <(find "$backup_path" -maxdepth 1 -name "*.bak" -printf "%f\n" | sort -r)

    if [ ${#backups[@]} -eq 0 ]; then
        echo -e "\n${YELLOW}在目录 '${backup_path}' 中未找到任何备份文件 (*.bak)。${NC}"
        press_any_key
        return
    fi

    echo -e "${CYAN}请选择要恢复的备份文件:${NC}"
    local i=1
    for bak in "${backups[@]}"; do
        echo -e " ${GREEN}[$i]${NC} - ${bak}"
        ((i++))
    done
    echo -e "\n ${GREEN}q.${NC} - 取消"
    
    local choice
    read -p "请选择序号: " choice
    if [[ $choice =~ ^[qQ]$ ]] || [[ -z "$choice" ]]; then
        echo -e "\n${YELLOW}操作已取消。${NC}"; press_any_key; return
    fi

    if ! [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#backups[@]} ]]; then
        echo -e "\n${RED}无效的选择。${NC}"; press_any_key; return
    fi
    
    local index=$((choice-1))
    local file_to_restore="${backup_path}/${backups[$index]}"
    
    echo -e "\n${RED}========================[ 严重警告 ]========================${NC}"
    echo -e "${YELLOW}您确定要从 '${backups[$index]}' 恢复规则吗?${NC}"
    echo -e "${RED}此操作将【彻底覆盖】所有当前正在运行的防火墙规则！${NC}"
    echo -e "${PURPLE}==========================================================${NC}"
    read -p "请输入 'yes' 确认恢复: " confirm

    if [[ "$confirm" != "yes" ]]; then
        echo -e "\n${YELLOW}操作已取消。${NC}"
        press_any_key
        return
    fi
    
    echo -e "\n${YELLOW}正在恢复规则...${NC}"
    if nft flush ruleset && nft -f "$file_to_restore"; then
        echo -e "${GREEN}规则已成功从备份恢复！${NC}"
        apply_and_save_changes 0 "恢复规则" false "del_allow" "all"
    else
        echo -e "${RED}恢复失败！防火墙可能处于不稳定状态。${NC}"
        echo -e "${YELLOW}建议立即【重置防火墙】或从其他备份恢复。${NC}"
    fi
    press_any_key
}

backup_restore_menu() {
    while true; do
        clear
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "                                      ${CYAN}备份与恢复中心${NC}"
        echo -e "${PURPLE}======================================================${NC}"
        echo -e " ${GREEN}1.${NC} 备份当前所有规则"
        echo -e " ${GREEN}2.${NC} ${RED}从文件恢复规则${NC}"
        echo -e "\n ${GREEN}q.${NC} 返回主菜单"
        echo -e "${PURPLE}------------------------------------------------------${NC}"
        read -p "请输入您的选项: " choice
        case $choice in
            1) backup_rules ;;
            2) restore_rules ;;
            q|Q) break ;;
            *) echo -e "\n${RED}无效选项。${NC}"; sleep 1 ;;
        esac
    done
}

# --- 快捷方式管理 ---
create_shortcut() {
    clear
    echo -e "${BLUE}--- 创建终端快捷方式 ---${NC}\n"
    local shortcut=${SHORTCUT_NAME}
    local script_path
    script_path=$(realpath "$0")
    local link_path="/usr/local/bin/${shortcut}"

    if [ -e "$link_path" ]; then
        if [ -L "$link_path" ] && [ "$(readlink "$link_path")" = "$script_path" ]; then
            echo -e "${GREEN}快捷方式 '${shortcut}' 已存在, 无需创建。${NC}"
            press_any_key
            return
        fi
        echo -e "${YELLOW}警告: '${link_path}' 已存在一个文件或快捷方式。${NC}"
        read -p "是否要覆盖它? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[yY]$ ]]; then
            echo -e "${YELLOW}操作已取消。${NC}"; press_any_key; return
        fi
    fi

    echo -e "${YELLOW}正在创建快捷方式 '${shortcut}' 指向 '${script_path}'...${NC}"
    chmod +x "$script_path"
    if ln -sf "$script_path" "$link_path"; then
        echo -e "\n${GREEN}快捷方式创建成功！${NC}"
        echo -e "现在您可以在终端任何位置输入 ${CYAN}${shortcut}${NC} 来运行此脚本。"
    else
        echo -e "\n${RED}快捷方式创建失败。请检查 /usr/local/bin 目录的权限。${NC}"
    fi
    press_any_key
}

delete_shortcut() {
    clear
    echo -e "${BLUE}--- 删除终端快捷方式 ---${NC}\n"
    local shortcut=${SHORTCUT_NAME}
    local link_path="/usr/local/bin/${shortcut}"
    local script_path
    script_path=$(realpath "$0")

    if [ ! -L "$link_path" ]; then
        echo -e "${YELLOW}快捷方式 '${shortcut}' 不存在, 或不是一个快捷方式。${NC}"
        press_any_key
        return
    fi
    
    if [ "$(readlink "$link_path")" != "$script_path" ]; then
        echo -e "${RED}错误: '${shortcut}' 指向其他文件, 为安全起见, 本脚本不会删除它。${NC}"
        press_any_key
        return
    fi
    
    echo -e "${YELLOW}正在删除快捷方式 '${shortcut}'...${NC}"
    if rm "$link_path"; then
        echo -e "\n${GREEN}快捷方式已成功删除。${NC}"
    else
        echo -e "\n${RED}删除失败。请检查 /usr/local/bin 目录的权限。${NC}"
    fi
    press_any_key
}

shortcut_manager_menu() {
    while true; do
        clear
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "                                      ${CYAN}终端快捷方式管理${NC}"
        echo -e "${PURPLE}======================================================${NC}"
        echo -e " ${GREEN}1.${NC} 创建快捷方式 (命令: ${SHORTCUT_NAME})"
        echo -e " ${GREEN}2.${NC} ${RED}删除快捷方式${NC} (命令: ${SHORTCUT_NAME})"
        echo -e "\n ${GREEN}q.${NC} 返回主菜单"
        echo -e "${PURPLE}------------------------------------------------------${NC}"
        read -p "请输入您的选项: " choice
        case $choice in
            1) create_shortcut ;;
            2) delete_shortcut ;;
            q|Q) break ;;
            *) echo -e "\n${RED}无效选项。${NC}"; sleep 1 ;;
        esac
    done
}

# =================================================================
#
# ### 开始: Docker v1.2 网络管理模块的完整代码 ###
#
# =================================================================

# --- [新] 全局变量定义 (请将这部分添加到脚本顶部的全局变量区) ---
FORWARD_CHAIN="forward";
DOCKER_CHAIN="DOCKER_FILTER_CHAIN";
DOCKER_IP_WHITELIST="DOCKER_IP_WHITELIST";
DOCKER_IP_BLACKLIST="DOCKER_IP_BLACKLIST";
DOCKER_PORT_ALLOW="DOCKER_PORT_ALLOW";
DOCKER_PORT_DENY="DOCKER_PORT_DENY";

# --- [新] initialize_firewall 函数 (请用这个版本完整替换您现有的同名函数) ---
initialize_firewall() {
    if ! nft list chain inet "${TABLE_NAME}" "${USER_CHAIN}" &>/dev/null; then
        echo -e "${YELLOW}未检测到防火墙规则或结构已旧, 正在进行初始化...${NC}"
        nft flush ruleset
        nft add table inet ${TABLE_NAME}
        
        # --- 创建核心链 (Input, Output, Forward) ---
        nft add chain inet ${TABLE_NAME} ${INPUT_CHAIN} '{ type filter hook input priority filter; policy drop; }'
        nft add chain inet ${TABLE_NAME} ${OUTPUT_CHAIN} '{ type filter hook output priority filter; policy accept; }'
        nft add chain inet ${TABLE_NAME} ${FORWARD_CHAIN} '{ type filter hook forward priority filter; policy accept; }'

        # --- 创建用户自定义链 (主机入站) ---
        nft add chain inet ${TABLE_NAME} ${USER_CHAIN}
        nft add chain inet ${TABLE_NAME} ${USER_IP_WHITELIST}
        nft add chain inet ${TABLE_NAME} ${USER_IP_BLACKLIST}
        nft add chain inet ${TABLE_NAME} ${USER_PORT_BLOCK}
        nft add chain inet ${TABLE_NAME} ${USER_PORT_ALLOW}
        
        # --- 创建用户自定义链 (主机出站) ---
        nft add chain inet ${TABLE_NAME} ${USER_OUT_IP_BLOCK}
        nft add chain inet ${TABLE_NAME} ${USER_OUT_PORT_BLOCK}
        
        # --- 创建Docker过滤专用链 ---
        nft add chain inet ${TABLE_NAME} ${DOCKER_CHAIN}
        nft add chain inet ${TABLE_NAME} ${DOCKER_IP_WHITELIST}
        nft add chain inet ${TABLE_NAME} ${DOCKER_IP_BLACKLIST}
        nft add chain inet ${TABLE_NAME} ${DOCKER_PORT_ALLOW}
        nft add chain inet ${TABLE_NAME} ${DOCKER_PORT_DENY}

        # --- 配置核心INPUT链规则 ---
        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} ct state established,related accept comment "\"核心:允许已建立的连接\""
        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} iifname lo accept comment "\"核心:允许本地回环接口\""
        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} ip6 nexthdr icmpv6 accept comment "\"核心:允许核心ICMPv6功能\""
        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} ip protocol icmp icmp type echo-request accept comment "\"Allow IPv4 Ping\""
        
        # 动态获取并允许SSH端口
        local ssh_ports_to_add=$(ss -tlpn "sport = :*" 2>/dev/null | grep 'sshd' | grep -oE ':[0-9]+' | sed 's/://g' | sort -u | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$ssh_ports_to_add" ]]; then
            if [[ "$ssh_ports_to_add" == *,* ]]; then
                nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} tcp dport "{ ${ssh_ports_to_add} }" accept comment "\"核心:允许SSH\""
            else
                nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} tcp dport "$ssh_ports_to_add" accept comment "\"核心:允许SSH\""
            fi
        else
            nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} tcp dport 22 accept comment "\"核心:允许SSH(备用)\""
        fi

        # --- 配置链跳转逻辑 ---
        # INPUT 流量跳转到用户规则
        nft add rule inet ${TABLE_NAME} ${INPUT_CHAIN} jump ${USER_CHAIN} comment "\"跳转到用户入站规则主链\""
        
        # OUTPUT 流量跳转到出站规则
        nft add rule inet ${TABLE_NAME} ${OUTPUT_CHAIN} jump ${USER_OUT_IP_BLOCK} comment "\"跳转到用户出站IP黑名单\""
        nft add rule inet ${TABLE_NAME} ${OUTPUT_CHAIN} jump ${USER_OUT_PORT_BLOCK} comment "\"跳转到用户出站端口封锁\""
        
        # FORWARD 流量 (Docker) 跳转到Docker过滤链
        local docker_interfaces=$(ip -o link show type bridge | awk -F': ' '/docker|br-/ {print $2}' | cut -d'@' -f1 | tr '\n' ' ' | sed 's/ $//')
        if [[ -n "$docker_interfaces" ]]; then
            echo -e "${CYAN}检测到Docker网络接口: ${docker_interfaces}, 正在自动添加转发过滤规则...${NC}"
            nft add rule inet ${TABLE_NAME} ${FORWARD_CHAIN} oifname { $(echo ${docker_interfaces} | tr ' ' ',') } jump ${DOCKER_CHAIN} comment "\"跳转到Docker过滤链\""
            nft add rule inet ${TABLE_NAME} ${FORWARD_CHAIN} iifname { $(echo ${docker_interfaces} | tr ' ' ',') } jump ${USER_OUT_IP_BLOCK} comment "\"跳转到主机出站IP封锁链(Docker共用)\""
            nft add rule inet ${TABLE_NAME} ${FORWARD_CHAIN} iifname { $(echo ${docker_interfaces} | tr ' ' ',') } jump ${USER_OUT_PORT_BLOCK} comment "\"跳转到主机出站端口封锁链(Docker共用\""
            nft add rule inet ${TABLE_NAME} ${FORWARD_CHAIN} iifname { $(echo ${docker_interfaces} | tr ' ' ',') } accept comment "\"默认允许容器出站(未被阻止的)\""
        fi

        # --- 配置用户规则链内部优先级 ---
        nft add rule inet ${TABLE_NAME} ${USER_CHAIN} jump ${USER_IP_WHITELIST} comment "\"优先级1:IP白名单\""
        nft add rule inet ${TABLE_NAME} ${USER_CHAIN} jump ${USER_IP_BLACKLIST} comment "\"优先级2:IP黑名单\""
        nft add rule inet ${TABLE_NAME} ${USER_CHAIN} jump ${USER_PORT_ALLOW} comment "\"优先级4:端口放行\""
        nft add rule inet ${TABLE_NAME} ${USER_CHAIN} jump ${USER_PORT_BLOCK} comment "\"优先级3:端口封锁\""
        
        # --- 配置Docker过滤链内部优先级 ---
        nft add rule inet ${TABLE_NAME} ${DOCKER_CHAIN} jump ${DOCKER_IP_WHITELIST} comment "\"Docker优先级1:IP白名单\""
        nft add rule inet ${TABLE_NAME} ${DOCKER_CHAIN} jump ${DOCKER_IP_BLACKLIST} comment "\"Docker优先级2:IP黑名单\""
        nft add rule inet ${TABLE_NAME} ${DOCKER_CHAIN} jump ${DOCKER_PORT_ALLOW} comment "\"Docker优先级4:端口允许\""
        nft add rule inet ${TABLE_NAME} ${DOCKER_CHAIN} jump ${DOCKER_PORT_DENY} comment "\"Docker优先级3:端口拒绝\""
        
        echo -e "${GREEN}防火墙已初始化为全新的多链安全架构 (已包含Docker支持)。${NC}"
        nft list ruleset > ${NFT_CONF_PATH}
        
        if ! systemctl is-enabled nftables.service &>/dev/null; then
            echo -e "\n${YELLOW}--> 检测到 nftables 服务未设置开机自启, 正在为您自动设置...${NC}"
            if systemctl enable nftables.service &>/dev/null; then
                echo -e "${GREEN}  -> 设置成功! 防火墙规则将在系统重启后自动加载。${NC}"
            else
                echo -e "${RED}  -> 错误: 设置开机自启失败。您可能需要手动执行 'systemctl enable nftables.service'。${NC}"
            fi
        else
            echo -e "\n${GREEN}--> nftables 服务已设置为开机自启, 无需操作。${NC}"
        fi
        sleep 2
    fi
    mkdir -p "${COUNTRY_IP_DIR}" "${CUSTOM_IP_DIR}"
}

# --- [新] Docker 网络管理模块的独立函数 ---
add_docker_rule_ip_based() {
    local action=$1
    local title=$2
    local target_chain=$3
    local rule_ip_prop="saddr"
    local ip_input=""; local is_set=false; local final_status=0
    local ip_type=""; local rule_type=""
    if [[ "$action" == "accept" ]]; then rule_type="add_allow"; else rule_type="add_block"; fi
    
    clear; echo -e "${BLUE}--- ${title} ---${NC}\n"
    echo -e "${CYAN}请选择操作对象:${NC}"
    echo " 1) 手动输入IP/网段 (默认)"
    echo " 2) 从已有的IP集中选择"
    local choice_obj; read -p "#? (默认: 1): " choice_obj; choice_obj=${choice_obj:-1}
    
    local prompt="请输入源IP地址或网段 ('q'返回): "
    if [[ "$choice_obj" == "2" ]]; then
        ip_input=$(select_from_ipset)
        if [ $? -ne 0 ]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi
        is_set=true
        if [[ "$ip_input" == *_v6 ]] || [[ "$ip_input" == *_V6 ]]; then ip_type="ipv6"; else ip_type="ipv4"; fi
    else
        while true; do
            read -p "$prompt" ip_input
            if [[ $ip_input =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi
            ip_type=$(validate_ip_or_cidr "$ip_input")
            if [[ "$ip_type" != "invalid" ]]; then break; else echo -e "${RED}IP地址格式错误。${NC}"; fi
        done
    fi
    
    read -p "请输入备注 (可选, 'q'取消): " comment
    if [[ $comment =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi
    
    local base_cmd=("nft" "insert" "rule" "inet" "${TABLE_NAME}" "${target_chain}")
    local entity_desc="${title} ${ip_input}"
    
    local cmd_args=("${base_cmd[@]}"); local ip_prefix="ip"
    if [[ "$ip_type" == "ipv6" ]]; then ip_prefix="ip6"; fi
    
    if $is_set; then cmd_args+=("$ip_prefix" "$rule_ip_prop" "@$ip_input"); else cmd_args+=("$ip_prefix" "$rule_ip_prop" "$ip_input"); fi
    
    local rule_comment="${comment:-Rule_for_${ip_input}_Docker}"
    cmd_args+=("$action" "comment" "\"$rule_comment\"")
    echo -e "\n${YELLOW}执行: ${cmd_args[*]}${NC}"
    "${cmd_args[@]}"; final_status=$?
    
    apply_and_save_changes $final_status "$entity_desc" "true" "$rule_type"
}

# [新版本] add_docker_rule_port_based (功能补全)
add_docker_rule_port_based() {
    local action=$1
    local title=$2
    local target_chain=$3
    local final_status=0
    local ip_input="" ip_type="" is_set=false
    local rule_type=""
    if [[ "$action" == "accept" ]]; then rule_type="add_allow"; else rule_type="add_block"; fi
    
    clear; echo -e "${BLUE}--- ${title} ---${NC}\n"
    while true; do
        echo -e "${CYAN}支持格式 - 单个:80, 多个:80,443, 范围:1000-2000${NC}"
        read -p "请输入要操作的端口 (输入 'q' 返回): " port_input
        if [[ $port_input =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi
        formatted_ports=$(validate_and_format_ports "$port_input")
        if [[ $? -eq 0 && -n "$formatted_ports" ]]; then break; else echo -e "${RED}输入无效或为空。${NC}"; fi
    done

    # --- 新增的IP选择逻辑 ---
    echo -e "\n${CYAN}请选择此规则的IP来源:${NC}"
    echo " 1) 所有IP (默认)"
    echo " 2) 指定单个IP/网段"
    echo " 3) 从已有的IP集中选择"
    local choice_ip_source; read -p "#? (默认: 1): " choice_ip_source; choice_ip_source=${choice_ip_source:-1}
    case $choice_ip_source in
        2) 
            local prompt="请输入来源IP地址或网段 ('q'返回): "
            while true; do
                read -p "$prompt" ip_input
                if [[ $ip_input =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi
                ip_type=$(validate_ip_or_cidr "$ip_input")
                if [[ "$ip_type" != "invalid" ]]; then break; else echo -e "${RED}IP地址格式错误。${NC}"; fi
            done
            ;;
        3) 
            ip_input=$(select_from_ipset)
            if [ $? -ne 0 ]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi
            is_set=true
            if [[ "$ip_input" == *_v6 ]] || [[ "$ip_input" == *_V6 ]]; then ip_type="ipv6"; else ip_type="ipv4"; fi
            ;;
        *) 
            ip_input=""
            ;;
    esac
    # --- IP选择逻辑结束 ---

    while true; do
        echo -e "\n${CYAN}请选择协议:${NC}"
        echo -e " 1) All (TCP+UDP) (默认)"
        echo -e " 2) TCP"
        echo -e " 3) UDP"
        echo -e " q) 返回"
        read -p "#? (默认: 1. All): " choice; choice=${choice:-1}
        case $choice in
            1) protocols_to_add=("tcp" "udp"); protocol_desc="TCP+UDP"; break;;
            2) protocols_to_add=("tcp"); protocol_desc="TCP"; break;;
            3) protocols_to_add=("udp"); protocol_desc="UDP"; break;;
            [qQ]) echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return;;
            *) echo -e "${RED}无效选择。${NC}";;
        esac
    done
    
    read -p "请输入备注 (可选, 'q'取消): " comment
    if [[ $comment =~ ^[qQ]$ ]]; then echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; return; fi
    
    local command_verb; if [[ "$action" == "accept" ]]; then command_verb="add"; else command_verb="insert"; fi
    local entity_desc="${title} 端口:${port_input}"
    if [[ -n "$ip_input" ]]; then entity_desc+=" (IP来源:${ip_input})"; fi
    entity_desc+=" [协议: ${protocol_desc}]"
    
    for proto in "${protocols_to_add[@]}"; do
        local full_comment="${comment:-${action^}_Port_$(echo "$port_input" | sed 's/,/_/g')}_${proto}_Docker}"
        local base_cmd_args=("nft" "${command_verb}" "rule" "inet" "${TABLE_NAME}" "${target_chain}")
        
        # --- 新增的命令构建逻辑 ---
        if [[ -n "$ip_input" ]]; then
            local ip_prop="saddr"
            local ip_prefix="ip"
            if [[ "$ip_type" == "ipv6" ]]; then ip_prefix="ip6"; fi
            base_cmd_args+=("$ip_prefix" "$ip_prop")
            if $is_set; then
                base_cmd_args+=("@$ip_input")
            else
                base_cmd_args+=("$ip_input")
            fi
        fi
        # --- 命令构建逻辑结束 ---

        base_cmd_args+=("$proto" "dport" "$formatted_ports" "$action" "comment" "\"$full_comment\"")
        
        echo -e "\n${YELLOW}执行命令: ${base_cmd_args[*]}${NC}"
        "${base_cmd_args[@]}"
        if [ $? -ne 0 ]; then final_status=1; fi
    done
    
    apply_and_save_changes $final_status "$entity_desc" "true" "$rule_type" "$port_input"
}

get_docker_sync_status() {
    if nft list chain inet ${TABLE_NAME} ${DOCKER_CHAIN} 2>/dev/null | grep -q "SYNC: JUMP TO HOST"; then
        echo -e "${GREEN}(当前: 同步中)${NC}"
    else
        echo -e "${RED}(当前: 未同步)${NC}"
    fi
}

# [请用此代码块完整替换旧的 toggle_docker_sync 函数]
toggle_docker_sync() {
    clear
    local status_text=$(get_docker_sync_status)
    echo -e "${BLUE}--- 同步主防火墙规则到Docker过滤链 ---${NC}\n"
    echo -e "当前状态: ${status_text}\n"
    
    if [[ "$status_text" == *同步中* ]]; then
        echo -e "${YELLOW}您确定要取消将主防火墙规则同步到Docker吗?${NC}"
        echo -e "取消后，只有在Docker防火墙中单独添加的规则会生效。"
        read -p "确认取消同步吗? (y/N): " confirm
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            local handles=$(nft --handle list chain inet ${TABLE_NAME} ${DOCKER_CHAIN} | grep "SYNC: JUMP TO HOST" | awk '{print $NF}')
            if [[ -z "$handles" ]]; then
                echo -e "${YELLOW}未找到可取消的同步规则。可能已被手动删除。${NC}"; press_any_key; return
            fi
            # 从后往前删除，避免handle变化导致错误
            for handle in $(echo "$handles" | sort -nr); do
                nft delete rule inet ${TABLE_NAME} ${DOCKER_CHAIN} handle $handle
            done
            apply_and_save_changes $? "取消Docker与主规则同步"
        else
            echo -e "${GREEN}操作已取消。${NC}"; press_any_key
        fi
    else
        echo -e "${YELLOW}您确定要将主防火墙的以下规则同步应用到Docker吗?${NC}"
        echo -e "  - IP白名单 (${USER_IP_WHITELIST})"
        echo -e "  - IP黑名单 (${USER_IP_BLACKLIST})"
        echo -e "  - 端口封锁 (${USER_PORT_BLOCK})"
        echo -e "  - 端口放行 (${USER_PORT_ALLOW})"
        echo -e "\n这将使您对主机的访问控制策略同样对Docker容器生效。"
        read -p "确认启用同步吗? (y/N): " confirm
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            local final_status=0
            
            # 插入第一条规则到DOCKER_CHAIN链的顶部
            nft insert rule inet ${TABLE_NAME} ${DOCKER_CHAIN} jump ${USER_IP_WHITELIST} comment "\"SYNC: JUMP TO HOST WHITELIST\"" || final_status=1
            
            local last_handle=$(nft --handle list chain inet ${TABLE_NAME} ${DOCKER_CHAIN} | grep "SYNC: JUMP TO HOST WHITELIST" | head -n 1 | awk '{print $NF}')
            if [[ -n "$last_handle" ]]; then
                nft add rule inet ${TABLE_NAME} ${DOCKER_CHAIN} handle ${last_handle} jump ${USER_IP_BLACKLIST} comment "\"SYNC: JUMP TO HOST BLACKLIST\"" || final_status=1
            else
                echo -e "${RED}错误：无法定位上一条规则(WHITELIST)，中止操作。${NC}"; final_status=1
            fi

            ###【修复】交换了下面两条规则的顺序，确保 ALLOW 在 BLOCK 之前 ###
            if [[ "$final_status" -eq 0 ]]; then
                last_handle=$(nft --handle list chain inet ${TABLE_NAME} ${DOCKER_CHAIN} | grep "SYNC: JUMP TO HOST BLACKLIST" | head -n 1 | awk '{print $NF}')
                if [[ -n "$last_handle" ]]; then
                    # 先添加 ALLOW
                    nft add rule inet ${TABLE_NAME} ${DOCKER_CHAIN} handle ${last_handle} jump ${USER_PORT_ALLOW} comment "\"SYNC: JUMP TO HOST PORT ALLOW\"" || final_status=1
                else
                    echo -e "${RED}错误：无法定位上一条规则(BLACKLIST)，中止操作。${NC}"; final_status=1
                fi
            fi

            if [[ "$final_status" -eq 0 ]]; then
                last_handle=$(nft --handle list chain inet ${TABLE_NAME} ${DOCKER_CHAIN} | grep "SYNC: JUMP TO HOST PORT ALLOW" | head -n 1 | awk '{print $NF}')
                if [[ -n "$last_handle" ]]; then
                    # 最后添加 BLOCK
                    nft add rule inet ${TABLE_NAME} ${DOCKER_CHAIN} handle ${last_handle} jump ${USER_PORT_BLOCK} comment "\"SYNC: JUMP TO HOST PORT BLOCK\"" || final_status=1
                else
                    echo -e "${RED}错误：无法定位上一条规则(PORT ALLOW)，中止操作。${NC}"; final_status=1
                fi
            fi

            apply_and_save_changes $final_status "启用Docker与主规则同步"
        else
            echo -e "${GREEN}操作已取消。${NC}"; press_any_key
        fi
    fi
}

# [新版本] edit_delete_docker_rule_visual (功能完整)
edit_delete_docker_rule_visual() {
    local docker_chains=("${DOCKER_IP_WHITELIST}" "${DOCKER_IP_BLACKLIST}" "${DOCKER_PORT_DENY}" "${DOCKER_PORT_ALLOW}")
    
    while true; do
        clear
        echo -e "${BLUE}--- 删除/排序/编辑 Docker 独立规则 ---${NC}\n"
        local i=1
        all_rules_text=(); all_rules_handle=(); all_rules_chain=()
        all_rules_action=(); all_rules_ports=()
        declare -A chain_indices

        echo -e "${CYAN}当前可操作的所有 Docker 独立规则:${NC}"
        for chain_name in "${docker_chains[@]}"; do
            if ! nft list chain inet ${TABLE_NAME} "${chain_name}" &>/dev/null; then continue; fi
            local all_lines_in_chain=()
            mapfile -t all_lines_in_chain < <(nft --handle list chain inet ${TABLE_NAME} "${chain_name}")
            
            local rules_in_chain=()
            for line in "${all_lines_in_chain[@]}"; do
                if ! [[ "$line" =~ ^[[:space:]]*chain ]]; then rules_in_chain+=("$line"); fi
            done
            
            if [ ${#rules_in_chain[@]} -eq 0 ]; then continue; fi

            echo -e "${PURPLE}--- Chain: ${chain_name} (规则 #${i} 到 #$((i + ${#rules_in_chain[@]} - 1))) ---${NC}"
            chain_indices[$chain_name, "start"]=$i
            
            for rule in "${rules_in_chain[@]}"; do
                local handle=$(echo "$rule" | awk '/handle/ {print $NF}')
                if [[ -n "$handle" ]]; then
                    echo -e "${GREEN}[$i]${NC} $rule"
                    all_rules_text+=("$rule"); all_rules_handle+=("$handle"); all_rules_chain+=("$chain_name")
                    ((i++))
                fi
            done
            chain_indices[$chain_name, "end"]=$((i-1))
        done

        if [ ${#all_rules_handle[@]} -eq 0 ]; then
            echo -e "\n${YELLOW}没有独立的 Docker 规则可供操作。${NC}"; press_any_key; break
        fi

        echo -e "\n${CYAN}操作提示: 'd <编号>'(删除), 'm <编号>'(移动), 'da'(全删), 'q'(返回).${NC}"
        read -p "请输入您的操作和编号: " action_input
        if [[ $action_input =~ ^[qQ]$ ]]; then break; fi
        local action=$(echo "$action_input" | awk '{print tolower($1)}')
        local choices_str=$(echo "$action_input" | cut -d' ' -f2-)
        
        case "$action" in
            da|deleteall)
                read -p "警告: 您确定要删除所有 ${#all_rules_handle[@]} 条Docker独立规则吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    for chain_name in "${docker_chains[@]}"; do nft flush chain inet "${TABLE_NAME}" "$chain_name"; done
                    apply_and_save_changes 0 "删除所有Docker独立规则" false "del_allow" "all"
                    echo -e "${GREEN}所有规则已删除, 正在刷新...${NC}"; sleep 1
                else
                    echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1
                fi
                continue
                ;;
            d|delete)
                read -ra choices <<< "$choices_str"
                if [ ${#choices[@]} -eq 0 ]; then echo -e "\n${RED}输入为空或未提供编号。${NC}"; sleep 1; continue; fi
                local valid_choices=true
                for choice in "${choices[@]}"; do
                    if ! [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#all_rules_handle[@]} ]]; then
                        echo -e "\n${RED}输入错误: '$choice' 不是一个有效的编号。${NC}"; sleep 2; valid_choices=false; break
                    fi
                done
                if ! $valid_choices; then continue; fi
                local sorted_choices=($(for i in "${choices[@]}"; do echo "$i"; done | sort -nur))
                local final_success=0; local deleted_count=0
                for choice in "${sorted_choices[@]}"; do
                    local index=$((choice-1))
                    local handle_to_delete=${all_rules_handle[$index]}
                    local chain_to_delete_from=${all_rules_chain[$index]}
                    nft delete rule inet "${TABLE_NAME}" "${chain_to_delete_from}" handle "${handle_to_delete}"
                    if [ $? -eq 0 ]; then ((deleted_count++)); else final_success=1; fi
                done
                apply_and_save_changes $final_success "删除 ${deleted_count} 条Docker规则" false
                echo -e "${GREEN}操作完成, 正在刷新列表...${NC}"; sleep 1
                ;;
            m|move)
                read -ra choices <<< "$choices_str"
                if [ ${#choices[@]} -ne 1 ]; then
                    echo -e "\n${RED}错误: '移动' 操作只需一个参数: 'm <要移动的规则编号>'。${NC}"; sleep 2; continue
                fi
                local source_choice=${choices[0]}
                if ! [[ "$source_choice" =~ ^[0-9]+$ && "$source_choice" -ge 1 && "$source_choice" -le ${#all_rules_handle[@]} ]]; then
                    echo -e "\n${RED}输入错误: '$source_choice' 不是一个有效的编号。${NC}"; sleep 2; continue
                fi
                
                local source_index=$((source_choice-1))
                local source_chain=${all_rules_chain[$source_index]}
                local chain_start_idx=${chain_indices[$source_chain, "start"]}
                local chain_end_idx=${chain_indices[$source_chain, "end"]}

                clear
                echo -e "${BLUE}--- 移动Docker规则 #${source_choice} ---${NC}"
                echo -e "${YELLOW}当前规则:${NC} ${all_rules_text[$source_index]}"
                echo -e "${CYAN}所在链:${NC} ${source_chain} (范围: #${chain_start_idx} - #${chain_end_idx})\n"
                
                echo -e "${PURPLE}--- 请选择移动方式 ---${NC}"
                if [[ "$source_choice" -ne "$chain_start_idx" ]]; then echo -e " ${GREEN}t${NC}   - 置顶"; echo -e " ${GREEN}u${NC}   - 上移一位"; fi
                if [[ "$source_choice" -ne "$chain_end_idx" ]]; then echo -e " ${GREEN}b${NC}   - 置底"; echo -e " ${GREEN}d${NC}   - 下移一位"; fi
                echo -e " ${GREEN}bp <编号>${NC} - 移至规则 <编号> 之前"; echo -e " ${GREEN}ap <编号>${NC} - 移至规则 <编号> 之后";
                echo -e "\n ${GREEN}q${NC} - 取消移动"; echo -e "${PURPLE}----------------------${NC}"
                read -p "请输入移动指令: " move_cmd_input
                if [[ $move_cmd_input =~ ^[qQ]$ ]]; then continue; fi

                local move_action=$(echo "$move_cmd_input" | awk '{print tolower($1)}')
                local dest_choice=$(echo "$move_cmd_input" | awk '{print $2}')
                local source_handle=${all_rules_handle[$source_index]}
                local rule_body=$(echo "${all_rules_text[$source_index]}" | sed 's/ handle [0-9]*$//')
                local final_status=-1; local op_desc=""

                # 使用修正后的移动逻辑
                case "$move_action" in
                    t|top)
                        if [[ "$source_choice" -ne "$chain_start_idx" ]]; then
                            local first_handle_in_chain=$(nft --handle list chain inet "${TABLE_NAME}" "${source_chain}" | awk '!/chain/ && /handle/ {print $NF; exit}')
                            nft insert rule inet "${TABLE_NAME}" "${source_chain}" handle "${first_handle_in_chain}" ${rule_body} && final_status=0
                            op_desc="置顶Docker规则 #${source_choice}"
                        fi
                        ;;
                    b|bottom)
                        if [[ "$source_choice" -ne "$chain_end_idx" ]]; then
                            nft add rule inet "${TABLE_NAME}" "${source_chain}" ${rule_body} && final_status=0
                            op_desc="置底Docker规则 #${source_choice}"
                        fi
                        ;;
                    u|up)
                        if [[ "$source_choice" -ne "$chain_start_idx" ]]; then
                            local target_handle=${all_rules_handle[$((source_index-1))]}
                            nft insert rule inet "${TABLE_NAME}" "${source_chain}" handle "${target_handle}" ${rule_body} && final_status=0
                            op_desc="上移Docker规则 #${source_choice}"
                        fi
                        ;;
                    d|down)
                        if [[ "$source_choice" -ne "$chain_end_idx" ]]; then
                            local target_handle=${all_rules_handle[$((source_index+1))]}
                            nft add rule inet "${TABLE_NAME}" "${source_chain}" handle "${target_handle}" ${rule_body} && final_status=0
                            op_desc="下移Docker规则 #${source_choice}"
                        fi
                        ;;
                    bp|before|ap|after)
                        if ! [[ "$dest_choice" =~ ^[0-9]+$ && "$dest_choice" -ge "$chain_start_idx" && "$dest_choice" -le "$chain_end_idx" ]]; then
                             echo -e "\n${RED}目标编号 #${dest_choice} 无效或不在同一链内。${NC}"; sleep 2; continue
                        fi
                        if [[ "$source_choice" -eq "$dest_choice" ]]; then continue; fi
                        local dest_index=$((dest_choice-1))
                        local dest_handle=${all_rules_handle[$dest_index]}
                        if [[ "$move_action" == "bp" || "$move_action" == "before" ]]; then
                            nft insert rule inet "${TABLE_NAME}" "${source_chain}" handle ${dest_handle} ${rule_body} && final_status=0
                            op_desc="移动Docker规则 #${source_choice} -> #${dest_choice} 之前"
                        elif [[ "$move_action" == "ap" || "$move_action" == "after" ]]; then
                            nft add rule inet "${TABLE_NAME}" "${source_chain}" handle ${dest_handle} ${rule_body} && final_status=0
                            op_desc="移动Docker规则 #${source_choice} -> #${dest_choice} 之后"
                        fi
                        ;;
                     *) echo -e "\n${RED}无效的移动指令。${NC}"; sleep 1; continue ;;
                esac

                if [[ "$final_status" -eq 0 ]]; then
                    nft delete rule inet "${TABLE_NAME}" "${source_chain}" handle "${source_handle}"
                    if [ $? -ne 0 ]; then final_status=1; fi
                    apply_and_save_changes $final_status "$op_desc" false
                elif [[ "$final_status" -eq 1 ]]; then echo -e "${RED}操作失败。${NC}"; fi
                echo -e "${GREEN}操作完成, 正在刷新列表...${NC}"; sleep 1
                ;;
            *)
                echo -e "\n${RED}无效操作。${NC}"; sleep 2
                ;;
        esac
    done
}

docker_network_manager_menu() {
    while true; do
        clear
        local sync_status=$(get_docker_sync_status)
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "                              ${CYAN}Docker 网络管理中心 (v1.2 Arch)${NC}"
        echo -e "${PURPLE}======================================================${NC}"
        echo -e "${YELLOW}在这里添加的规则将只对转发到Docker容器的流量生效。${NC}"
        echo -e " ${GREEN}1.${NC} 同步主防火墙规则 ${sync_status}"
        echo -e " ${GREEN}2.${NC} 添加Docker白名单IP (Whitelist)"
        echo -e " ${GREEN}3.${NC} 添加Docker黑名单IP (Blacklist)"
        echo -e " ${GREEN}4.${NC} 添加Docker允许访问的端口 (Port Allow)"
        echo -e " ${GREEN}5.${NC} 添加Docker拒绝访问的端口 (Port Deny)"
        echo -e " ${GREEN}6.${NC} ${RED}查看/删除 Docker独立规则${NC}"
        echo -e "\n ${GREEN}q.${NC} 返回主菜单"
        echo -e "${PURPLE}------------------------------------------------------${NC}"
        read -p "请输入您的选项: " choice
        case $choice in
            1) toggle_docker_sync ;;
            2) add_docker_rule_ip_based "accept" "Docker IP 白名单" "${DOCKER_IP_WHITELIST}" ;;
            3) add_docker_rule_ip_based "drop" "Docker IP 黑名单" "${DOCKER_IP_BLACKLIST}" ;;
            4) add_docker_rule_port_based "accept" "Docker 端口放行" "${DOCKER_PORT_ALLOW}" ;;
            5) add_docker_rule_port_based "drop" "Docker 端口拒绝" "${DOCKER_PORT_DENY}" ;;
            6) edit_delete_docker_rule_visual ;;
            q|Q) break ;;
            *) echo -e "\n${RED}无效选项。${NC}"; sleep 1 ;;
        esac
    done
}

# =================================================================
#
# ### 结束: Docker v1.2 模块代码 ###
#
# =================================================================

main_menu() {
    local policy_input=$(nft list chain inet ${TABLE_NAME} ${INPUT_CHAIN} 2>/dev/null | grep -o 'policy \w*' | awk '{print $2}')
    local policy_output=$(nft list chain inet ${TABLE_NAME} ${OUTPUT_CHAIN} 2>/dev/null | grep -o 'policy \w*' | awk '{print $2}')
    
    local forward_status="${RED}已关闭${NC}"
    if [[ -f /proc/sys/net/ipv4/ip_forward && $(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]]; then
        forward_status="${GREEN}已开启${NC}"
    fi

    local autostart_status
    if systemctl is-enabled nftables.service &>/dev/null; then
        autostart_status="${GREEN}已自启${NC}"
    else
        autostart_status="${RED}未自启${NC}"
    fi
    
    local ipv4_ping_status; local ipv4_ping_status_text
    if [[ "$policy_input" == "drop" ]]; then
        if nft list ruleset | grep -q 'comment "Allow IPv4 Ping"'; then
            ipv4_ping_status="${GREEN}已放行${NC}"; ipv4_ping_status_text="${GREEN}允许${NC}"
        else
            ipv4_ping_status="${RED}已阻断${NC}"; ipv4_ping_status_text="${RED}阻断${NC}"
        fi
    else 
        if nft list ruleset | grep -q 'comment "Block IPv4 Ping (Policy-Accept-Mode)"'; then
            ipv4_ping_status="${RED}已阻断${NC}"; ipv4_ping_status_text="${RED}阻断${NC}"
        else
            ipv4_ping_status="${GREEN}已放行${NC}"; ipv4_ping_status_text="${GREEN}允许${NC}"
        fi
    fi

    local ssh_port_info
    ssh_port_info=$(ss -tlpn 2>/dev/null | grep 'sshd' | grep -E '(\*|0\.0\.0\.0|\[::\]):[0-9]+' | grep -oE ':[0-9]+' | sed 's/://g' | sort -u | tr '\n' ',' | sed 's/,$//')
    if [[ -z "$ssh_port_info" ]]; then ssh_port_info="${YELLOW}未知${NC}"; else ssh_port_info="${GREEN}${ssh_port_info}${NC}"; fi

    local policy_input_color; local policy_menu_status
    if [[ "$policy_input" == "drop" ]]; then
        policy_input_color="${YELLOW}"; policy_menu_status="(当前: ${GREEN}drop${NC})"
    else
        policy_input_color="${RED}"; policy_menu_status="(当前: ${RED}accept(危险)${NC})"
    fi
    
    local shortcut_status_text="(状态: ${RED}未安装${NC})"
    if [ -L "/usr/local/bin/${SHORTCUT_NAME}" ] && [ "$(readlink "/usr/local/bin/${SHORTCUT_NAME}")" = "$(realpath "$0")" ]; then
        shortcut_status_text="(状态: ${GREEN}已安装${NC})"
    fi
    
    local f2b_status_text
    if command -v fail2ban-client &>/dev/null; then
        if systemctl is-active --quiet fail2ban; then f2b_status_text="(状态: ${GREEN}运行中${NC})"; else f2b_status_text="(状态: ${YELLOW}已停止${NC})"; fi
    else
        f2b_status_text="(状态: ${RED}未安装${NC})"
    fi
    local policy_forward=$(nft list chain inet ${TABLE_NAME} ${FORWARD_CHAIN} 2>/dev/null | grep -o 'policy \w*' | awk '{print $2}')
    local policy_forward_color;
    if [[ "$policy_forward" == "drop" ]]; then policy_forward_color="${RED}"; else policy_forward_color="${GREEN}"; fi

    clear
    echo -e "${PURPLE}======================================================${NC}"
    echo -e "         ${CYAN}NFTables 防火墙管理器 (By cnyun.de v 1.0)${NC}"
    echo -e "${PURPLE}--------------------[ 系统状态 ]----------------------${NC}"
    echo -e " 入站策略: ${policy_input_color}${policy_input}${NC}  | 出站策略: ${YELLOW}${policy_output}${NC}  | 内核转发: ${forward_status}"
    echo -e " 开机自启: ${autostart_status} | Ping(IPv4): ${ipv4_ping_status} | SSH端口: ${ssh_port_info} \n FORWARD转发策略: ${policy_forward_color}${policy_forward}${NC}"
    echo -e "${PURPLE}======================================================${NC}"
    echo -e "${BLUE}--- 规则管理 (主机) ---${NC}"
    echo -e " ${GREEN}1.${NC} 新增 IP 到主机白名单"
    echo -e " ${GREEN}2.${NC} ${YELLOW}新增 IP 到主机黑名单${NC}"
    echo -e " ${GREEN}3.${NC} ${YELLOW}新增 [主机端口封禁] 规则${NC}"
    echo -e " ${GREEN}4.${NC} 新增 [主机端口放行] 规则"
    echo -e " ${GREEN}5.${NC} IP 集管理 (国家/自定义)"
    echo -e " ${GREEN}6.${NC} ${RED}查看/删除/编辑/排序 主机规则${NC}"
    echo -e "\n${BLUE}--- 转发 & 容器 ---${NC}"
    echo -e " ${GREEN}7.${NC} ${YELLOW}新增 [出站IP/端口] 封锁${NC}"
    echo -e " ${GREEN}8.${NC} ${YELLOW}轻量级端口转发 (socat)${NC}"
    echo -e " ${GREEN}9.${NC} ${CYAN}Docker 网络管理${NC}"
    echo -e "\n${BLUE}--- 系统 & 监控 & 附加功能 ---${NC}"
    echo -e " ${GREEN}10.${NC} 查看完整防火墙状态"
    echo -e " ${GREEN}11.${NC} ${YELLOW}超级网络监控 (多维度实时视图)${NC}"
    echo -e " ${GREEN}12.${NC} ${RED}重置防火墙为默认结构${NC}"
    echo -e " ${GREEN}13.${NC} 清除连接状态 (Conntrack)"
    echo -e " ${GREEN}14.${NC} 切换 IPv4 ICMP (Ping) 状态 (当前: ${ipv4_ping_status_text})"
    echo -e " ${GREEN}15.${NC} ${RED}切换默认入站策略 (Input)${NC} ${policy_menu_status}"
    echo -e " ${GREEN}16.${NC} ${RED}切换默认转发策略 (Forward)${NC} (当前: ${policy_forward_color}${policy_forward}${NC})" # <-- 新增行
    echo -e " ${GREEN}17.${NC} ${CYAN}Fail2ban与SSH综合管理${NC} ${f2b_status_text}" # <-- 编号+1
    echo -e " ${GREEN}18.${NC} ${YELLOW}备份与恢复规则${NC}" # <-- 编号+1
    echo -e " ${GREEN}19.${NC} ${YELLOW}终端快捷方式管理${NC} ${shortcut_status_text}" # <-- 编号+1
    echo -e "\n${PURPLE}------------------------------------------------------${NC}"
    echo -e " ${GREEN}q.${NC} 退出脚本"
    echo -e "${PURPLE}------------------------------------------------------${NC}"
}

initialize_firewall
while true; do
    main_menu
    read -p "请输入您的选项: " choice
    case $choice in
        1) add_rule_ip_based "in" "accept" "主机IP白名单" ;;
        2) add_rule_ip_based "in" "drop" "主机IP黑名单" ;;
        3) add_rule_port_based "in" "drop" "主机端口封锁" ;;
        4) add_rule_port_based "in" "accept" "主机端口放行" ;;
        5) ipset_manager_menu ;;
        6) edit_delete_rule_visual ;;
        7) 
            clear
            echo -e "${BLUE}--- 出站封锁菜单 ---${NC}"
            echo -e " ${GREEN}1.${NC} 按目标 IP 封锁出站流量"
            echo -e " ${GREEN}2.${NC} 按目标端口封锁出站流量"
            echo -e "\n ${GREEN}q.${NC} 返回"
            read -p "请选择封锁类型: " ob_choice
            case $ob_choice in
                1) add_rule_ip_based "out" "drop" "出站IP封锁" ;;
                2) add_rule_port_based "out" "drop" "出站端口封锁" ;;
                *) ;;
            esac
            ;;
        8) socat_manager_menu ;;
        9) docker_network_manager_menu ;; # <-- 新增的选项
        10) view_full_status ;;
        11) detailed_network_monitor_menu ;;
        12) reset_firewall ;;
        13) clear_connections ;;
        14) toggle_ipv4_ping ;;
        15) toggle_default_policy ;;
        16) toggle_forward_policy ;; # <-- 新增行
        17) fail2ban_ssh_manager_menu ;; # <-- 编号+1
        18) backup_restore_menu ;; # <-- 编号+1
        19) shortcut_manager_menu ;; # <-- 编号+1
        q|Q) echo -e "${CYAN}感谢使用，再见！${NC}"; exit 0 ;;
        *) echo -e "\n${RED}无效的选项，请重新输入。${NC}"; sleep 1 ;;
    esac
done
