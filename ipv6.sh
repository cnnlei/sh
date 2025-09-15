#!/bin/bash

# ==============================================================================
# =                        用户配置区域                                       =
# ==============================================================================
CONSTANT_SUFFIXES=(
    "9ab:b47a:d086:144f:318c:afde"
    "7a02:4bf7:77f4:33cd:695b:12fe"
    "14f:b874:8144:c0a8:4be1:582e"
    "e2ae:1b0b:39fb:49a5:12ea:1223"
    "706f:c718:316d:2dcb:4b7d:ebff"
    "13ce:6bdb:9804:eed4:597f:b8c6"
    "3cf5:f563:eddc:c267:c6cf:4321"
    "f500:5246:fb9b:52ab:e54e:38b5"
    "27db:df14:f458:22df:7b0f:362c"
    "27db:df14:f458:22df:7b0f:362c"
)
# ==============================================================================

# --- 全局变量与函数定义 ---
CONFIG_FILE="/etc/ipv6-dynamic-addrs.conf"
APPLY_SCRIPT="/usr/local/bin/apply-ipv6-addrs.sh"
SERVICE_FILE="/etc/systemd/system/apply-ipv6-addrs.service"
SUPPORTED_MASKS=(48 56 64 62 60 58)

# 终极净化函数: 移除所有不可见字符、\r、并修剪首尾空白
clean_input() {
    if command -v perl &>/dev/null; then
        perl -pe 's/[^[:print:]\t]//g; s/^\s+|\s+$//g;'
    else
        tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
    fi
}

cleanup_configuration() {
    echo "-------------------------------------"
    echo "开始执行清理操作..."
    if [ ! -f "$CONFIG_FILE" ]; then echo "未找到配置文件，无需清理。"; exit 0; fi

    local IFACE PREFIX_LEN
    IFACE=$(grep '^IFACE=' "$CONFIG_FILE" | cut -d'=' -f2)
    PREFIX_LEN=$(grep '^PREFIX_LEN=' "$CONFIG_FILE" | cut -d'=' -f2)
    mapfile -t IP_LIST < <(grep -v '=' "$CONFIG_FILE" | sed '/^\s*$/d')

    if systemctl is-active --quiet apply-ipv6-addrs.service; then
        echo "正在停止并禁用 systemd 服务..."
        systemctl disable --now apply-ipv6-addrs.service
    fi

    echo "正在从网卡移除已配置的IP地址..."
    if [ -n "$IFACE" ] && [ -n "$PREFIX_LEN" ]; then
        for ip in "${IP_LIST[@]}"; do
            if [ -n "$ip" ]; then
                echo "  - 移除 $ip"
                ip addr del "${ip}/${PREFIX_LEN}" dev "${IFACE}" 2>/dev/null
            fi
        done
    else
        echo "警告：配置文件损坏或信息不全，无法自动移除IP。"
    fi

    echo "正在删除相关文件..."
    rm -f "$SERVICE_FILE" "$APPLY_SCRIPT" "$CONFIG_FILE"
    echo "正在重新加载 systemd daemon..."
    systemctl daemon-reload
    echo "====================================="
    echo "清理完成！所有配置和IP地址均已移除。"
    echo "====================================="
    exit 0
}

generate_constant_ips() {
    local prefix_addr="$1"
    local plen="$2"
    local ips=()

    local keep
    case "$plen" in
        48) keep=3 ;;
        56|64|62|60|58) keep=4 ;;
        *) echo "错误：不支持的前缀长度 /$plen"; return 1 ;;
    esac

    IFS=':' read -r -a prefix_parts <<< "$prefix_addr"
    local prefix_base_array=("${prefix_parts[@]:0:$keep}")
    local num_suffix_parts_needed=$((8 - keep))

    for suffix in "${CONSTANT_SUFFIXES[@]}"; do
        IFS=':' read -r -a suffix_parts <<< "$suffix"
        local suffix_len=${#suffix_parts[@]}
        local start_index=$((suffix_len - num_suffix_parts_needed))
        if [ $start_index -lt 0 ]; then start_index=0; fi
        local final_suffix_array=("${suffix_parts[@]:$start_index:$num_suffix_parts_needed}")
        local new_ip_parts=("${prefix_base_array[@]}" "${final_suffix_array[@]}")
        local new_ip
        new_ip=$(IFS=':'; echo "${new_ip_parts[*]}")
        
        ips+=("$new_ip")
    done

    printf "%s\n" "${ips[@]}" | sort -u
}

run_configuration() {
    echo "正在扫描具备公网 IPv6 地址的网卡..."
    mapfile -t interfaces < <(ip -6 addr show scope global | awk '/^[0-9]+: / {iface=$2; sub(/:/,"", iface)} /inet6.*scope global/ {print iface}' | sort -u)
    if [ ${#interfaces[@]} -eq 0 ]; then echo "错误：未在本机找到任何配置了公网 IPv6 地址的网卡。"; return; fi
    
    local IFACE
    if [ ${#interfaces[@]} -eq 1 ]; then
        IFACE=${interfaces[0]}; echo "自动选择唯一网卡: $IFACE"
    else
        echo "发现多个具备公网 IPv6 的网卡，请选择一个进行操作："
        PS3="请输入数字选择网卡 (q退出): "
        select opt in "${interfaces[@]}"; do
            if [[ $REPLY =~ ^[qQ]$ ]]; then echo "已退出。"; exit 0; fi
            if [[ -n "$opt" ]]; then IFACE=$opt; echo "您选择了网卡: $IFACE"; break; else echo "无效的选择，请重试。"; fi
        done
    fi

    local FULL_IPV6_CIDR
    FULL_IPV6_CIDR=$(ip -6 addr show dev "$IFACE" scope global | grep 'inet6' | awk '{print $2}' | head -n 1)
    if [ -z "$FULL_IPV6_CIDR" ]; then echo "错误：无法从选择的网卡 '$IFACE' 获取有效的公网 IPv6 地址。脚本终止。"; return; fi
    
    local IP_ADDR PREFIX_LEN DISPLAY_PREFIX
    IP_ADDR=$(echo "$FULL_IPV6_CIDR" | cut -d'/' -f1)
    PREFIX_LEN=$(echo "$FULL_IPV6_CIDR" | cut -d'/' -f2)

    if [[ ! " ${SUPPORTED_MASKS[*]} " =~ " ${PREFIX_LEN} " ]]; then
        echo "错误：前缀长度 /$PREFIX_LEN 不受支持。"; return
    fi
    
    local keep
    case "$PREFIX_LEN" in
        48) keep=3 ;;
        *) keep=4 ;;
    esac
    
    IFS=':' read -r -a addr_parts <<< "$IP_ADDR"
    DISPLAY_PREFIX=$(printf "%s:" "${addr_parts[@]:0:$keep}")
    DISPLAY_PREFIX="${DISPLAY_PREFIX%:}"

    PS3=$'\n'"请输入配置模式 [1-2, q返回]: "
    options=("【常量】同步IP (智能覆盖)" "【随机】生成IP (添加/覆盖)")
    select opt in "${options[@]}"; do
        if [[ $REPLY =~ ^[qQ]$ ]]; then return; fi
        case $opt in
            "${options[0]}") main_choice=1; break;;
            "${options[1]}") main_choice=2; break;;
            *) echo "无效选项 $REPLY";;
        esac
    done

    echo "-------------------------------------"
    echo "使用配置: 网卡=$IFACE, 前缀=${DISPLAY_PREFIX}::/${PREFIX_LEN}"
    echo "-------------------------------------"
    
    local -a final_ips
    case $main_choice in
    1) # 常量同步
        echo "您选择了常量同步模式。"
        local -a existing_ips=()
        if [ -f "$CONFIG_FILE" ]; then
            mapfile -t existing_ips < <(grep -v '=' "$CONFIG_FILE" | sed '/^\s*$/d')
            if [ ${#existing_ips[@]} -gt 0 ]; then
                echo "检测到配置文件中有 ${#existing_ips[@]} 个本脚本管理的IP。"
            fi
        fi

        local -a newly_generated_ips
        newly_generated_ips=($(generate_constant_ips "$DISPLAY_PREFIX" "$PREFIX_LEN")) || return 1
        
        declare -A new_map
        for ip in "${newly_generated_ips[@]}"; do
            [[ -n "$ip" ]] && new_map["$ip"]=1
        done

        declare -A existing_map
        for ip in "${existing_ips[@]}"; do
            [[ -n "$ip" ]] && existing_map["$ip"]=1
        done

        local -a ips_to_add=()
        for ip in "${newly_generated_ips[@]}"; do
            if [[ -z "${existing_map[$ip]}" ]]; then
                ips_to_add+=("$ip")
            fi
        done

        local -a ips_to_remove=()
        for ip in "${existing_ips[@]}"; do
            if [[ -z "${new_map[$ip]}" ]]; then
                ips_to_remove+=("$ip")
            fi
        done

        if [ ${#ips_to_add[@]} -eq 0 ] && [ ${#ips_to_remove[@]} -eq 0 ]; then echo "配置已是最新，无需更改。"; return; fi
        
        echo "将执行以下操作："
        if [ ${#ips_to_add[@]} -gt 0 ]; then echo "  [+] 将添加以下 ${#ips_to_add[@]} 个IP:"; printf "      -> %s\n" "${ips_to_add[@]}"; fi
        if [ ${#ips_to_remove[@]} -gt 0 ]; then echo "  [-] 将移除以下 ${#ips_to_remove[@]} 个IP:"; printf "      -> %s\n" "${ips_to_remove[@]}"; fi
        
        local confirm
        read -p "确认继续吗？ [y/N]: " confirm; if [[ ! "$confirm" =~ ^[yY]$ ]]; then echo "操作已取消。"; return; fi
        
        echo "正在同步配置..."
        for ip in "${ips_to_remove[@]}"; do ip addr del "${ip}/${PREFIX_LEN}" dev "$IFACE" 2>/dev/null; done
        for ip in "${ips_to_add[@]}"; do if ! ip addr show dev "$IFACE" | grep -q "$ip"; then ip addr add "${ip}/${PREFIX_LEN}" dev "$IFACE"; fi; done
        final_ips=("${newly_generated_ips[@]}")
        ;;
    2) # 随机生成
        local -a existing_ips=()
        if [ -f "$CONFIG_FILE" ]; then
            mapfile -t existing_ips < <(grep -v '=' "$CONFIG_FILE" | sed '/^\s*$/d')
        fi
        final_ips=(); op_mode="overwrite"
        if [ ${#existing_ips[@]} -gt 0 ]; then
            local sub_choice
            read -p "您想 (A)dd [添加] 还是 (O)verwrite [覆盖]? [A/O]: " sub_choice
            if [[ "$sub_choice" =~ ^[aA]$ ]]; then op_mode="add"; final_ips=("${existing_ips[@]}"); fi
        fi
        local count
        read -p "您想生成几个随机IP地址？ " count
        if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -le 0 ]; then echo "错误：请输入一个正整数。"; return; fi
        generated_ips=()
        for ((i=0; i<count; i++)); do
            PART5=$(openssl rand -hex 2)
            PART6=$(openssl rand -hex 2)
            PART7=$(openssl rand -hex 2)
            PART8=$(openssl rand -hex 2)
            new_ip="${DISPLAY_PREFIX}:${PART5}:${PART6}:${PART7}:${PART8}"
            generated_ips+=("$new_ip")
        done
        if [ "$op_mode" == "add" ]; then final_ips+=("${generated_ips[@]}"); else final_ips=("${generated_ips[@]}"); fi
        read -p "将配置 ${#final_ips[@]} 个IP。确认继续吗？ [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[yY] ]]; then echo "操作已取消。"; return; fi
        echo "正在应用配置..."
        if [ "$op_mode" == "overwrite" ] && [ ${#existing_ips[@]} -gt 0 ]; then
            for ip in "${existing_ips[@]}"; do ip addr del "${ip}/${PREFIX_LEN}" dev "$IFACE" 2>/dev/null; done
        fi
        ips_to_add=()
        if [ "$op_mode" == "add" ]; then ips_to_add=("${generated_ips[@]}"); else ips_to_add=("${final_ips[@]}"); fi
        for ip in "${ips_to_add[@]}"; do if ! ip addr show dev "$IFACE" | grep -q "$ip"; then ip addr add "${ip}/${PREFIX_LEN}" dev "$IFACE"; fi; done
        ;;
    esac

    echo "正在更新配置文件: $CONFIG_FILE"
    { echo "IFACE=$IFACE"; echo "PREFIX_LEN=$PREFIX_LEN"; printf "%s\n" "${final_ips[@]}"; } > "$CONFIG_FILE"

    if [ ! -f "$SERVICE_FILE" ]; then
        echo "正在创建并启用开机服务..."
        cat << EOF > "$APPLY_SCRIPT"
#!/bin/bash
CONFIG_FILE="$CONFIG_FILE"
if [ -f "\$CONFIG_FILE" ]; then
    IFACE=\$(grep '^IFACE=' "\$CONFIG_FILE" | cut -d'=' -f2)
    PREFIX_LEN=\$(grep '^PREFIX_LEN=' "\$CONFIG_FILE" | cut -d'=' -f2)
    IP_LIST=\$(grep -v '=' "\$CONFIG_FILE" | sed '/^\s*$/d')
    
    if [ -n "\$IFACE" ] && [ -n "\$PREFIX_LEN" ]; then
        while ! ip link show dev "\$IFACE" | grep -q "state UP"; do sleep 1; done
        for ip in \$IP_LIST; do
            if ! ip addr show dev "\$IFACE" | grep -q "\$ip"; then
                ip addr add "\${ip}/\${PREFIX_LEN}" dev "\$IFACE"
            fi
        done
    fi
fi
EOF
        chmod +x "$APPLY_SCRIPT"

        cat << EOF > "$SERVICE_FILE"
[Unit]
Description=Apply Additional IPv6 Addresses at Startup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$APPLY_SCRIPT

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable apply-ipv6-addrs.service
    fi

    echo "====================================="
    echo "配置完成！"
    echo "====================================="
}

# --- 脚本主入口 ---
if [ "$(id -u)" -ne 0 ]; then
    echo "错误：此脚本必须以 root 权限运行。请使用 'sudo $0'"
    exit 1
fi

while true; do
    clear
    PS3=$'\n'"请选择要执行的操作 [1-2, q退出]: "
    options=("配置/管理 IPv6 地址" "【卸载】清理所有配置")
    select opt in "${options[@]}"; do
        if [[ $REPLY =~ ^[qQ]$ ]]; then echo "已退出。"; exit 0; fi
        case $opt in
            "${options[0]}") run_configuration; break;;
            "${options[1]}")
                read -p "警告：此操作将移除所有配置，不可恢复。确定吗？ [y/N]: " confirm_cleanup
                if [[ "$confirm_cleanup" =~ ^[yY]$ ]]; then
                    cleanup_configuration
                fi
                exit 0;;
            *) echo "无效选项 $REPLY";;
        esac
    done
    read -n 1 -s -r -p "按任意键返回主菜单..."
done
