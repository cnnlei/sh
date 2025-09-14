#!/bin/bash

#===================================================================================
# 脚本名称: he_tunnel_manager_the_real_final_answer.sh
# 脚本功能: (最终JSON结构修正版) 根据正确的JSON结构修改x-ui配置
#           - [终极修复] 使用正确的jq命令, 将sendThrough字段添加到与settings同级的位置
#           - ... (包含之前所有功能)
# 使用方法: sudo ./he_tunnel_manager_the_real_final_answer.sh
#===================================================================================

# --- 全局配置 ---
WORK_DIR="/he"
CONFIG_NAME="he.sh"
CONFIG_FILE_PATH="${WORK_DIR}/${CONFIG_NAME}"
INTERFACE_NAME="he-ipv6"
ROUTE_TABLE_ID="100"
LA_SERVER_IP="66.220.18.42"

# --- x-ui 联动配置 ---
XUI_DB_PATH="/etc/x-ui/x-ui.db"
XUI_SERVICE_NAME="x-ui"
XUI_OUTBOUND_TAGS=("he-ipv6" "warp")

SERVERS=(
    "66.220.18.42"    "美国, 洛杉矶 (Los Angeles, CA)"
    "216.66.80.30"    "美国, 弗里蒙特 (Fremont, CA)"
    "216.66.84.42"    "美国, 阿什本 (Ashburn, VA)"
    "64.62.200.2"     "美国, 纽约 (New York, NY)"
    "216.66.87.14"    "美国, 芝加哥 (Chicago, IL)"
    "66.220.7.82"     "美国, 迈阿密 (Miami, FL)"
    "216.66.88.98"    "美国, 达拉斯 (Dallas, TX)"
    "216.66.86.114"   "美国, 西雅图 (Seattle, WA)"
    "209.51.181.2"    "英国, 伦敦 (London, UK)"
    "195.10.195.10"   "德国, 法兰克福 (Frankfurt, DE)"
    "216.66.22.2"     "荷兰, 阿姆斯特丹 (Amsterdam, NL)"
    "216.66.38.58"    "瑞士, 苏黎世 (Zurich, CH)"
    "103.56.233.1"    "日本, 东京 (Tokyo, JP)"
    "184.105.251.94"  "中国, 香港 (Hong Kong)"
    "184.105.220.102" "新加坡 (Singapore)"
)
# --- 全局配置结束 ---


#================================================
# 函数 1: 检查并安装依赖
#================================================
check_dependencies() {
    echo "🔎 正在检查依赖..."
    local missing_deps=()
    command -v ip &> /dev/null || missing_deps+=("iproute2")
    command -v awk &> /dev/null || missing_deps+=("awk")
    command -v jq &> /dev/null || missing_deps+=("jq")
    command -v sqlite3 &> /dev/null || missing_deps+=("sqlite3")
    if [ ${#missing_deps[@]} -eq 0 ]; then echo "✔︎ 所有依赖已满足。"; return 0; fi
    echo "⚠️ 缺少依赖: ${missing_deps[*]}"
    read -p "是否尝试自动安装? (Y/n): " install_choice
    if [[ "$install_choice" =~ ^[nN]$ ]]; then echo "❌ 用户取消安装。脚本无法继续。"; return 1; fi
    echo "正在尝试安装依赖..."
    if command -v apt-get &> /dev/null; then apt-get update && apt-get install -y iproute2 gawk jq sqlite3
    elif command -v yum &> /dev/null; then yum install -y iproute2 gawk jq sqlite
    elif command -v dnf &> /dev/null; then dnf install -y iproute2 gawk jq sqlite
    else echo "❌ 无法识别的包管理器。请手动安装 ${missing_deps[*]}。"; return 1; fi
    if command -v sqlite3 &> /dev/null && command -v jq &> /dev/null; then echo "✔︎ 依赖安装成功！"; return 0; else echo "❌ 依赖安装失败。"; return 1; fi
}


#================================================
# 函数 2: 生成标准的配置文件模板
#================================================
generate_config_template() {
    cat <<EOF > "$CONFIG_FILE_PATH"
#!/bin/bash
REMOTE_IPV4="66.220.18.42"
IPV6_ROUTED_64_SEGMENT="c:fa"
IPV6_ROUTED_48_SEGMENT="f1c0"
INTERFACE_NAME="${INTERFACE_NAME}"
ROUTE_TABLE_ID="${ROUTE_TABLE_ID}"
LOCAL_IPV4=\$(ip -4 route get 8.8.8.8 | awk '{print \$7}' | head -n 1)
echo "Cleaning up old tunnel configuration..."
if ip link show \$INTERFACE_NAME &> /dev/null; then ip link set dev \$INTERFACE_NAME down; ip tunnel del \$INTERFACE_NAME; fi
ip -6 rule del from 2001:470:\${IPV6_ROUTED_64_SEGMENT}::/64 table \$ROUTE_TABLE_ID &> /dev/null
ip -6 rule del from 2001:470:\${IPV6_ROUTED_48_SEGMENT}::/48 table \$ROUTE_TABLE_ID &> /dev/null
ip -6 route flush table \$ROUTE_TABLE_ID &> /dev/null
echo "Setting up new tunnel on interface '\$INTERFACE_NAME'..."
ip tunnel add \$INTERFACE_NAME mode sit remote \${REMOTE_IPV4} local \${LOCAL_IPV4} ttl 255
ip link set dev \$INTERFACE_NAME up
ip addr add 2001:470:\${IPV6_ROUTED_64_SEGMENT}::2/64 dev \$INTERFACE_NAME
ip addr add 2001:470:\${IPV6_ROUTED_48_SEGMENT}::1/48 dev \$INTERFACE_NAME
ip link set dev \$INTERFACE_NAME mtu 1280
echo "Setting up routing rules..."
ip -6 route add default via 2001:470:\${IPV6_ROUTED_64_SEGMENT}::1 dev \$INTERFACE_NAME table \$ROUTE_TABLE_ID
ip -6 rule add from 2001:470:\${IPV6_ROUTED_64_SEGMENT}::/64 table \$ROUTE_TABLE_ID
ip -6 rule add from 2001:470:\${IPV6_ROUTED_48_SEGMENT}::/48 table \$ROUTE_TABLE_ID
echo "Configuration applied."
EOF
}


#================================================
# 函数 3: 交互式编辑给定的配置文件
#================================================
interactive_edit_tunnel() {
    local config_path="$1"; local current_64=$(grep 'IPV6_ROUTED_64_SEGMENT=' "$config_path"|cut -d'"' -f2); local current_48=$(grep 'IPV6_ROUTED_48_SEGMENT=' "$config_path"|cut -d'"' -f2); local current_ip=$(grep 'REMOTE_IPV4=' "$config_path"|cut -d'"' -f2); if [ -z "$current_64" ] || [ -z "$current_48" ] || [ -z "$current_ip" ]; then echo "❌ 错误: 无法解析 '$config_path' 文件。"; return 1; fi
    echo "=================================================="; echo "    交互式 HE.net IPv6 隧道配置更新工具"; echo "=================================================="
    local current_location="未知"; for ((i=0; i<${#SERVERS[@]}; i+=2)); do if [[ "${SERVERS[i]}" == "$current_ip" ]]; then local current_location="${SERVERS[i+1]}"; break; fi; done
    echo "正在编辑文件: $config_path"; echo "当前配置值如下:"; echo "  - /64 地址段: $current_64"; echo "  - /48 地址段: $current_48"; echo "  - 隧道服务器: $current_ip ($current_location)"; echo "--------------------------------------------------"; echo "请输入新的配置值。如果某项不想更改，可直接回车。"; echo
    read -p "➡️ 请输入新的 /64 地址段 (例如 c:fa) [$current_64]: " new_64; [ -z "$new_64" ] && new_64=$current_64
    read -p "➡️ 请输入新的 /48 地址段 (例如 f1c0) [$current_48]: " new_48; [ -z "$new_48" ] && new_48=$current_48
    local new_ip=$current_ip; local perform_ip_change=false
    if [[ "$current_ip" != "$LA_SERVER_IP" ]]; then read -p "⚠️ 当前服务器不是洛杉矶, 要更换吗? (y/N): " choice; if [[ "$choice" =~ ^[yY] ]]; then perform_ip_change=true; fi; else perform_ip_change=true; fi
    if $perform_ip_change; then
        echo; echo "--- 请从以下列表中选择新的隧道服务器 ---"; for ((i=0; i<${#SERVERS[@]}; i+=2)); do local idx=$((i/2 + 1)); printf " %2d. %-15s %s\n" "$idx" "${SERVERS[i]}" "${SERVERS[i+1]}"; done; echo "-------------------------------------------"
        local current_idx_str=""; for ((i=0; i<${#SERVERS[@]}; i+=2)); do if [[ "${SERVERS[i]}" == "$current_ip" ]]; then local current_idx_str="默认: $((i/2 + 1))"; break; fi; done
        read -p "➡️ 请输入序号 [$current_idx_str]: " new_idx
        if [[ "$new_idx" =~ ^[0-9]+$ ]] && [ "$new_idx" -ge 1 ] && [ "$new_idx" -le $((${#SERVERS[@]}/2)) ]; then new_ip=${SERVERS[($new_idx-1)*2]}; else echo "ℹ️ 输入无效或为空, 保持当前IP不变。"; fi
    fi
    echo "--------------------------------------------------"; echo "最终配置如下:"; echo "  - 新 /64 段: $new_64"; echo "  - 新 /48 段: $new_48"; echo "  - 新服务器IP: $new_ip"; echo "--------------------------------------------------"; read -p "确认要将以上更改写入 '$config_path' 吗？(y/N): " confirm; if [[ ! "$confirm" =~ ^[yY] ]]; then echo "🚫 操作已取消。"; return 1; fi
    echo "⚙️ 正在更新配置文件: $config_path ..."; sed -i.bak -e "s/REMOTE_IPV4=\".*\"/REMOTE_IPV4=\"$new_ip\"/" -e "s/IPV6_ROUTED_64_SEGMENT=\".*\"/IPV6_ROUTED_64_SEGMENT=\"$new_64\"/" -e "s/IPV6_ROUTED_48_SEGMENT=\".*\"/IPV6_ROUTED_48_SEGMENT=\"$new_48\"/" "$config_path"; echo "✔︎ 配置文件更新完毕！原始文件已备份为 ${config_path}.bak"
    export FINAL_NEW_48_SEGMENT=$new_48; return 0
}


#================================================
# 函数 4: 【最终JSON结构修正版】更新 x-ui 配置
#================================================
update_xui_config() {
    local new_48_segment="$1"
    echo; echo "🔄 开始联动更新 x-ui 数据库 (最终模式)..."
    if [ ! -f "$XUI_DB_PATH" ]; then echo "ℹ️ 未找到 x-ui 数据库文件: $XUI_DB_PATH。跳过更新。"; return; fi

    local new_ipv6_addr="2001:470:${new_48_segment}::2"
    
    # 步骤1: 停止 x-ui 服务
    echo "  -> 步骤 1/4: 正在停止 '$XUI_SERVICE_NAME' 服务以安全读写数据库..."
    if systemctl is-active --quiet "$XUI_SERVICE_NAME"; then
        systemctl stop "$XUI_SERVICE_NAME"; sleep 1
    fi
    echo "  -> ✔︎ 服务已停止。"

    # 步骤2: 从数据库读取 xrayTemplateConfig 的完整JSON内容
    echo "  -> 步骤 2/4: 正在从数据库 settings 表读取 xrayTemplateConfig..."
    local xray_config_json=$(sqlite3 "$XUI_DB_PATH" "SELECT value FROM settings WHERE key = 'xrayTemplateConfig';")
    if [ -z "$xray_config_json" ]; then
        echo "  -> ❌ 错误: 未能在 settings 表中找到 xrayTemplateConfig 键。正在尝试重启服务..."
        systemctl start "$XUI_SERVICE_NAME"
        return
    fi

    # 步骤3: 使用 jq 在内存中修改配置
    echo "  -> 步骤 3/4: 正在使用 jq 在内存中更新出站配置..."
    local tags_json_array='['
    for tag in "${XUI_OUTBOUND_TAGS[@]}"; do tags_json_array+="\"$tag\","; done
    tags_json_array="${tags_json_array%,}]"
    
    # 【修复】使用正确的 jq 命令, 在顶层添加/修改 sendThrough 字段
    local modified_xray_config_json=$(echo "$xray_config_json" | jq --argjson tags "$tags_json_array" --arg ip "$new_ipv6_addr" \
    '( .outbounds[] | select(.tag | IN($tags[])) ) |= (.sendThrough = $ip)')

    # 步骤4: 将修改后的完整JSON内容安全地写回数据库
    echo "  -> 步骤 4/4: 正在将修改后的完整配置写回数据库..."
    local escaped_json=$(echo "$modified_xray_config_json" | sed "s/'/''/g")
    
    sqlite3 "$XUI_DB_PATH" "UPDATE settings SET value = '${escaped_json}' WHERE key = 'xrayTemplateConfig';"
    
    if [ $? -ne 0 ]; then
        echo "❌ 使用 sqlite3 将新配置写回数据库失败！正在尝试重启服务以恢复..."
        systemctl start "$XUI_SERVICE_NAME"
        return
    fi
    echo "  -> ✔︎ 数据库修改成功。"

    # 最后: 启动 x-ui 服务
    echo "  -> 正在启动 '$XUI_SERVICE_NAME' 服务..."
    systemctl start "$XUI_SERVICE_NAME"
    sleep 2
    if systemctl is-active --quiet "$XUI_SERVICE_NAME"; then
        echo "✔︎ '$XUI_SERVICE_NAME' 服务已成功启动, 新配置已生效！"
    else
        echo "❌ '$XUI_SERVICE_NAME' 服务启动失败！请手动检查: sudo systemctl status $XUI_SERVICE_NAME"
    fi
}


#================================================
# 函数 5: 创建并启用 systemd 开机自启服务
#================================================
setup_systemd_service() {
    local service_name="he-tunnel.service"; local service_path="/etc/systemd/system/${service_name}"; if ! command -v systemctl &> /dev/null; then echo "ℹ️ 未检测到 systemd, 无法设置开机自启服务。"; return; fi; if systemctl is-enabled "$service_name" &> /dev/null; then echo "ℹ️ 开机自启服务 ('$service_name') 已经启用, 无需重复设置。"; return; fi
    echo; read -p "💡 是否要将 '$CONFIG_FILE_PATH' 设置为开机自启? (Y/n): " choice; if [[ "$choice" =~ ^[nN]$ ]]; then echo "ℹ️ 用户选择不设置开机自启。"; return; fi
    echo "⚙️ 正在创建 systemd 服务: $service_path..."; cat << EOF > "$service_path"
[Unit]
Description=HE.net IPv6 Tunnel Setup (managed by he_tunnel_manager script)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$CONFIG_FILE_PATH
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    echo "⚙️ 正在启用服务..."; systemctl daemon-reload; systemctl enable "$service_name"; if systemctl is-enabled "$service_name" &> /dev/null; then echo "✔︎ 成功! '$CONFIG_FILE_PATH' 将在下次开机时自动运行。"; else echo "❌ 错误: 设置开机自启失败。请检查 systemd 日志。"; fi
}


#================================================
# 主执行流程
#================================================
main() {
    if [ "$(id -u)" -ne 0 ]; then echo "❌ 错误：此脚本需要以 root 权限运行。"; exit 1; fi; check_dependencies; if [ $? -ne 0 ]; then exit 1; fi; echo "--------------------------------------------------"; echo "⚙️ 准备工作环境..."; mkdir -p "$WORK_DIR"
    if [ ! -f "$CONFIG_FILE_PATH" ]; then echo "  -> 配置文件 '$CONFIG_FILE_PATH' 不存在, 正在生成模板..."; generate_config_template; chmod +x "$CONFIG_FILE_PATH"; echo "✔︎ 模板生成成功。"; else echo "ℹ️ 配置文件 '$CONFIG_FILE_PATH' 已存在, 将直接进行编辑。"; fi
    echo; interactive_edit_tunnel "$CONFIG_FILE_PATH"; if [ $? -ne 0 ]; then echo; echo "❌ 编辑过程被取消或失败, 脚本已终止。"; exit 1; fi
    echo; read -p "✅ 配置已更新, 是否立即执行 '$CONFIG_FILE_PATH' 来应用网络设置? (Y/n): " choice
    if [[ ! "$execute_choice" =~ ^[nN]$ ]]; then
        echo "🚀 正在执行配置脚本..."; echo "-------------------------------------------"; bash "$CONFIG_FILE_PATH"; echo "-------------------------------------------"; echo "🎉 网络配置完成！"
        update_xui_config "$FINAL_NEW_48_SEGMENT"
        setup_systemd_service
        echo "🎉 所有操作完成！"
    else echo "ℹ️ 用户选择不执行。配置已保存在 '$CONFIG_FILE_PATH'。"; fi; exit 0
}

# --- 运行主函数 ---
main
