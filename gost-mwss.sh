#!/bin/bash

# --- 脚本信息 ---
# 名称: Gost-MWSS 多服务管理脚本
# 版本: v1.1
# 更新: 增强依赖检查，可自动为新系统安装 curl, openssl, jq 等核心工具。
# 功能: 使用 'function' 关键字定义所有函数，以兼容ash/busybox等极简shell环境。
# =================================================

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 全局变量 ---
SERVICE_PREFIX="gost_"
SERVICE_DIR="/etc/systemd/system"
ACME_CMD="$HOME/.acme.sh/acme.sh"

# --- 函数定义 ---
function check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误: 此脚本必须以 root 用户权限运行。${NC}"; exit 1
    fi
}

function list_services_for_menu() {
    echo -e "${CYAN}--- 当前已配置的 Gost-MWSS 服务 ---${NC}"
    
    local service_files
    # Use systemctl to get the list of service files
    mapfile -t service_files < <(systemctl list-units --type=service --all "${SERVICE_PREFIX}*.service" --no-legend | awk '{print $1}')

    if [ ${#service_files[@]} -eq 0 ]; then
        echo "未找到任何 Gost-MWSS 服务。"
    else
        printf "%-25s %-20s %-20s\n" "服务名 (NAME)" "运行状态 (STATUS)" "开机自启 (ENABLED)"
        echo "-----------------------------------------------------------------"
        for service_fullname in "${service_files[@]}"; do
            # Get status using more reliable commands
            local active_status
            active_status=$(systemctl show -p ActiveState --value "$service_fullname")
            local enabled_status
            enabled_status=$(systemctl is-enabled "$service_fullname" 2>/dev/null)

            # Translate status for better readability
            local display_active
            case "$active_status" in
                active)       display_active="${GREEN}运行中${NC}" ;;
                inactive)     display_active="已停止" ;;
                failed)       display_active="${RED}失败${NC}" ;;
                activating)   display_active="${YELLOW}启动中...${NC}" ;;
                deactivating) display_active="${YELLOW}停止中...${NC}" ;;
                *)            display_active="$active_status" ;;
            esac

            local display_enabled
            case "$enabled_status" in
                enabled)      display_enabled="${GREEN}已启用${NC}" ;;
                disabled)     display_enabled="${YELLOW}已禁用${NC}" ;;
                static)       display_enabled="静态" ;;
                masked)       display_enabled="${RED}被禁用${NC}" ;;
                *)            display_enabled="$enabled_status" ;;
            esac

            local short_name=${service_fullname#"$SERVICE_PREFIX"}
            short_name=${short_name%".service"}
            
            # Use printf and %-b to correctly handle strings with colors
            printf "%-25s %-20b %-20b\n" "$short_name" "$display_active" "$display_enabled"
        done
    fi
    echo "-----------------------------------------------------------------"
}

function select_service() {
    echo -e "${CYAN}--- 请选择要操作的服务 ---${NC}" >&2
    local services_list
    mapfile -t services_list < <(systemctl list-units --type=service --all "${SERVICE_PREFIX}*.service" --no-legend | awk '{print $1}')

    if [ ${#services_list[@]} -eq 0 ]; then
        echo -e "${RED}未找到任何可操作的 Gost-MWSS 服务。${NC}" >&2
        return 1
    fi

    select service_fullname in "${services_list[@]}" "返回上一级"; do
        case "$service_fullname" in
            "返回上一级")
                return 1
                ;;
            "")
                echo -e "${RED}无效的输入，请输入列表中的数字。${NC}" >&2
                ;;
            *)
                local short_name=${service_fullname#"$SERVICE_PREFIX"}
                short_name=${short_name%".service"}
                echo "$short_name"
                return 0
                ;;
        esac
    done
}

function view_service_details() {
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi

    local SERVICE_FILE_PATH="${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service"
    if [ ! -f "$SERVICE_FILE_PATH" ]; then
        echo -e "${RED}错误: 找不到服务文件 ${SERVICE_FILE_PATH}${NC}"; return
    fi

    echo -e "${CYAN}--- 服务 '${SERVICE_NAME}' 的详细配置 ---${NC}"
    
    local EXEC_LINE
    EXEC_LINE=$(grep '^ExecStart=' "$SERVICE_FILE_PATH")
    local FORWARDER="未配置"
    if [[ "$EXEC_LINE" == *"-F "* ]]; then
        local F_ARG_TEMP=${EXEC_LINE#*-F \"}
        FORWARDER=${F_ARG_TEMP%%\"*}
    fi
    
    local listener_count=0
    grep -o '\-L "[^"]*"' <<< "$EXEC_LINE" | while read -r L_ARG_QUOTED; do
        listener_count=$((listener_count + 1))
        echo "---------------- [ 监听器 ${listener_count} ] ----------------"
        local L_ARG=${L_ARG_QUOTED:4:-1}
        
        local REST=${L_ARG#*//}; local MAIN_PART=${REST%%\?*}; local QUERY_PART=${REST#*\?}
        local USER_PASS_PART=${MAIN_PART%@*}; local HOST_PORT_PART=${MAIN_PART#*@}
        local IP; local PORT; local USER; local PASS;
        
        if [[ "$USER_PASS_PART" == "$HOST_PORT_PART" ]]; then
            USER="N/A"; PASS="N/A"
            IP=${HOST_PORT_PART%:*}
            PORT=${HOST_PORT_PART##*:}
        else
            USER=${USER_PASS_PART%:*}
            PASS=${USER_PASS_PART#*:}
            IP=${HOST_PORT_PART%:*}
            PORT=${HOST_PORT_PART##*:}
        fi
        
        local PATH_VAR="N/A"; local KNOCK="N/A"; local CERT_FILE="N/A"; local KEY_FILE="N/A"
        local OLD_IFS=$IFS; IFS='&'; for param in $QUERY_PART; do case "$param" in path=*) PATH_VAR=${param#path=/} ;; knock=*) KNOCK=${param#knock=} ;; cert=*) CERT_FILE=${param#cert=} ;; key=*) KEY_FILE=${param#key=} ;; esac; done; IFS=$OLD_IFS
        
        printf "%-15s: %s\n" "监听地址 (IP)" "${YELLOW}${IP}${NC}"
        printf "%-15s: %s\n" "端口 (Port)" "${YELLOW}${PORT}${NC}"
        printf "%-15s: %s\n" "用户名 (User)" "${YELLOW}${USER}${NC}"
        printf "%-15s: %s\n" "密码 (Password)" "${YELLOW}${PASS}${NC}"
        printf "%-15s: %s\n" "路径 (Path)" "${YELLOW}/${PATH_VAR}${NC}"
        printf "%-15s: %s\n" "Knock 域名" "${YELLOW}${KNOCK}${NC}"
        printf "%-15s: %s\n" "证书 (Cert)" "${YELLOW}${CERT_FILE}${NC}"
        printf "%-15s: %s\n" "密钥 (Key)" "${YELLOW}${KEY_FILE}${NC}"
    done
    
    echo "---------------- [ 全局配置 ] ----------------"
    printf "%-15s: %s\n" "后置转发代理" "${YELLOW}${FORWARDER}${NC}"
    echo "----------------------------------------------"
}

function add_new_service() {
    echo -e "${CYAN}--- 添加新的 Gost-MWSS 服务 ---${NC}"
    read -p ">> 请输入一个唯一的服务名称 (例如: myline1): " SERVICE_NAME
    if [ -z "$SERVICE_NAME" ]; then echo -e "${RED}错误: 服务名称不能为空。${NC}"; return; fi
    if [[ ! "$SERVICE_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then echo -e "${RED}错误: 服务名称只能包含字母、数字、下划线和连字符。${NC}"; return; fi
    if [ -f "${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service" ]; then echo -e "${RED}错误: 名为 '${SERVICE_NAME}' 的服务已存在。${NC}"; return; fi
    
    echo -e "${YELLOW}--- 正在为服务 '${SERVICE_NAME}' 配置基础参数 ---${NC}"
    read -p ">> 请输入监听 IP 地址 [默认: :: (自动支持IPv4+IPv6)]: " GOST_LISTEN_IP
    
    if [ -z "$GOST_LISTEN_IP" ]; then
        GOST_LISTEN_IP="::"
    fi

    read -p ">> 请输入 Gost-MWSS 服务的【用户名】: " GOST_USER
    read -p ">> 请输入 Gost-MWSS 服务的【密码】: " GOST_PASSWORD
    read -p ">> 请输入 Gost-MWSS 服务的【端口号】: " GOST_PORT
    read -p ">> 请输入 Gost-MWSS 服务的【路径】 (path): " GOST_PATH
    read -p ">> 请输入用于'knock'功能的域名 [默认: www.yaohuo.me]: " GOST_KNOCK_DOMAIN; GOST_KNOCK_DOMAIN=${GOST_KNOCK_DOMAIN:-www.yaohuo.me}

    local GOST_FORWARD_PARAM=""; local FORWARD_PROXY_ADDRESS=""
    echo -e "${YELLOW}--- 高级选项: 后置转发 (可选) ---${NC}"
    read -p ">> 是否要为此服务添加一个后置转发代理? [y/N]: " ADD_FORWARDER
    if [[ "$ADD_FORWARDER" == "y" || "$ADD_FORWARDER" == "Y" ]]; then
        read -p ">> 请输入完整的后置转发代理地址 (例如: socks5://127.0.0.1:1080): " FORWARD_PROXY_ADDRESS
        if [ -n "$FORWARD_PROXY_ADDRESS" ]; then
            GOST_FORWARD_PARAM="-F \"${FORWARD_PROXY_ADDRESS}\""
        fi
    fi
    
    echo -e "${YELLOW}--- 证书配置 ---${NC}"
    read -p ">> 请输入证书(crt)文件路径 [默认: /root/1.crt]: " GOST_CERT_FILE
    GOST_CERT_FILE=${GOST_CERT_FILE:-/root/1.crt}

    read -p ">> 请输入密钥(key)文件路径 [默认: /root/1.key]: " GOST_KEY_FILE
    GOST_KEY_FILE=${GOST_KEY_FILE:-/root/1.key}

    if [ ! -f "$GOST_CERT_FILE" ] || [ ! -f "$GOST_KEY_FILE" ]; then
        echo -e "${YELLOW}警告: 证书文件 ${GOST_CERT_FILE} 或密钥文件 ${GOST_KEY_FILE} 不存在。${NC}"
        echo -e "${YELLOW}您可以稍后使用菜单中的“申请证书”或“生成自签名证书”功能来获取。${NC}"
        read -p "是否继续? (y/n): " confirm_cert; if [[ "$confirm_cert" != "y" ]]; then return; fi
    fi
    
    local FORMATTED_LISTEN_IP
    if [[ "$GOST_LISTEN_IP" == *":"* ]]; then
        FORMATTED_LISTEN_IP="[${GOST_LISTEN_IP}]"
    else
        FORMATTED_LISTEN_IP="${GOST_LISTEN_IP}"
    fi
    
    local LISTEN_PARAMS="-L \"mwss://${GOST_USER}:${GOST_PASSWORD}@${FORMATTED_LISTEN_IP}:${GOST_PORT}?path=/${GOST_PATH}&cert=${GOST_CERT_FILE}&key=${GOST_KEY_FILE}&probe_resist=code:404&knock=${GOST_KNOCK_DOMAIN}\""
    SERVICE_FILE_PATH="${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service"
    echo "--> 正在创建服务文件: ${SERVICE_FILE_PATH}"
    local EXEC_START_CMD="/usr/bin/gost ${LISTEN_PARAMS} ${GOST_FORWARD_PARAM}"
    cat << EOF > ${SERVICE_FILE_PATH}
[Unit]
Description=Gost Service (${SERVICE_NAME})
After=network.target
[Service]
Type=simple
ExecStart=${EXEC_START_CMD}
Restart=on-failure
RestartSec=42s
[Install]
WantedBy=multi-user.target
EOF
    echo "--> 正在重载、启动并启用服务..."
    systemctl daemon-reload
    systemctl enable "${SERVICE_PREFIX}${SERVICE_NAME}.service" > /dev/null 2>&1
    systemctl start "${SERVICE_PREFIX}${SERVICE_NAME}.service"
    echo ""
    echo "================================================="
    echo -e "      ${GREEN}服务 '${SERVICE_NAME}' 创建成功！${NC}"
    echo "================================================="
    echo "您的 Gost-MWSS 服务配置信息如下:"
    echo "  监听地址: ${YELLOW}${GOST_LISTEN_IP}${NC}"
    echo "  端口:     ${YELLOW}${GOST_PORT}${NC}"
    echo "  用户名:   ${YELLOW}${GOST_USER}${NC}"
    echo "  密码:     ${YELLOW}${GOST_PASSWORD}${NC}"
    echo "  路径:     ${YELLOW}/${GOST_PATH}${NC}"
    echo "  Knock 域名: ${YELLOW}${GOST_KNOCK_DOMAIN}${NC}"
    echo "  证书路径: ${YELLOW}${GOST_CERT_FILE}${NC}"
    echo "  密钥路径: ${YELLOW}${GOST_KEY_FILE}${NC}"
    if [ -n "$FORWARD_PROXY_ADDRESS" ]; then
        echo -e "  后置转发代理: ${YELLOW}${FORWARD_PROXY_ADDRESS}${NC}"
    else
        echo "  后置转发代理: 未配置"
    fi
    echo "-------------------------------------------------"
    echo ""
    systemctl status "${SERVICE_PREFIX}${SERVICE_NAME}.service" --no-pager
}

function modify_service() {
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi

    local SERVICE_FILE_PATH="${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service"
    if [ ! -f "$SERVICE_FILE_PATH" ]; then
        echo -e "${RED}错误: 找不到服务文件 ${SERVICE_FILE_PATH}${NC}"; return
    fi

    echo -e "${CYAN}--- 正在修改服务 '${SERVICE_NAME}' ---${NC}"
    
    # --- 1. 解析当前配置 ---
    local EXEC_LINE
    EXEC_LINE=$(grep '^ExecStart=' "$SERVICE_FILE_PATH")
    if [ -z "$EXEC_LINE" ]; then
        echo -e "${RED}错误: 无法在服务文件中找到 'ExecStart' 配置行。${NC}"; return
    fi
    
    local L_ARG_RAW
    L_ARG_RAW=$(echo "$EXEC_LINE" | grep -o '\-L "[^"]*"')
    local L_ARG=${L_ARG_RAW:4:-1}

    local CURRENT_FORWARDER=""
    if [[ "$EXEC_LINE" == *"-F "* ]]; then
        local F_ARG_RAW
        F_ARG_RAW=$(echo "$EXEC_LINE" | grep -o '\-F "[^"]*"')
        CURRENT_FORWARDER=${F_ARG_RAW:4:-1}
    fi

    local PROTO_REMOVED=${L_ARG#*//}
    local MAIN_PART=${PROTO_REMOVED%%\?*}
    local QUERY_PART=${PROTO_REMOVED#*\?}
    
    local CURRENT_USER; local CURRENT_PASS
    if [[ "$MAIN_PART" == *"@"* ]]; then
        local USER_PASS_PART=${MAIN_PART%@*}
        local HOST_PORT_PART=${MAIN_PART#*@}
        CURRENT_USER=${USER_PASS_PART%:*}
        CURRENT_PASS=${USER_PASS_PART#*:}
    else
        local HOST_PORT_PART=$MAIN_PART
        CURRENT_USER=""
        CURRENT_PASS=""
    fi

    local CURRENT_IP_RAW=${HOST_PORT_PART%:*}
    local CURRENT_PORT=${HOST_PORT_PART##*:}
    local CURRENT_IP
    if [[ "$CURRENT_IP_RAW" == "["* ]]; then
        CURRENT_IP=${CURRENT_IP_RAW:1:-1}
    else
        CURRENT_IP="$CURRENT_IP_RAW"
    fi
    
    local CURRENT_PATH=""; local CURRENT_KNOCK=""; local CURRENT_CERT=""; local CURRENT_KEY=""
    local OLD_IFS=$IFS; IFS='&'; for param in $QUERY_PART; do case "$param" in path=*) CURRENT_PATH=${param#path=/} ;; knock=*) CURRENT_KNOCK=${param#knock=} ;; cert=*) CURRENT_CERT=${param#cert=} ;; key=*) CURRENT_KEY=${param#key=} ;; esac; done; IFS=$OLD_IFS

    # --- 2. 提示用户输入新配置 (将当前值作为默认值) ---
    echo -e "${YELLOW}--- 请输入新配置 (直接回车则保留原值) ---${NC}"
    
    read -p ">> 监听 IP 地址 [当前: ${CURRENT_IP}]: " NEW_LISTEN_IP
    NEW_LISTEN_IP=${NEW_LISTEN_IP:-$CURRENT_IP}
    
    read -p ">> 用户名 [当前: ${CURRENT_USER}]: " NEW_USER
    NEW_USER=${NEW_USER:-$CURRENT_USER}
    
    read -p ">> 密码 [当前: ${CURRENT_PASS}]: " NEW_PASSWORD
    NEW_PASSWORD=${NEW_PASSWORD:-$CURRENT_PASS}
    
    read -p ">> 端口号 [当前: ${CURRENT_PORT}]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    
    read -p ">> 路径 (path) [当前: ${CURRENT_PATH}]: " NEW_PATH
    NEW_PATH=${NEW_PATH:-$CURRENT_PATH}
    
    read -p ">> Knock 域名 [当前: ${CURRENT_KNOCK}]: " NEW_KNOCK_DOMAIN
    NEW_KNOCK_DOMAIN=${NEW_KNOCK_DOMAIN:-$CURRENT_KNOCK}

    read -p ">> 证书(crt/cer)文件路径 [当前: ${CURRENT_CERT}]: " NEW_CERT_FILE
    NEW_CERT_FILE=${NEW_CERT_FILE:-$CURRENT_CERT}

    read -p ">> 密钥(key)文件路径 [当前: ${CURRENT_KEY}]: " NEW_KEY_FILE
    NEW_KEY_FILE=${NEW_KEY_FILE:-$CURRENT_KEY}
    
    read -p ">> 后置转发代理地址 (留空则删除) [当前: ${CURRENT_FORWARDER}]: " NEW_FORWARDER
    NEW_FORWARDER=${NEW_FORWARDER:-$CURRENT_FORWARDER}

    # --- 3. 重建服务文件 ---
    local NEW_FORWARD_PARAM=""
    if [ -n "$NEW_FORWARDER" ]; then
        NEW_FORWARD_PARAM="-F \"${NEW_FORWARDER}\""
    fi

    local FORMATTED_LISTEN_IP
    if [[ "$NEW_LISTEN_IP" == *":"* ]]; then
        FORMATTED_LISTEN_IP="[${NEW_LISTEN_IP}]"
    else
        FORMATTED_LISTEN_IP="${NEW_LISTEN_IP}"
    fi

    local LISTEN_PARAMS="-L \"mwss://${NEW_USER}:${NEW_PASSWORD}@${FORMATTED_LISTEN_IP}:${NEW_PORT}?path=/${NEW_PATH}&cert=${NEW_CERT_FILE}&key=${NEW_KEY_FILE}&probe_resist=code:404&knock=${NEW_KNOCK_DOMAIN}\""
    local EXEC_START_CMD="/usr/bin/gost ${LISTEN_PARAMS} ${NEW_FORWARD_PARAM}"
    
    echo "--> 正在更新服务文件: ${SERVICE_FILE_PATH}"
    cat << EOF > ${SERVICE_FILE_PATH}
[Unit]
Description=Gost Service (${SERVICE_NAME})
After=network.target
[Service]
Type=simple
ExecStart=${EXEC_START_CMD}
Restart=on-failure
RestartSec=42s
[Install]
WantedBy=multi-user.target
EOF
    
    # --- 4. 应用更改 ---
    echo "--> 正在重载 systemd 配置..."
    systemctl daemon-reload
    echo -e "${GREEN}服务 '${SERVICE_NAME}' 配置已更新！${NC}"
    
    read -p ">> 是否立即重启服务以应用新配置? [Y/n]: " CONFIRM_RESTART
    if [[ "$CONFIRM_RESTART" != "n" && "$CONFIRM_RESTART" != "N" ]]; then
        echo "--> 正在重启服务..."
        systemctl restart "${SERVICE_PREFIX}${SERVICE_NAME}.service"
        sleep 1
        echo "--> 服务状态:"
        systemctl status "${SERVICE_PREFIX}${SERVICE_NAME}.service" --no-pager
    else
        echo -e "${YELLOW}服务配置已更新，但未重启。您需要稍后手动重启才能生效。${NC}"
    fi
}

function delete_service() {
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi
    read -p ">> 你确定要永久删除服务 '${SERVICE_NAME}' 吗? 此操作不可逆！ (y/n): " CONFIRM_DELETE
    if [[ "$CONFIRM_DELETE" != "y" ]]; then echo "操作已取消。"; return; fi
    FULL_SERVICE_NAME="${SERVICE_PREFIX}${SERVICE_NAME}.service"
    echo "--> 正在停止服务: ${FULL_SERVICE_NAME}"; systemctl stop "$FULL_SERVICE_NAME"
    echo "--> 正在禁用服务: ${FULL_SERVICE_NAME}"; systemctl disable "$FULL_SERVICE_NAME" > /dev/null 2>&1
    echo "--> 正在删除服务文件..."; rm -f "${SERVICE_DIR}/${FULL_SERVICE_NAME}"
    echo "--> 正在重载 systemd..."; systemctl daemon-reload; systemctl reset-failed
    echo -e "${GREEN}服务 '${SERVICE_NAME}' 已成功删除。${NC}"
}

function manage_service() {
    local ACTION=$1
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi
    echo "--> 正在对服务 '${SERVICE_NAME}' 执行 ${ACTION} 操作..."
    systemctl "$ACTION" "${SERVICE_PREFIX}${SERVICE_NAME}.service"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}操作成功。正在检查状态...${NC}"
    else
        echo -e "${RED}操作失败！请检查上面的错误信息或使用日志功能查看详情。${NC}"
    fi
    sleep 1
    systemctl status "${SERVICE_PREFIX}${SERVICE_NAME}.service" --no-pager
}

function manage_autostart() {
    local ACTION=$1
    local ACTION_TEXT
    if [ "$ACTION" == "enable" ]; then
        ACTION_TEXT="启用"
    else
        ACTION_TEXT="禁用"
    fi

    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi

    echo "--> 正在为服务 '${SERVICE_NAME}' ${ACTION_TEXT} 开机自启..."
    systemctl "$ACTION" "${SERVICE_PREFIX}${SERVICE_NAME}.service" > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}操作成功！服务 '${SERVICE_NAME}' 的开机自启已${ACTION_TEXT}。${NC}"
    else
        echo -e "${RED}操作失败！请检查上面的错误信息。${NC}"
    fi
    
    local enabled_status
    enabled_status=$(systemctl is-enabled "${SERVICE_PREFIX}${SERVICE_NAME}.service" 2>/dev/null)
    echo -e "--> 当前开机自启状态: ${CYAN}${enabled_status}${NC}"
}


function view_logs() {
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi
    echo -e "${YELLOW}正在加载日志... 按 Ctrl+C 退出日志查看。${NC}"
    journalctl -u "${SERVICE_PREFIX}${SERVICE_NAME}.service" -f -n 50 --no-pager
}

function update_gost_binary(){
    if [ -f /usr/bin/gost ]; then
        echo -e "${YELLOW}--> 检测到 /usr/bin/gost 已存在。此操作将覆盖它。${NC}"
        read -p ">> 是否继续? (y/n): " confirm_overwrite
        if [[ "$confirm_overwrite" != "y" ]]; then echo "操作已取消。"; return; fi
    fi
    echo ""
    echo -e "${GREEN}--> 准备安装/更新 Gost 主程序...${NC}"
    echo "------------------------------------------"
    echo "请选择 Gost 的安装方式："
    echo "  1. 自动从 GitHub API 检测最新版本"
    echo "  2. 手动粘贴 Gost 压缩包的直接下载链接"
    echo "------------------------------------------"
    read -p ">> 请输入选项 [1-2，默认: 1]: " INSTALL_CHOICE
    if [[ "$INSTALL_CHOICE" == "2" ]]; then
        read -p ">> 请粘贴下载链接: " MANUAL_DOWNLOAD_URL
        if [ -z "$MANUAL_DOWNLOAD_URL" ]; then echo -e "${RED}错误: 链接不能为空！${NC}"; return; fi
        DOWNLOAD_URL="$MANUAL_DOWNLOAD_URL"
    else
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) GOST_ARCH="amd64" ;;
            aarch64) GOST_ARCH="arm64" ;;
            *) echo -e "${RED}不支持的系统架构: $ARCH。${NC}"; return ;;
        esac
        
        API_URL="https://api.github.com/repos/go-gost/gost/releases"
        echo "--> 正在从 GitHub API (go-gost/gost) 获取最新版本信息..."
        
        DOWNLOAD_URL=$(curl -s $API_URL | jq -r --arg GOST_ARCH "$GOST_ARCH" '.[0].assets[] | select(.name | test("linux_" + $GOST_ARCH + "\\.tar\\.gz$")) | .browser_download_url')
        
        if [ -z "$DOWNLOAD_URL" ]; then echo -e "${RED}错误: 自动获取失败。请检查 API 访问或使用手动链接。${NC}"; return; fi
    fi
    
    echo -e "${GREEN}--> 已确定下载链接: ${YELLOW}${DOWNLOAD_URL}${NC}"
    TMP_DIR="/tmp/gost_install"
    mkdir -p "$TMP_DIR"
    FILENAME=$(basename "$DOWNLOAD_URL")
    echo "--> 正在下载..."
    curl -L --retry 3 -o "$TMP_DIR/$FILENAME" "$DOWNLOAD_URL"
    if [ $? -ne 0 ]; then echo -e "${RED}下载失败！${NC}"; rm -rf "$TMP_DIR"; return; fi
    
    echo "--> 正在解压安装..."
    if [[ "$FILENAME" == *.zip ]]; then
        unzip -o "$TMP_DIR/$FILENAME" -d "$TMP_DIR"
    elif [[ "$FILENAME" == *.tar.gz ]]; then
        tar -xzf "$TMP_DIR/$FILENAME" -C "$TMP_DIR"
    else
        echo -e "${RED}未知的压缩格式${NC}"; rm -rf "$TMP_DIR"; return
    fi
    
    GOST_BINARY=$(find "$TMP_DIR" -name gost -type f | head -n 1)
    if [ -z "$GOST_BINARY" ]; then echo -e "${RED}在解压文件中未找到gost程序！${NC}"; rm -rf "$TMP_DIR"; return; fi
    
    mv -f "$GOST_BINARY" /usr/bin/gost
    chmod +x /usr/bin/gost
    rm -rf "$TMP_DIR"
    
    if [ -f /usr/bin/gost ]; then
        VERSION=$(/usr/bin/gost -V 2>/dev/null)
        echo -e "${GREEN}--> Gost 更新成功！${NC}"
        echo -e "${GREEN}    版本信息: ${VERSION}${NC}"
        
        local active_services
        mapfile -t active_services < <(systemctl list-units --type=service --state=active "${SERVICE_PREFIX}*.service" --no-legend | awk '{print $1}')
        
        if [ ${#active_services[@]} -eq 0 ]; then
            echo -e "${YELLOW}未检测到正在运行的 Gost 服务，无需重启。${NC}"
        else
            echo ""
            read -p ">> 是否立即重启所有正在运行的(${#active_services[@]}个)Gost服务以应用新版本? [Y/n]: " confirm_restart_all
            if [[ "$confirm_restart_all" != "n" && "$confirm_restart_all" != "N" ]]; then
                echo "--> 正在重启所有正在运行的 Gost 服务..."
                for service_fullname in "${active_services[@]}"; do
                    local short_name=${service_fullname#"$SERVICE_PREFIX"}
                    short_name=${short_name%".service"}
                    echo -n "    -> 正在重启服务 '${short_name}'..."
                    systemctl restart "$service_fullname"
                    if [ $? -eq 0 ]; then
                        echo -e " ${GREEN}成功${NC}"
                    else
                        echo -e " ${RED}失败${NC}"
                    fi
                done
                echo -e "${GREEN}所有正在运行的 Gost 服务重启完毕。${NC}"
            else
                echo -e "${YELLOW}操作取消。请稍后手动重启服务以应用新版本。${NC}"
            fi
        fi
        
    else
        echo -e "${RED}Gost 更新失败！${NC}"
    fi
}

function apply_certificate() {
    echo -e "${CYAN}--- 申请域名证书 (Let's Encrypt) ---${NC}"
    # 1. 安装 acme.sh
    if ! command -v "$ACME_CMD" &> /dev/null; then
        echo -e "${YELLOW}检测到 acme.sh 未安装，正在为您准备安装...${NC}"
        read -p ">> 请输入您的邮箱 (用于 acme.sh 注册和证书续期提醒): " ACME_EMAIL
        if [ -z "$ACME_EMAIL" ]; then
            echo -e "${RED}错误: 邮箱不能为空。${NC}"; return
        fi
        
        echo "--> 正在从 get.acme.sh 下载并安装 acme.sh..."
        curl https://get.acme.sh | sh -s email="$ACME_EMAIL"
        if [ $? -ne 0 ]; then
            echo -e "${RED}acme.sh 安装失败，请检查网络或错误信息。${NC}"; return
        fi
        echo -e "${GREEN}acme.sh 安装成功！${NC}"
    fi

    # 2. 获取域名
    read -p ">> 请输入要申请证书的域名 (例如: my.domain.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}错误: 域名不能为空。${NC}"; return
    fi
    echo -e "${YELLOW}重要提示: 请确保域名 ${CYAN}${DOMAIN}${NC} ${YELLOW}已正确解析到本服务器的公网 IP 地址。${NC}"
    
    # 3. 检查端口占用
    if ss -lnt | grep -q ':80 '; then
        echo -e "${RED}错误: 检测到 80 端口已被占用，无法使用 standalone 模式申请证书。${NC}"
        echo -e "${RED}请先停止占用 80 端口的服务 (如 Nginx, Apache 等) 后再试。${NC}"
        return
    fi
    
    # 4. 申请证书
    echo "--> 正在为域名 ${DOMAIN} 申请证书 (standalone 模式)..."
    "$ACME_CMD" --issue -d "$DOMAIN" --standalone -k ec-256
    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败！请检查域名解析是否正确或查看上面的错误日志。${NC}"; return
    fi
    
    # 5. 安装证书到指定目录
    local CERT_DIR="/root/certs/${DOMAIN}"
    local CERT_PATH="${CERT_DIR}/fullchain.cer"
    local KEY_PATH="${CERT_DIR}/private.key"
    echo "--> 正在安装证书到 ${CERT_DIR}..."
    mkdir -p "$CERT_DIR"
    "$ACME_CMD" --install-cert -d "$DOMAIN" --ecc \
        --fullchain-file "$CERT_PATH" \
        --key-file "$KEY_PATH"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}证书安装失败！${NC}"; return
    fi

    echo ""
    echo -e "${GREEN}=====================================================${NC}"
    echo -e "${GREEN} 证书申请成功! ${NC}"
    echo -e "${GREEN}=====================================================${NC}"
    echo -e "您的证书和密钥已保存到以下路径:"
    echo -e "  ${CYAN}证书 (Cert):${NC} ${YELLOW}${CERT_PATH}${NC}"
    echo -e "  ${CYAN}密钥 (Key): ${NC} ${YELLOW}${KEY_PATH}${NC}"
    echo -e "现在您可以在添加或修改 Gost-MWSS 服务时使用以上路径了。"
    echo -e "${YELLOW}acme.sh 会自动为您处理证书的续签，无需担心过期问题。${NC}"
}

function generate_self_signed_cert() {
    echo -e "${CYAN}--- 生成自签名 SSL 证书 (OpenSSL) ---${NC}"

    # User input
    read -p ">> 请输入证书通用名称(CN) [默认: localhost]: " COMMON_NAME
    COMMON_NAME=${COMMON_NAME:-localhost}

    read -p ">> 请输入证书有效期(天) [默认: 3650]: " DAYS
    DAYS=${DAYS:-3650}

    read -p ">> 请输入密钥(key)文件保存路径 [默认: /root/1.key]: " KEY_PATH
    KEY_PATH=${KEY_PATH:-/root/1.key}

    read -p ">> 请输入证书(crt)文件保存路径 [默认: /root/1.crt]: " CERT_PATH
    CERT_PATH=${CERT_PATH:-/root/1.crt}

    # Check for overwrites
    if [ -f "$KEY_PATH" ] || [ -f "$CERT_PATH" ]; then
        echo -e "${YELLOW}警告: 文件 ${KEY_PATH} 或 ${CERT_PATH} 已存在。${NC}"
        read -p ">> 是否覆盖? [y/N]: " confirm_overwrite
        if [[ "$confirm_overwrite" != "y" && "$confirm_overwrite" != "Y" ]]; then
            echo -e "${YELLOW}操作已取消。${NC}"
            return
        fi
    fi

    # Generate cert
    echo "--> 正在生成证书和密钥..."
    openssl req -x509 -newkey rsa:4096 -keyout "$KEY_PATH" -out "$CERT_PATH" -days "$DAYS" -nodes -subj "/CN=${COMMON_NAME}" > /dev/null 2>&1

    if [ $? -eq 0 ] && [ -f "$KEY_PATH" ] && [ -f "$CERT_PATH" ]; then
        echo ""
        echo -e "${GREEN}=====================================================${NC}"
        echo -e "${GREEN} 自签名证书生成成功! ${NC}"
        echo -e "${GREEN}=====================================================${NC}"
        echo -e "文件已保存到以下路径:"
        echo -e "  ${CYAN}证书 (Cert):${NC} ${YELLOW}${CERT_PATH}${NC}"
        echo -e "  ${CYAN}密钥 (Key): ${NC} ${YELLOW}${KEY_PATH}${NC}"
        echo "现在您可以在添加或修改服务时使用这些路径了。"
    else
        echo -e "${RED}证书生成失败！请检查 openssl 命令或文件权限。${NC}"
    fi
}

function install_script() {
    echo -e "${CYAN}--- 安装/更新 gost-mwss 快捷命令 ---${NC}"
    local SCRIPT_PATH
    SCRIPT_PATH=$(readlink -f "$0")
    local TARGET_PATH="/usr/local/bin/gost-mwss"

    if [ "$SCRIPT_PATH" == "$TARGET_PATH" ]; then
        echo -e "${GREEN}快捷命令已经是最新的 (您正在通过它运行此脚本)。${NC}"
        return
    fi

    echo "此操作将把当前脚本复制到 ${TARGET_PATH}"
    echo "之后，您就可以在系统任何地方通过输入 'gost-mwss' 来运行此面板。"
    read -p ">> 是否继续? [Y/n]: " confirm_install

    if [[ "$confirm_install" == "n" || "$confirm_install" == "N" ]]; then
        echo -e "${YELLOW}操作已取消。${NC}"
        return
    fi

    echo "--> 正在复制脚本到 ${TARGET_PATH}..."
    cp -f "$SCRIPT_PATH" "$TARGET_PATH"
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误: 复制失败！请检查权限。${NC}"
        return
    fi

    echo "--> 正在为脚本添加可执行权限..."
    chmod +x "$TARGET_PATH"
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误: 添加可执行权限失败！${NC}"
        return
    fi

    echo ""
    echo -e "${GREEN}快捷命令 'gost-mwss' 安装/更新成功！${NC}"
    echo -e "${YELLOW}请重新打开终端，或运行 'source ~/.bashrc' (或 ~/.zshrc 等) 来让命令立即生效。${NC}"
    echo "之后，您可以随时随地输入 ${CYAN}gost-mwss${NC} 来打开此面板。"
}

function main_menu() {
    check_root
    
    # --- Dependency Check & Auto-Installation ---
    local FATAL_DEPS="grep sed awk"
    for dep in $FATAL_DEPS; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${RED}致命错误: 核心工具 '${dep}' 未找到，脚本无法运行。${NC}"; exit 1
        fi
    done

    local INSTALL_DEPS="curl openssl jq socat"
    local DEPS_TO_INSTALL=""
    for dep in $INSTALL_DEPS; do
        if ! command -v $dep &> /dev/null; then
            DEPS_TO_INSTALL+="${dep} "
        fi
    done

    if [ -n "$DEPS_TO_INSTALL" ]; then
        echo -e "${YELLOW}首次运行或环境不完整，正在准备安装核心依赖: ${CYAN}${DEPS_TO_INSTALL}${NC}"
        
        local PKG_MANAGER_CMD=""
        if [ -f /etc/os-release ]; then . /etc/os-release; OS_ID=$ID; fi
        
        case "$OS_ID" in
            ubuntu|debian) PKG_MANAGER_CMD="apt-get update > /dev/null && apt-get install -y";;
            centos|rhel|fedora|rocky|almalinux) PKG_MANAGER_CMD="yum install -y";;
            *)
                echo -e "${RED}无法识别您的操作系统发行版。${NC}"
                echo -e "${RED}请手动安装以下依赖后重试: ${CYAN}${DEPS_TO_INSTALL}${NC}"; exit 1;;
        esac

        echo "--> 正在使用包管理器进行安装..."
        eval "$PKG_MANAGER_CMD $DEPS_TO_INSTALL"

        for dep in $DEPS_TO_INSTALL; do
            if ! command -v $dep &> /dev/null; then
                echo -e "${RED}错误: 依赖 '${dep}' 安装失败！请手动安装后重试。${NC}"; exit 1
            fi
        done
        echo -e "${GREEN}所有依赖已成功安装！${NC}"
    fi
    
    while true; do
        clear
        echo "=========================================="
        echo "      Gost-MWSS 多服务管理脚本 v1.0"
        echo "=========================================="
        
        local GOST_VERSION
        if [ -x /usr/bin/gost ]; then
            GOST_VERSION=$(/usr/bin/gost -V 2>/dev/null)
        fi
        
        if [ -n "$GOST_VERSION" ]; then
            echo -e "  当前 Gost 版本: ${GREEN}${GOST_VERSION}${NC}"
        else
            echo -e "  当前 Gost 版本: ${RED}未安装 (请使用选项 13 安装)${NC}"
        fi
        echo "=========================================="

        list_services_for_menu
        echo ""
        echo -e "${GREEN}请选择要执行的操作:${NC}"
        echo "  1. 添加新的 Gost-MWSS 服务"
        echo "  2. 查看服务详细配置"
        echo "  3. 修改服务配置"
        echo "  ----------------------------------------"
        echo "  4. 启动指定的 Gost-MWSS 服务"
        echo "  5. 停止指定的 Gost-MWSS 服务"
        echo "  6. 重启指定的 Gost-MWSS 服务"
        echo "  7. 启用服务开机自启"
        echo "  8. 禁用服务开机自启"
        echo "  ----------------------------------------"
        echo "  9. 查看指定服务的日志"
        echo "  10. 删除指定的 Gost-MWSS 服务"
        echo "  11. 申请域名证书 (Let's Encrypt)"
        echo "  12. 生成自签名证书 (OpenSSL)"
        echo "  13. 更新 Gost 主程序 (影响所有服务)"
        echo "  14. 安装/更新快捷命令"
        echo "  15. 退出脚本"
        echo "=========================================="
        read -p "请输入选项 [1-15]: " choice
        case $choice in
            1) add_new_service ;;
            2) view_service_details ;;
            3) modify_service ;;
            4) manage_service "start" ;;
            5) manage_service "stop" ;;
            6) manage_service "restart" ;;
            7) manage_autostart "enable" ;;
            8) manage_autostart "disable" ;;
            9) view_logs ;;
            10) delete_service ;;
            11) apply_certificate ;;
            12) generate_self_signed_cert ;;
            13) update_gost_binary ;;
            14) install_script ;;
            15) echo "退出脚本。"; exit 0 ;;
            *) echo -e "${RED}无效的选项，请重新输入。${NC}" ;;
        esac
        echo ""
        read -p "按 Enter键 返回主菜单..."
    done
}

# --- 脚本入口 ---
main_menu    fi

    echo -e "${CYAN}--- 服务 '${SERVICE_NAME}' 的详细配置 ---${NC}"
    
    local EXEC_LINE
    EXEC_LINE=$(grep '^ExecStart=' "$SERVICE_FILE_PATH")
    local FORWARDER="未配置"
    if [[ "$EXEC_LINE" == *"-F "* ]]; then
        local F_ARG_TEMP=${EXEC_LINE#*-F \"}
        FORWARDER=${F_ARG_TEMP%%\"*}
    fi
    
    local listener_count=0
    grep -o '\-L "[^"]*"' <<< "$EXEC_LINE" | while read -r L_ARG_QUOTED; do
        listener_count=$((listener_count + 1))
        echo "---------------- [ 监听器 ${listener_count} ] ----------------"
        local L_ARG=${L_ARG_QUOTED:4:-1}
        
        local REST=${L_ARG#*//}; local MAIN_PART=${REST%%\?*}; local QUERY_PART=${REST#*\?}
        local USER_PASS_PART=${MAIN_PART%@*}; local HOST_PORT_PART=${MAIN_PART#*@}
        local IP; local PORT; local USER; local PASS;
        
        if [[ "$USER_PASS_PART" == "$HOST_PORT_PART" ]]; then
            USER="N/A"; PASS="N/A"
            IP=${HOST_PORT_PART%:*}
            PORT=${HOST_PORT_PART##*:}
        else
            USER=${USER_PASS_PART%:*}
            PASS=${USER_PASS_PART#*:}
            IP=${HOST_PORT_PART%:*}
            PORT=${HOST_PORT_PART##*:}
        fi
        
        local PATH_VAR="N/A"; local KNOCK="N/A"; local CERT_FILE="N/A"; local KEY_FILE="N/A"
        local OLD_IFS=$IFS; IFS='&'; for param in $QUERY_PART; do case "$param" in path=*) PATH_VAR=${param#path=/} ;; knock=*) KNOCK=${param#knock=} ;; cert=*) CERT_FILE=${param#cert=} ;; key=*) KEY_FILE=${param#key=} ;; esac; done; IFS=$OLD_IFS
        
        printf "%-15s: %s\n" "监听地址 (IP)" "${YELLOW}${IP}${NC}"
        printf "%-15s: %s\n" "端口 (Port)" "${YELLOW}${PORT}${NC}"
        printf "%-15s: %s\n" "用户名 (User)" "${YELLOW}${USER}${NC}"
        printf "%-15s: %s\n" "密码 (Password)" "${YELLOW}${PASS}${NC}"
        printf "%-15s: %s\n" "路径 (Path)" "${YELLOW}/${PATH_VAR}${NC}"
        printf "%-15s: %s\n" "Knock 域名" "${YELLOW}${KNOCK}${NC}"
        printf "%-15s: %s\n" "证书 (Cert)" "${YELLOW}${CERT_FILE}${NC}"
        printf "%-15s: %s\n" "密钥 (Key)" "${YELLOW}${KEY_FILE}${NC}"
    done
    
    echo "---------------- [ 全局配置 ] ----------------"
    printf "%-15s: %s\n" "后置转发代理" "${YELLOW}${FORWARDER}${NC}"
    echo "----------------------------------------------"
}

function add_new_service() {
    echo -e "${CYAN}--- 添加新的 Gost-MWSS 服务 ---${NC}"
    read -p ">> 请输入一个唯一的服务名称 (例如: myline1): " SERVICE_NAME
    if [ -z "$SERVICE_NAME" ]; then echo -e "${RED}错误: 服务名称不能为空。${NC}"; return; fi
    if [[ ! "$SERVICE_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then echo -e "${RED}错误: 服务名称只能包含字母、数字、下划线和连字符。${NC}"; return; fi
    if [ -f "${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service" ]; then echo -e "${RED}错误: 名为 '${SERVICE_NAME}' 的服务已存在。${NC}"; return; fi
    
    echo -e "${YELLOW}--- 正在为服务 '${SERVICE_NAME}' 配置基础参数 ---${NC}"
    read -p ">> 请输入监听 IP 地址 [默认: :: (自动支持IPv4+IPv6)]: " GOST_LISTEN_IP
    
    if [ -z "$GOST_LISTEN_IP" ]; then
        GOST_LISTEN_IP="::"
    fi

    read -p ">> 请输入 Gost-MWSS 服务的【用户名】: " GOST_USER
    read -p ">> 请输入 Gost-MWSS 服务的【密码】: " GOST_PASSWORD
    read -p ">> 请输入 Gost-MWSS 服务的【端口号】: " GOST_PORT
    read -p ">> 请输入 Gost-MWSS 服务的【路径】 (path): " GOST_PATH
    read -p ">> 请输入用于'knock'功能的域名 [默认: www.yaohuo.me]: " GOST_KNOCK_DOMAIN; GOST_KNOCK_DOMAIN=${GOST_KNOCK_DOMAIN:-www.yaohuo.me}

    local GOST_FORWARD_PARAM=""; local FORWARD_PROXY_ADDRESS=""
    echo -e "${YELLOW}--- 高级选项: 后置转发 (可选) ---${NC}"
    read -p ">> 是否要为此服务添加一个后置转发代理? [y/N]: " ADD_FORWARDER
    if [[ "$ADD_FORWARDER" == "y" || "$ADD_FORWARDER" == "Y" ]]; then
        read -p ">> 请输入完整的后置转发代理地址 (例如: socks5://127.0.0.1:1080): " FORWARD_PROXY_ADDRESS
        if [ -n "$FORWARD_PROXY_ADDRESS" ]; then
            GOST_FORWARD_PARAM="-F \"${FORWARD_PROXY_ADDRESS}\""
        fi
    fi
    
    echo -e "${YELLOW}--- 证书配置 ---${NC}"
    read -p ">> 请输入证书(crt)文件路径 [默认: /root/1.crt]: " GOST_CERT_FILE
    GOST_CERT_FILE=${GOST_CERT_FILE:-/root/1.crt}

    read -p ">> 请输入密钥(key)文件路径 [默认: /root/1.key]: " GOST_KEY_FILE
    GOST_KEY_FILE=${GOST_KEY_FILE:-/root/1.key}

    if [ ! -f "$GOST_CERT_FILE" ] || [ ! -f "$GOST_KEY_FILE" ]; then
        echo -e "${YELLOW}警告: 证书文件 ${GOST_CERT_FILE} 或密钥文件 ${GOST_KEY_FILE} 不存在。${NC}"
        echo -e "${YELLOW}您可以稍后使用菜单中的“申请证书”或“生成自签名证书”功能来获取。${NC}"
        read -p "是否继续? (y/n): " confirm_cert; if [[ "$confirm_cert" != "y" ]]; then return; fi
    fi
    
    local FORMATTED_LISTEN_IP
    if [[ "$GOST_LISTEN_IP" == *":"* ]]; then
        FORMATTED_LISTEN_IP="[${GOST_LISTEN_IP}]"
    else
        FORMATTED_LISTEN_IP="${GOST_LISTEN_IP}"
    fi
    
    local LISTEN_PARAMS="-L \"mwss://${GOST_USER}:${GOST_PASSWORD}@${FORMATTED_LISTEN_IP}:${GOST_PORT}?path=/${GOST_PATH}&cert=${GOST_CERT_FILE}&key=${GOST_KEY_FILE}&probe_resist=code:404&knock=${GOST_KNOCK_DOMAIN}\""
    SERVICE_FILE_PATH="${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service"
    echo "--> 正在创建服务文件: ${SERVICE_FILE_PATH}"
    local EXEC_START_CMD="/usr/bin/gost ${LISTEN_PARAMS} ${GOST_FORWARD_PARAM}"
    cat << EOF > ${SERVICE_FILE_PATH}
[Unit]
Description=Gost Service (${SERVICE_NAME})
After=network.target
[Service]
Type=simple
ExecStart=${EXEC_START_CMD}
Restart=on-failure
RestartSec=42s
[Install]
WantedBy=multi-user.target
EOF
    echo "--> 正在重载、启动并启用服务..."
    systemctl daemon-reload
    systemctl enable "${SERVICE_PREFIX}${SERVICE_NAME}.service" > /dev/null 2>&1
    systemctl start "${SERVICE_PREFIX}${SERVICE_NAME}.service"
    echo ""
    echo "================================================="
    echo -e "      ${GREEN}服务 '${SERVICE_NAME}' 创建成功！${NC}"
    echo "================================================="
    echo "您的 Gost-MWSS 服务配置信息如下:"
    echo "  监听地址: ${YELLOW}${GOST_LISTEN_IP}${NC}"
    echo "  端口:     ${YELLOW}${GOST_PORT}${NC}"
    echo "  用户名:   ${YELLOW}${GOST_USER}${NC}"
    echo "  密码:     ${YELLOW}${GOST_PASSWORD}${NC}"
    echo "  路径:     ${YELLOW}/${GOST_PATH}${NC}"
    echo "  Knock 域名: ${YELLOW}${GOST_KNOCK_DOMAIN}${NC}"
    echo "  证书路径: ${YELLOW}${GOST_CERT_FILE}${NC}"
    echo "  密钥路径: ${YELLOW}${GOST_KEY_FILE}${NC}"
    if [ -n "$FORWARD_PROXY_ADDRESS" ]; then
        echo -e "  后置转发代理: ${YELLOW}${FORWARD_PROXY_ADDRESS}${NC}"
    else
        echo "  后置转发代理: 未配置"
    fi
    echo "-------------------------------------------------"
    echo ""
    systemctl status "${SERVICE_PREFIX}${SERVICE_NAME}.service" --no-pager
}

function modify_service() {
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi

    local SERVICE_FILE_PATH="${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service"
    if [ ! -f "$SERVICE_FILE_PATH" ]; then
        echo -e "${RED}错误: 找不到服务文件 ${SERVICE_FILE_PATH}${NC}"; return
    fi

    echo -e "${CYAN}--- 正在修改服务 '${SERVICE_NAME}' ---${NC}"
    
    # --- 1. 解析当前配置 ---
    local EXEC_LINE
    EXEC_LINE=$(grep '^ExecStart=' "$SERVICE_FILE_PATH")
    if [ -z "$EXEC_LINE" ]; then
        echo -e "${RED}错误: 无法在服务文件中找到 'ExecStart' 配置行。${NC}"; return
    fi
    
    local L_ARG_RAW
    L_ARG_RAW=$(echo "$EXEC_LINE" | grep -o '\-L "[^"]*"')
    local L_ARG=${L_ARG_RAW:4:-1}

    local CURRENT_FORWARDER=""
    if [[ "$EXEC_LINE" == *"-F "* ]]; then
        local F_ARG_RAW
        F_ARG_RAW=$(echo "$EXEC_LINE" | grep -o '\-F "[^"]*"')
        CURRENT_FORWARDER=${F_ARG_RAW:4:-1}
    fi

    local PROTO_REMOVED=${L_ARG#*//}
    local MAIN_PART=${PROTO_REMOVED%%\?*}
    local QUERY_PART=${PROTO_REMOVED#*\?}
    
    local CURRENT_USER; local CURRENT_PASS
    if [[ "$MAIN_PART" == *"@"* ]]; then
        local USER_PASS_PART=${MAIN_PART%@*}
        local HOST_PORT_PART=${MAIN_PART#*@}
        CURRENT_USER=${USER_PASS_PART%:*}
        CURRENT_PASS=${USER_PASS_PART#*:}
    else
        local HOST_PORT_PART=$MAIN_PART
        CURRENT_USER=""
        CURRENT_PASS=""
    fi

    local CURRENT_IP_RAW=${HOST_PORT_PART%:*}
    local CURRENT_PORT=${HOST_PORT_PART##*:}
    local CURRENT_IP
    if [[ "$CURRENT_IP_RAW" == "["* ]]; then
        CURRENT_IP=${CURRENT_IP_RAW:1:-1}
    else
        CURRENT_IP="$CURRENT_IP_RAW"
    fi
    
    local CURRENT_PATH=""; local CURRENT_KNOCK=""; local CURRENT_CERT=""; local CURRENT_KEY=""
    local OLD_IFS=$IFS; IFS='&'; for param in $QUERY_PART; do case "$param" in path=*) CURRENT_PATH=${param#path=/} ;; knock=*) CURRENT_KNOCK=${param#knock=} ;; cert=*) CURRENT_CERT=${param#cert=} ;; key=*) CURRENT_KEY=${param#key=} ;; esac; done; IFS=$OLD_IFS

    # --- 2. 提示用户输入新配置 (将当前值作为默认值) ---
    echo -e "${YELLOW}--- 请输入新配置 (直接回车则保留原值) ---${NC}"
    
    read -p ">> 监听 IP 地址 [当前: ${CURRENT_IP}]: " NEW_LISTEN_IP
    NEW_LISTEN_IP=${NEW_LISTEN_IP:-$CURRENT_IP}
    
    read -p ">> 用户名 [当前: ${CURRENT_USER}]: " NEW_USER
    NEW_USER=${NEW_USER:-$CURRENT_USER}
    
    read -p ">> 密码 [当前: ${CURRENT_PASS}]: " NEW_PASSWORD
    NEW_PASSWORD=${NEW_PASSWORD:-$CURRENT_PASS}
    
    read -p ">> 端口号 [当前: ${CURRENT_PORT}]: " NEW_PORT
    NEW_PORT=${NEW_PORT:-$CURRENT_PORT}
    
    read -p ">> 路径 (path) [当前: ${CURRENT_PATH}]: " NEW_PATH
    NEW_PATH=${NEW_PATH:-$CURRENT_PATH}
    
    read -p ">> Knock 域名 [当前: ${CURRENT_KNOCK}]: " NEW_KNOCK_DOMAIN
    NEW_KNOCK_DOMAIN=${NEW_KNOCK_DOMAIN:-$CURRENT_KNOCK}

    read -p ">> 证书(crt/cer)文件路径 [当前: ${CURRENT_CERT}]: " NEW_CERT_FILE
    NEW_CERT_FILE=${NEW_CERT_FILE:-$CURRENT_CERT}

    read -p ">> 密钥(key)文件路径 [当前: ${CURRENT_KEY}]: " NEW_KEY_FILE
    NEW_KEY_FILE=${NEW_KEY_FILE:-$CURRENT_KEY}
    
    read -p ">> 后置转发代理地址 (留空则删除) [当前: ${CURRENT_FORWARDER}]: " NEW_FORWARDER
    NEW_FORWARDER=${NEW_FORWARDER:-$CURRENT_FORWARDER}

    # --- 3. 重建服务文件 ---
    local NEW_FORWARD_PARAM=""
    if [ -n "$NEW_FORWARDER" ]; then
        NEW_FORWARD_PARAM="-F \"${NEW_FORWARDER}\""
    fi

    local FORMATTED_LISTEN_IP
    if [[ "$NEW_LISTEN_IP" == *":"* ]]; then
        FORMATTED_LISTEN_IP="[${NEW_LISTEN_IP}]"
    else
        FORMATTED_LISTEN_IP="${NEW_LISTEN_IP}"
    fi

    local LISTEN_PARAMS="-L \"mwss://${NEW_USER}:${NEW_PASSWORD}@${FORMATTED_LISTEN_IP}:${NEW_PORT}?path=/${NEW_PATH}&cert=${NEW_CERT_FILE}&key=${NEW_KEY_FILE}&probe_resist=code:404&knock=${NEW_KNOCK_DOMAIN}\""
    local EXEC_START_CMD="/usr/bin/gost ${LISTEN_PARAMS} ${NEW_FORWARD_PARAM}"
    
    echo "--> 正在更新服务文件: ${SERVICE_FILE_PATH}"
    cat << EOF > ${SERVICE_FILE_PATH}
[Unit]
Description=Gost Service (${SERVICE_NAME})
After=network.target
[Service]
Type=simple
ExecStart=${EXEC_START_CMD}
Restart=on-failure
RestartSec=42s
[Install]
WantedBy=multi-user.target
EOF
    
    # --- 4. 应用更改 ---
    echo "--> 正在重载 systemd 配置..."
    systemctl daemon-reload
    echo -e "${GREEN}服务 '${SERVICE_NAME}' 配置已更新！${NC}"
    
    read -p ">> 是否立即重启服务以应用新配置? [Y/n]: " CONFIRM_RESTART
    if [[ "$CONFIRM_RESTART" != "n" && "$CONFIRM_RESTART" != "N" ]]; then
        echo "--> 正在重启服务..."
        systemctl restart "${SERVICE_PREFIX}${SERVICE_NAME}.service"
        sleep 1
        echo "--> 服务状态:"
        systemctl status "${SERVICE_PREFIX}${SERVICE_NAME}.service" --no-pager
    else
        echo -e "${YELLOW}服务配置已更新，但未重启。您需要稍后手动重启才能生效。${NC}"
    fi
}

function delete_service() {
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi
    read -p ">> 你确定要永久删除服务 '${SERVICE_NAME}' 吗? 此操作不可逆！ (y/n): " CONFIRM_DELETE
    if [[ "$CONFIRM_DELETE" != "y" ]]; then echo "操作已取消。"; return; fi
    FULL_SERVICE_NAME="${SERVICE_PREFIX}${SERVICE_NAME}.service"
    echo "--> 正在停止服务: ${FULL_SERVICE_NAME}"; systemctl stop "$FULL_SERVICE_NAME"
    echo "--> 正在禁用服务: ${FULL_SERVICE_NAME}"; systemctl disable "$FULL_SERVICE_NAME" > /dev/null 2>&1
    echo "--> 正在删除服务文件..."; rm -f "${SERVICE_DIR}/${FULL_SERVICE_NAME}"
    echo "--> 正在重载 systemd..."; systemctl daemon-reload; systemctl reset-failed
    echo -e "${GREEN}服务 '${SERVICE_NAME}' 已成功删除。${NC}"
}

function manage_service() {
    local ACTION=$1
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi
    echo "--> 正在对服务 '${SERVICE_NAME}' 执行 ${ACTION} 操作..."
    systemctl "$ACTION" "${SERVICE_PREFIX}${SERVICE_NAME}.service"
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}操作成功。正在检查状态...${NC}"
    else
        echo -e "${RED}操作失败！请检查上面的错误信息或使用日志功能查看详情。${NC}"
    fi
    sleep 1
    systemctl status "${SERVICE_PREFIX}${SERVICE_NAME}.service" --no-pager
}

function manage_autostart() {
    local ACTION=$1
    local ACTION_TEXT
    if [ "$ACTION" == "enable" ]; then
        ACTION_TEXT="启用"
    else
        ACTION_TEXT="禁用"
    fi

    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi

    echo "--> 正在为服务 '${SERVICE_NAME}' ${ACTION_TEXT} 开机自启..."
    systemctl "$ACTION" "${SERVICE_PREFIX}${SERVICE_NAME}.service" > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}操作成功！服务 '${SERVICE_NAME}' 的开机自启已${ACTION_TEXT}。${NC}"
    else
        echo -e "${RED}操作失败！请检查上面的错误信息。${NC}"
    fi
    
    local enabled_status
    enabled_status=$(systemctl is-enabled "${SERVICE_PREFIX}${SERVICE_NAME}.service" 2>/dev/null)
    echo -e "--> 当前开机自启状态: ${CYAN}${enabled_status}${NC}"
}


function view_logs() {
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi
    echo -e "${YELLOW}正在加载日志... 按 Ctrl+C 退出日志查看。${NC}"
    journalctl -u "${SERVICE_PREFIX}${SERVICE_NAME}.service" -f -n 50 --no-pager
}

function update_gost_binary(){
    if [ -f /usr/bin/gost ]; then
        echo -e "${YELLOW}--> 检测到 /usr/bin/gost 已存在。此操作将覆盖它。${NC}"
        read -p ">> 是否继续? (y/n): " confirm_overwrite
        if [[ "$confirm_overwrite" != "y" ]]; then echo "操作已取消。"; return; fi
    fi
    echo ""
    echo -e "${GREEN}--> 准备安装/更新 Gost 主程序...${NC}"
    echo "------------------------------------------"
    echo "请选择 Gost 的安装方式："
    echo "  1. 自动从 GitHub API 检测最新版本"
    echo "  2. 手动粘贴 Gost 压缩包的直接下载链接"
    echo "------------------------------------------"
    read -p ">> 请输入选项 [1-2，默认: 1]: " INSTALL_CHOICE
    if [[ "$INSTALL_CHOICE" == "2" ]]; then
        read -p ">> 请粘贴下载链接: " MANUAL_DOWNLOAD_URL
        if [ -z "$MANUAL_DOWNLOAD_URL" ]; then echo -e "${RED}错误: 链接不能为空！${NC}"; return; fi
        DOWNLOAD_URL="$MANUAL_DOWNLOAD_URL"
    else
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) GOST_ARCH="amd64" ;;
            aarch64) GOST_ARCH="arm64" ;;
            *) echo -e "${RED}不支持的系统架构: $ARCH。${NC}"; return ;;
        esac
        
        API_URL="https://api.github.com/repos/go-gost/gost/releases"
        echo "--> 正在从 GitHub API (go-gost/gost) 获取最新版本信息..."
        
        DOWNLOAD_URL=$(curl -s $API_URL | jq -r --arg GOST_ARCH "$GOST_ARCH" '.[0].assets[] | select(.name | test("linux_" + $GOST_ARCH + "\\.tar\\.gz$")) | .browser_download_url')
        
        if [ -z "$DOWNLOAD_URL" ]; then echo -e "${RED}错误: 自动获取失败。请检查 API 访问或使用手动链接。${NC}"; return; fi
    fi
    
    echo -e "${GREEN}--> 已确定下载链接: ${YELLOW}${DOWNLOAD_URL}${NC}"
    TMP_DIR="/tmp/gost_install"
    mkdir -p "$TMP_DIR"
    FILENAME=$(basename "$DOWNLOAD_URL")
    echo "--> 正在下载..."
    curl -L --retry 3 -o "$TMP_DIR/$FILENAME" "$DOWNLOAD_URL"
    if [ $? -ne 0 ]; then echo -e "${RED}下载失败！${NC}"; rm -rf "$TMP_DIR"; return; fi
    
    echo "--> 正在解压安装..."
    if [[ "$FILENAME" == *.zip ]]; then
        unzip -o "$TMP_DIR/$FILENAME" -d "$TMP_DIR"
    elif [[ "$FILENAME" == *.tar.gz ]]; then
        tar -xzf "$TMP_DIR/$FILENAME" -C "$TMP_DIR"
    else
        echo -e "${RED}未知的压缩格式${NC}"; rm -rf "$TMP_DIR"; return
    fi
    
    GOST_BINARY=$(find "$TMP_DIR" -name gost -type f | head -n 1)
    if [ -z "$GOST_BINARY" ]; then echo -e "${RED}在解压文件中未找到gost程序！${NC}"; rm -rf "$TMP_DIR"; return; fi
    
    mv -f "$GOST_BINARY" /usr/bin/gost
    chmod +x /usr/bin/gost
    rm -rf "$TMP_DIR"
    
    if [ -f /usr/bin/gost ]; then
        VERSION=$(/usr/bin/gost -V 2>/dev/null)
        echo -e "${GREEN}--> Gost 更新成功！${NC}"
        echo -e "${GREEN}    版本信息: ${VERSION}${NC}"
        
        local active_services
        mapfile -t active_services < <(systemctl list-units --type=service --state=active "${SERVICE_PREFIX}*.service" --no-legend | awk '{print $1}')
        
        if [ ${#active_services[@]} -eq 0 ]; then
            echo -e "${YELLOW}未检测到正在运行的 Gost 服务，无需重启。${NC}"
        else
            echo ""
            read -p ">> 是否立即重启所有正在运行的(${#active_services[@]}个)Gost服务以应用新版本? [Y/n]: " confirm_restart_all
            if [[ "$confirm_restart_all" != "n" && "$confirm_restart_all" != "N" ]]; then
                echo "--> 正在重启所有正在运行的 Gost 服务..."
                for service_fullname in "${active_services[@]}"; do
                    local short_name=${service_fullname#"$SERVICE_PREFIX"}
                    short_name=${short_name%".service"}
                    echo -n "    -> 正在重启服务 '${short_name}'..."
                    systemctl restart "$service_fullname"
                    if [ $? -eq 0 ]; then
                        echo -e " ${GREEN}成功${NC}"
                    else
                        echo -e " ${RED}失败${NC}"
                    fi
                done
                echo -e "${GREEN}所有正在运行的 Gost 服务重启完毕。${NC}"
            else
                echo -e "${YELLOW}操作取消。请稍后手动重启服务以应用新版本。${NC}"
            fi
        fi
        
    else
        echo -e "${RED}Gost 更新失败！${NC}"
    fi
}

function apply_certificate() {
    echo -e "${CYAN}--- 申请域名证书 (Let's Encrypt) ---${NC}"
    # 1. 安装 acme.sh
    if ! command -v "$ACME_CMD" &> /dev/null; then
        echo -e "${YELLOW}检测到 acme.sh 未安装，正在为您准备安装...${NC}"
        # 检查依赖
        if ! command -v curl &> /dev/null; then
            echo -e "${RED}错误: curl 未安装，请先安装 curl (e.g., sudo apt install curl)${NC}"; return
        fi
        if ! command -v socat &> /dev/null; then
            echo -e "${YELLOW}检测到 socat 未安装，正在尝试安装...${NC}"
            if [ -f /etc/os-release ]; then . /etc/os-release; OS_ID=$ID; fi
            case "$OS_ID" in
                ubuntu|debian) apt-get update > /dev/null && apt-get install -y socat;;
                centos|rhel|fedora|rocky|almalinux) yum install -y socat;;
                *) echo -e "${RED}无法自动安装 socat，请手动安装后重试。${NC}"; return;;
            esac
        fi
        
        read -p ">> 请输入您的邮箱 (用于 acme.sh 注册和证书续期提醒): " ACME_EMAIL
        if [ -z "$ACME_EMAIL" ]; then
            echo -e "${RED}错误: 邮箱不能为空。${NC}"; return
        fi
        
        echo "--> 正在从 get.acme.sh 下载并安装 acme.sh..."
        curl https://get.acme.sh | sh -s email="$ACME_EMAIL"
        if [ $? -ne 0 ]; then
            echo -e "${RED}acme.sh 安装失败，请检查网络或错误信息。${NC}"; return
        fi
        echo -e "${GREEN}acme.sh 安装成功！${NC}"
    fi

    # 2. 获取域名
    read -p ">> 请输入要申请证书的域名 (例如: my.domain.com): " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}错误: 域名不能为空。${NC}"; return
    fi
    echo -e "${YELLOW}重要提示: 请确保域名 ${CYAN}${DOMAIN}${NC} ${YELLOW}已正确解析到本服务器的公网 IP 地址。${NC}"
    
    # 3. 检查端口占用
    if ss -lnt | grep -q ':80 '; then
        echo -e "${RED}错误: 检测到 80 端口已被占用，无法使用 standalone 模式申请证书。${NC}"
        echo -e "${RED}请先停止占用 80 端口的服务 (如 Nginx, Apache 等) 后再试。${NC}"
        return
    fi
    
    # 4. 申请证书
    echo "--> 正在为域名 ${DOMAIN} 申请证书 (standalone 模式)..."
    "$ACME_CMD" --issue -d "$DOMAIN" --standalone -k ec-256
    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败！请检查域名解析是否正确或查看上面的错误日志。${NC}"; return
    fi
    
    # 5. 安装证书到指定目录
    local CERT_DIR="/root/certs/${DOMAIN}"
    local CERT_PATH="${CERT_DIR}/fullchain.cer"
    local KEY_PATH="${CERT_DIR}/private.key"
    echo "--> 正在安装证书到 ${CERT_DIR}..."
    mkdir -p "$CERT_DIR"
    "$ACME_CMD" --install-cert -d "$DOMAIN" --ecc \
        --fullchain-file "$CERT_PATH" \
        --key-file "$KEY_PATH"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}证书安装失败！${NC}"; return
    fi

    echo ""
    echo -e "${GREEN}=====================================================${NC}"
    echo -e "${GREEN} 证书申请成功! ${NC}"
    echo -e "${GREEN}=====================================================${NC}"
    echo -e "您的证书和密钥已保存到以下路径:"
    echo -e "  ${CYAN}证书 (Cert):${NC} ${YELLOW}${CERT_PATH}${NC}"
    echo -e "  ${CYAN}密钥 (Key): ${NC} ${YELLOW}${KEY_PATH}${NC}"
    echo -e "现在您可以在添加或修改 Gost-MWSS 服务时使用以上路径了。"
    echo -e "${YELLOW}acme.sh 会自动为您处理证书的续签，无需担心过期问题。${NC}"
}

function generate_self_signed_cert() {
    echo -e "${CYAN}--- 生成自签名 SSL 证书 (OpenSSL) ---${NC}"

    # Dependency check
    if ! command -v openssl &> /dev/null; then
        echo -e "${RED}错误: openssl 工具未安装。请先安装它 (e.g., sudo apt install openssl)。${NC}"
        return
    fi

    # User input
    read -p ">> 请输入证书通用名称(CN) [默认: localhost]: " COMMON_NAME
    COMMON_NAME=${COMMON_NAME:-localhost}

    read -p ">> 请输入证书有效期(天) [默认: 3650]: " DAYS
    DAYS=${DAYS:-3650}

    read -p ">> 请输入密钥(key)文件保存路径 [默认: /root/1.key]: " KEY_PATH
    KEY_PATH=${KEY_PATH:-/root/1.key}

    read -p ">> 请输入证书(crt)文件保存路径 [默认: /root/1.crt]: " CERT_PATH
    CERT_PATH=${CERT_PATH:-/root/1.crt}

    # Check for overwrites
    if [ -f "$KEY_PATH" ] || [ -f "$CERT_PATH" ]; then
        echo -e "${YELLOW}警告: 文件 ${KEY_PATH} 或 ${CERT_PATH} 已存在。${NC}"
        read -p ">> 是否覆盖? [y/N]: " confirm_overwrite
        if [[ "$confirm_overwrite" != "y" && "$confirm_overwrite" != "Y" ]]; then
            echo -e "${YELLOW}操作已取消。${NC}"
            return
        fi
    fi

    # Generate cert
    echo "--> 正在生成证书和密钥..."
    openssl req -x509 -newkey rsa:4096 -keyout "$KEY_PATH" -out "$CERT_PATH" -days "$DAYS" -nodes -subj "/CN=${COMMON_NAME}" > /dev/null 2>&1

    if [ $? -eq 0 ] && [ -f "$KEY_PATH" ] && [ -f "$CERT_PATH" ]; then
        echo ""
        echo -e "${GREEN}=====================================================${NC}"
        echo -e "${GREEN} 自签名证书生成成功! ${NC}"
        echo -e "${GREEN}=====================================================${NC}"
        echo -e "文件已保存到以下路径:"
        echo -e "  ${CYAN}证书 (Cert):${NC} ${YELLOW}${CERT_PATH}${NC}"
        echo -e "  ${CYAN}密钥 (Key): ${NC} ${YELLOW}${KEY_PATH}${NC}"
        echo "现在您可以在添加或修改服务时使用这些路径了。"
    else
        echo -e "${RED}证书生成失败！请检查 openssl 命令或文件权限。${NC}"
    fi
}

function install_script() {
    echo -e "${CYAN}--- 安装/更新 gost-mwss 快捷命令 ---${NC}"
    local SCRIPT_PATH
    SCRIPT_PATH=$(readlink -f "$0")
    local TARGET_PATH="/usr/local/bin/gost-mwss"

    if [ "$SCRIPT_PATH" == "$TARGET_PATH" ]; then
        echo -e "${GREEN}快捷命令已经是最新的 (您正在通过它运行此脚本)。${NC}"
        return
    fi

    echo "此操作将把当前脚本复制到 ${TARGET_PATH}"
    echo "之后，您就可以在系统任何地方通过输入 'gost-mwss' 来运行此面板。"
    read -p ">> 是否继续? [Y/n]: " confirm_install

    if [[ "$confirm_install" == "n" || "$confirm_install" == "N" ]]; then
        echo -e "${YELLOW}操作已取消。${NC}"
        return
    fi

    echo "--> 正在复制脚本到 ${TARGET_PATH}..."
    cp -f "$SCRIPT_PATH" "$TARGET_PATH"
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误: 复制失败！请检查权限。${NC}"
        return
    fi

    echo "--> 正在为脚本添加可执行权限..."
    chmod +x "$TARGET_PATH"
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误: 添加可执行权限失败！${NC}"
        return
    fi

    echo ""
    echo -e "${GREEN}快捷命令 'gost-mwss' 安装/更新成功！${NC}"
    echo -e "${YELLOW}请重新打开终端，或运行 'source ~/.bashrc' (或 ~/.zshrc 等) 来让命令立即生效。${NC}"
    echo "之后，您可以随时随地输入 ${CYAN}gost-mwss${NC} 来打开此面板。"
}

function main_menu() {
    check_root
    local CORE_DEPS="grep sed awk curl openssl"
    for dep in $CORE_DEPS; do
        if ! command -v $dep &> /dev/null; then
            echo -e "${RED}致命错误: 核心工具 '${dep}' 未找到。请先安装它。${NC}"; exit 1
        fi
    done
    if ! command -v jq &> /dev/null; then
       echo -e "${YELLOW}首次运行，正在安装核心依赖 'jq'...${NC}"
       if [ -f /etc/os-release ]; then . /etc/os-release; OS_ID=$ID; fi
       case "$OS_ID" in
           ubuntu|debian) apt-get update > /dev/null && apt-get install -y jq;;
           centos|rhel|fedora|rocky|almalinux) yum install -y jq;;
           *) echo -e "${RED}无法自动安装jq。请根据您的系统手动安装 (例如: sudo apt install jq)。${NC}";;
       esac
    fi
    while true; do
        clear
        echo "=========================================="
        echo "      Gost-MWSS 多服务管理脚本 v1.0"
        echo "=========================================="
        
        local GOST_VERSION
        if [ -x /usr/bin/gost ]; then
            GOST_VERSION=$(/usr/bin/gost -V 2>/dev/null)
        fi
        
        if [ -n "$GOST_VERSION" ]; then
            echo -e "  当前 Gost 版本: ${GREEN}${GOST_VERSION}${NC}"
        else
            echo -e "  当前 Gost 版本: ${RED}未安装 (请使用选项 13 安装)${NC}"
        fi
        echo "=========================================="

        list_services_for_menu
        echo ""
        echo -e "${GREEN}请选择要执行的操作:${NC}"
        echo "  1. 添加新的 Gost-MWSS 服务"
        echo "  2. 查看服务详细配置"
        echo "  3. 修改服务配置"
        echo "  ----------------------------------------"
        echo "  4. 启动指定的 Gost-MWSS 服务"
        echo "  5. 停止指定的 Gost-MWSS 服务"
        echo "  6. 重启指定的 Gost-MWSS 服务"
        echo "  7. 启用服务开机自启"
        echo "  8. 禁用服务开机自启"
        echo "  ----------------------------------------"
        echo "  9. 查看指定服务的日志"
        echo "  10. 删除指定的 Gost-MWSS 服务"
        echo "  11. 申请域名证书 (Let's Encrypt)"
        echo "  12. 生成自签名证书 (OpenSSL)"
        echo "  13. 更新 Gost 主程序 (影响所有服务)"
        echo "  14. 安装/更新快捷命令"
        echo "  15. 退出脚本"
        echo "=========================================="
        read -p "请输入选项 [1-15]: " choice
        case $choice in
            1) add_new_service ;;
            2) view_service_details ;;
            3) modify_service ;;
            4) manage_service "start" ;;
            5) manage_service "stop" ;;
            6) manage_service "restart" ;;
            7) manage_autostart "enable" ;;
            8) manage_autostart "disable" ;;
            9) view_logs ;;
            10) delete_service ;;
            11) apply_certificate ;;
            12) generate_self_signed_cert ;;
            13) update_gost_binary ;;
            14) install_script ;;
            15) echo "退出脚本。"; exit 0 ;;
            *) echo -e "${RED}无效的选项，请重新输入。${NC}" ;;
        esac
        echo ""
        read -p "按 Enter键 返回主菜单..."
    done
}

# --- 脚本入口 ---
main_menu
