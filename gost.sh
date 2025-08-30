#!/bin/bash

# --- 脚本信息 ---
# 名称: Gost-Generic 多服务管理脚本
# 版本: v3.3 (增加使用示例)
# 更新: 采用更强力的双重过滤逻辑，确保在任何情况下都能准确排除不应管理的服务。
#       增加了对所有服务配置的备份和恢复功能。
#       修正了恢复配置后服务未被设置为开机自启的问题。
#       增加了自定义备份与恢复目录的功能。
#       在添加和修改服务时，显示来自官方文档 (gost.run) 的常用示例。
# =================================================

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 全局变量 ---
SERVICE_PREFIX="gost_"
# 定义要明确排除的服务名前缀
EXCLUDE_PREFIX="mwss_gost_"
SERVICE_DIR="/etc/systemd/system"
ACME_CMD="$HOME/.acme.sh/acme.sh"

# --- 函数定义 ---
function check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误: 此脚本必须以 root 用户权限运行。${NC}"; exit 1
    fi
}

# --- [新功能] 显示Gost使用方法 ---
function display_gost_usage_examples() {
    local type=$1
    echo -e "${CYAN}--- 常用Gost配置示例 (参考: https://gost.run) ---${NC}"
    if [[ "$type" == "L" || "$type" == "all" ]]; then
        echo -e "${YELLOW}# 监听 (-L) 示例:${NC}"
        echo -e "  - ${GREEN}SOCKS5 代理 (无认证):${NC} socks5://:1080"
        echo -e "  - ${GREEN}SOCKS5 代理 (用户认证):${NC} socks5://user:pass@:1080"
        echo -e "  - ${GREEN}HTTP 代理:${NC} http://:8080"
        echo -e "  - ${GREEN}Shadowsocks (ss):${NC} ss://aes-256-gcm:password@:8338"
        echo -e "  - ${GREEN}本地TCP端口转发 (本机1234端口 -> 目标8080端口):${NC} forward+tcp://:1234/127.0.0.1:8080"
        echo -e "  - ${GREEN}TLS 隧道 (例如 wss):${NC} ws://:443?path=/ws&cert=/path/to/cert.pem&key=/path/to/key.pem"
        echo -e "  - ${GREEN}SNI 代理:${NC} sni://:443?host=example.com&cert=/path/to/cert.pem&key=/path/to/key.pem"
    fi
    if [[ "$type" == "F" || "$type" == "all" ]]; then
        echo -e "${YELLOW}# 转发 (-F) 示例 (用于构建转发链):${NC}"
        echo -e "  - ${GREEN}通过 SOCKS5 节点转发:${NC} socks5://1.2.3.4:1080"
        echo -e "  - ${GREEN}通过 HTTP 节点转发:${NC} http://user:pass@1.2.3.4:8080"
        echo -e "  - ${GREEN}通过 Shadowsocks 节点转发:${NC} ss://aes-128-cfb:password@1.2.3.4:8338"
        echo -e "  - ${GREEN}通过 TLS 隧道转发:${NC} wss://example.com/ws"
    fi
    echo "---------------------------------------------------------"
}


function list_services_for_menu() {
    echo -e "${CYAN}--- 当前已配置的 Gost 服务 ---${NC}"
    
    local service_files
    # 修改：采用更强的双重过滤逻辑
    mapfile -t service_files < <(systemctl list-units --type=service --all "*.service" --no-legend | awk '{print $1}' | grep "^${SERVICE_PREFIX}" | grep -v "^${EXCLUDE_PREFIX}")

    if [ ${#service_files[@]} -eq 0 ]; then
        echo "未找到任何 Gost 服务。"
    else
        printf "%-25s %-20s %-20s\n" "服务名 (NAME)" "运行状态 (STATUS)" "开机自启 (ENABLED)"
        echo "-----------------------------------------------------------------"
        for service_fullname in "${service_files[@]}"; do
            local active_status
            active_status=$(systemctl show -p ActiveState --value "$service_fullname")
            local enabled_status
            enabled_status=$(systemctl is-enabled "$service_fullname" 2>/dev/null)

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
            
            printf "%-25s %-20b %-20b\n" "$short_name" "$display_active" "$display_enabled"
        done
    fi
    echo "-----------------------------------------------------------------"
}

function select_service() {
    echo -e "${CYAN}--- 请选择要操作的服务 ---${NC}" >&2
    local services_list
    # 修改：采用更强的双重过滤逻辑
    mapfile -t services_list < <(systemctl list-units --type=service --all "*.service" --no-legend | awk '{print $1}' | grep "^${SERVICE_PREFIX}" | grep -v "^${EXCLUDE_PREFIX}")

    if [ ${#services_list[@]} -eq 0 ]; then
        echo -e "${RED}未找到任何可操作的 Gost 服务。${NC}" >&2
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
    done < /dev/tty
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
    local GOST_CMD=${EXEC_LINE#*=}

    echo "-------------------------------------------------"
    echo "监听配置 (-L):"
    if echo "$GOST_CMD" | grep -q -- '-L[ =]'; then
        echo "$GOST_CMD" | grep -o -- '-L[ =]"[^"]*"' | while read -r line; do
            echo -e "  ${YELLOW}${line}${NC}"
        done
    else
        echo "  未配置"
    fi

    echo "转发配置 (-F):"
    if echo "$GOST_CMD" | grep -q -- '-F[ =]'; then
        echo "$GOST_CMD" | grep -o -- '-F[ =]"[^"]*"' | while read -r line; do
            echo -e "  ${YELLOW}${line}${NC}"
        done
    else
        echo "  未配置"
    fi
    echo "-------------------------------------------------"
    echo -e "完整的启动命令:"
    echo -e "${CYAN}${GOST_CMD}${NC}"
    echo "-------------------------------------------------"
}

function add_new_service() {
    echo -e "${CYAN}--- 添加新的 Gost 服务 ---${NC}"
    read -p ">> 请输入一个唯一的服务名称 (例如: my_proxy): " SERVICE_NAME < /dev/tty
    if [ -z "$SERVICE_NAME" ]; then echo -e "${RED}错误: 服务名称不能为空。${NC}"; return; fi
    if [[ ! "$SERVICE_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then echo -e "${RED}错误: 服务名称只能包含字母、数字、下划线和连字符。${NC}"; return; fi
    if [ -f "${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service" ]; then echo -e "${RED}错误: 名为 '${SERVICE_NAME}' 的服务已存在。${NC}"; return; fi
    # 增加对排除前缀的判断
    if [[ -n "${EXCLUDE_PREFIX}" && "${SERVICE_PREFIX}${SERVICE_NAME}" == ${EXCLUDE_PREFIX}* ]]; then
        echo -e "${RED}错误: 此服务名 (${SERVICE_PREFIX}${SERVICE_NAME}) 属于被排除的格式，无法创建。${NC}"; return;
    fi
    
    local GOST_LISTEN_ARGS=""
    echo ""
    echo -e "${YELLOW}--- 配置 Gost 监听 (-L) ---${NC}"
    echo "您现在将逐一添加监听配置。"
    
    display_gost_usage_examples "L"

    while true; do
        read -p ">> 请输入一个监听配置 (例如: socks5://:1080), 或直接回车完成添加: " listen_conf < /dev/tty
        if [ -z "$listen_conf" ]; then
            if [ -z "$GOST_LISTEN_ARGS" ]; then
                echo -e "${RED}错误: 至少需要一个监听配置。${NC}"
                continue
            else
                break
            fi
        fi
        GOST_LISTEN_ARGS+=" -L=\"${listen_conf}\""
        read -p ">> 是否继续添加下一个监听配置? [Y/n]: " add_more < /dev/tty
        if [[ "$add_more" == "n" || "$add_more" == "N" ]]; then
            break
        fi
    done

    local GOST_FORWARD_ARGS=""
    echo ""
    echo -e "${YELLOW}--- 配置 Gost 转发 (-F) (可选) ---${NC}"
    echo "如果需要，您现在可以逐一添加后置转发代理，构建转发链。"
    
    display_gost_usage_examples "F"

    while true; do
        read -p ">> 请输入一个转发配置 (例如: socks5://1.2.3.4:1080), 或直接回车跳过: " forward_conf < /dev/tty
        if [ -z "$forward_conf" ]; then
            break
        fi
        GOST_FORWARD_ARGS+=" -F=\"${forward_conf}\""
        read -p ">> 是否继续添加下一个转发配置 (构建转发链)? [Y/n]: " add_more < /dev/tty
        if [[ "$add_more" == "n" || "$add_more" == "N" ]]; then
            break
        fi
    done
    
    SERVICE_FILE_PATH="${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service"
    echo "--> 正在创建服务文件: ${SERVICE_FILE_PATH}"
    
    local EXEC_START_CMD="/usr/bin/gost $(echo "${GOST_LISTEN_ARGS}${GOST_FORWARD_ARGS}" | sed 's/^[ \t]*//')"
    
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
    echo -e "         ${GREEN}服务 '${SERVICE_NAME}' 创建成功！${NC}"
    echo "================================================="
    echo "服务的启动命令配置如下:"
    echo -e "${CYAN}${EXEC_START_CMD}${NC}"
    echo "-------------------------------------------------"
    echo ""
    systemctl status "${SERVICE_PREFIX}${SERVICE_NAME}.service" --no-pager
}

# --- [功能已改进] ---
function modify_service() {
    local SERVICE_NAME
    SERVICE_NAME=$(select_service)
    if [ $? -ne 0 ]; then echo -e "${YELLOW}操作已取消。${NC}"; return; fi

    local SERVICE_FILE_PATH="${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service"
    if [ ! -f "$SERVICE_FILE_PATH" ]; then
        echo -e "${RED}错误: 找不到服务文件 ${SERVICE_FILE_PATH}${NC}"; return
    fi

    echo -e "${CYAN}--- 正在修改服务 '${SERVICE_NAME}' ---${NC}"
    
    # 1. 解析当前的配置
    local EXEC_LINE=$(grep '^ExecStart=' "$SERVICE_FILE_PATH")
    local GOST_CMD=${EXEC_LINE#*/usr/bin/gost }
    local CURRENT_LISTEN_ARGS_STR=$(echo "$GOST_CMD" | grep -o -- '-L[ =]"[^"]*"' | tr '\n' ' ' | sed 's/ *$//')
    local CURRENT_FORWARD_ARGS_STR=$(echo "$GOST_CMD" | grep -o -- '-F[ =]"[^"]*"' | tr '\n' ' ' | sed 's/ *$//')

    echo "当前配置如下:"
    view_service_details "$SERVICE_NAME"
    echo "-------------------------------------------------"

    # 2. 交互式修改监听配置 (-L)
    echo -e "${YELLOW}--- 开始交互式编辑【监听配置】(-L) ---${NC}"
    
    local current_listens=()
    mapfile -t current_listens < <(echo "$GOST_CMD" | grep -o -- '-L[ =]"[^"]*"' | sed -e 's/^-L[ =]//' -e 's/"//g')

    while true; do
        clear
        echo -e "${CYAN}--- 当前监听配置 ---${NC}"
        if [ ${#current_listens[@]} -eq 0 ]; then
            echo "  (当前为空)"
        else
            for i in "${!current_listens[@]}"; do
                echo -e "  [${GREEN}$((i+1))${NC}] ${YELLOW}${current_listens[$i]}${NC}"
            done
        fi
        echo "-------------------------------------------------"
        echo -e "请选择操作:"
        echo -e "  [${GREEN}A${NC}]dd    - 在末尾添加"
        echo -e "  [${GREEN}I${NC}]nsert - 在指定位置前后插入"
        echo -e "  [${GREEN}M${NC}]odify - 修改指定项"
        echo -e "  [${GREEN}D${NC}]elete - 删除指定项"
        echo -e "  [${GREEN}C${NC}]lear  - 清空所有"
        echo -e "  [${GREEN}F${NC}]inish - 完成编辑"
        echo "-------------------------------------------------"
        read -p ">> 请输入选项 [A/I/M/D/C/F]: " listen_choice < /dev/tty

        case $listen_choice in
            a|A)
                display_gost_usage_examples "L"; read -p ">> 请输入要添加到末尾的监听配置: " new_listen
                if [ -n "$new_listen" ]; then current_listens+=("$new_listen"); echo -e "${GREEN}添加成功！${NC}"; else echo -e "${RED}输入为空，未添加。${NC}"; fi; sleep 1;;
            i|I)
                if [ ${#current_listens[@]} -eq 0 ]; then echo -e "${YELLOW}列表为空，请使用 [A]dd 添加第一项。${NC}"; sleep 2; continue; fi
                display_gost_usage_examples "L"; read -p ">> 请输入要插入的新监听配置: " new_listen
                if [ -z "$new_listen" ]; then echo -e "${RED}输入为空，操作取消。${NC}"; sleep 1; continue; fi
                read -p ">> 请输入要参照的序号 [1-${#current_listens[@]}]: " index
                if ! [[ "$index" =~ ^[0-9]+$ ]] || [ "$index" -lt 1 ] || [ "$index" -gt ${#current_listens[@]} ]; then echo -e "${RED}无效的序号。${NC}"; sleep 1; continue; fi
                read -p ">> 在序号 ${index} [B]efore (之前) 或 [A]fter (之后) 插入? [B/A]: " position
                local real_index=$((index - 1))
                case $position in
                    b|B)
                        current_listens=("${current_listens[@]:0:$real_index}" "$new_listen" "${current_listens[@]:$real_index}")
                        echo -e "${GREEN}已在序号 ${index} 之前插入。${NC}";;
                    a|A)
                        ((real_index++))
                        current_listens=("${current_listens[@]:0:$real_index}" "$new_listen" "${current_listens[@]:$real_index}")
                        echo -e "${GREEN}已在序号 ${index} 之后插入。${NC}";;
                    *)
                        echo -e "${RED}无效的选择，操作取消。${NC}";;
                esac; sleep 1;;
            m|M)
                if [ ${#current_listens[@]} -eq 0 ]; then echo -e "${RED}当前没有可修改的配置。${NC}"; sleep 1; continue; fi
                read -p ">> 请输入要修改的配置序号 [1-${#current_listens[@]}]: " mod_index
                if [[ "$mod_index" =~ ^[0-9]+$ ]] && [ "$mod_index" -ge 1 ] && [ "$mod_index" -le ${#current_listens[@]} ]; then
                    local real_index=$((mod_index - 1))
                    echo -e "当前值: ${YELLOW}${current_listens[$real_index]}${NC}"
                    display_gost_usage_examples "L"; read -p ">> 请输入新的配置内容: " new_value
                    if [ -n "$new_value" ]; then current_listens[$real_index]="$new_value"; echo -e "${GREEN}修改成功！${NC}"; else echo -e "${RED}输入为空，未修改。${NC}"; fi
                else
                    echo -e "${RED}无效的序号。${NC}"
                fi; sleep 1;;
            d|D)
                if [ ${#current_listens[@]} -eq 0 ]; then echo -e "${RED}当前没有可删除的配置。${NC}"; sleep 1; continue; fi
                read -p ">> 请输入要删除的配置序号 [1-${#current_listens[@]}]: " del_index
                if [[ "$del_index" =~ ^[0-9]+$ ]] && [ "$del_index" -ge 1 ] && [ "$del_index" -le ${#current_listens[@]} ]; then
                    local real_index=$((del_index - 1))
                    unset 'current_listens[$real_index]'; current_listens=("${current_listens[@]}")
                    echo -e "${GREEN}删除成功！${NC}"
                else
                    echo -e "${RED}无效的序号。${NC}"
                fi; sleep 1;;
            c|C)
                read -p ">> 确定要清空所有监听配置吗? (服务将无法启动) [y/N]: " confirm_clear < /dev/tty
                if [[ "$confirm_clear" == "y" || "$confirm_clear" == "Y" ]]; then current_listens=(); echo -e "${GREEN}所有监听配置已清空。${NC}"; else echo -e "${YELLOW}操作已取消。${NC}"; fi; sleep 1;;
            f|F)
                if [ ${#current_listens[@]} -eq 0 ]; then
                    echo -e "${RED}错误: 至少需要一个监听配置才能完成。${NC}"; sleep 2; continue
                fi
                echo "完成监听配置编辑。"
                break;;
            *)
                echo -e "${RED}无效的输入。${NC}"; sleep 1;;
        esac
    done

    # 3. 交互式修改转发配置 (-F)
    echo ""
    echo -e "${YELLOW}--- 开始交互式编辑【转发配置】(-F) ---${NC}"
    
    local current_forwards=()
    mapfile -t current_forwards < <(echo "$GOST_CMD" | grep -o -- '-F="[^"]*"' | sed -e 's/^-F=//' -e 's/"//g')

    while true; do
        clear
        echo -e "${CYAN}--- 当前转发链配置 ---${NC}"
        if [ ${#current_forwards[@]} -eq 0 ]; then
            echo "  (当前为空)"
        else
            for i in "${!current_forwards[@]}"; do
                echo -e "  [${GREEN}$((i+1))${NC}] ${YELLOW}${current_forwards[$i]}${NC}"
            done
        fi
        echo "-------------------------------------------------"
        echo -e "请选择操作:"
        echo -e "  [${GREEN}A${NC}]dd    - 在链条末尾添加"
        echo -e "  [${GREEN}I${NC}]nsert - 在指定位置前后插入"
        echo -e "  [${GREEN}M${NC}]odify - 修改指定项"
        echo -e "  [${GREEN}D${NC}]elete - 删除指定项"
        echo -e "  [${GREEN}C${NC}]lear  - 清空所有"
        echo -e "  [${GREEN}F${NC}]inish - 完成编辑"
        echo "-------------------------------------------------"
        read -p ">> 请输入选项 [A/I/M/D/C/F]: " forward_choice < /dev/tty

        case $forward_choice in
            a|A)
                display_gost_usage_examples "F"; read -p ">> 请输入要添加到末尾的转发配置: " new_forward
                if [ -n "$new_forward" ]; then current_forwards+=("$new_forward"); echo -e "${GREEN}添加成功！${NC}"; else echo -e "${RED}输入为空，未添加。${NC}"; fi; sleep 1;;
            i|I)
                if [ ${#current_forwards[@]} -eq 0 ]; then echo -e "${YELLOW}列表为空，请使用 [A]dd 添加第一项。${NC}"; sleep 2; continue; fi
                display_gost_usage_examples "F"; read -p ">> 请输入要插入的新转发配置: " new_forward
                if [ -z "$new_forward" ]; then echo -e "${RED}输入为空，操作取消。${NC}"; sleep 1; continue; fi
                read -p ">> 请输入要参照的序号 [1-${#current_forwards[@]}]: " index
                if ! [[ "$index" =~ ^[0-9]+$ ]] || [ "$index" -lt 1 ] || [ "$index" -gt ${#current_forwards[@]} ]; then echo -e "${RED}无效的序号。${NC}"; sleep 1; continue; fi
                read -p ">> 在序号 ${index} [B]efore (之前) 或 [A]fter (之后) 插入? [B/A]: " position
                local real_index=$((index - 1))
                case $position in
                    b|B)
                        current_forwards=("${current_forwards[@]:0:$real_index}" "$new_forward" "${current_forwards[@]:$real_index}")
                        echo -e "${GREEN}已在序号 ${index} 之前插入。${NC}";;
                    a|A)
                        ((real_index++))
                        current_forwards=("${current_forwards[@]:0:$real_index}" "$new_forward" "${current_forwards[@]:$real_index}")
                        echo -e "${GREEN}已在序号 ${index} 之后插入。${NC}";;
                    *)
                        echo -e "${RED}无效的选择，操作取消。${NC}";;
                esac; sleep 1;;
            m|M)
                if [ ${#current_forwards[@]} -eq 0 ]; then echo -e "${RED}当前没有可修改的配置。${NC}"; sleep 1; continue; fi
                read -p ">> 请输入要修改的配置序号 [1-${#current_forwards[@]}]: " mod_index
                if [[ "$mod_index" =~ ^[0-9]+$ ]] && [ "$mod_index" -ge 1 ] && [ "$mod_index" -le ${#current_forwards[@]} ]; then
                    local real_index=$((mod_index - 1))
                    echo -e "当前值: ${YELLOW}${current_forwards[$real_index]}${NC}"
                    display_gost_usage_examples "F"; read -p ">> 请输入新的配置内容: " new_value
                    if [ -n "$new_value" ]; then current_forwards[$real_index]="$new_value"; echo -e "${GREEN}修改成功！${NC}"; else echo -e "${RED}输入为空，未修改。${NC}"; fi
                else
                    echo -e "${RED}无效的序号。${NC}";
                fi; sleep 1;;
            d|D)
                if [ ${#current_forwards[@]} -eq 0 ]; then echo -e "${RED}当前没有可删除的配置。${NC}"; sleep 1; continue; fi
                read -p ">> 请输入要删除的配置序号 [1-${#current_forwards[@]}]: " del_index
                if [[ "$del_index" =~ ^[0-9]+$ ]] && [ "$del_index" -ge 1 ] && [ "$del_index" -le ${#current_forwards[@]} ]; then
                    local real_index=$((del_index - 1))
                    unset 'current_forwards[$real_index]'; current_forwards=("${current_forwards[@]}")
                    echo -e "${GREEN}删除成功！${NC}"
                else
                    echo -e "${RED}无效的序号。${NC}"
                fi; sleep 1;;
            c|C)
                read -p ">> 确定要清空所有转发配置吗? [y/N]: " confirm_clear < /dev/tty
                if [[ "$confirm_clear" == "y" || "$confirm_clear" == "Y" ]]; then current_forwards=(); echo -e "${GREEN}所有转发配置已清空。${NC}"; else echo -e "${YELLOW}操作已取消。${NC}"; fi; sleep 1;;
            f|F)
                echo "完成转发配置编辑。"
                break;;
            *)
                echo -e "${RED}无效的输入。${NC}"; sleep 1;;
        esac
    done

    # 从编辑后的数组重新构建参数字符串
    local GOST_LISTEN_ARGS=""
    for listen_conf in "${current_listens[@]}"; do
        GOST_LISTEN_ARGS+=" -L=\"${listen_conf}\""
    done
    local GOST_FORWARD_ARGS=""
    for forward_conf in "${current_forwards[@]}"; do
        GOST_FORWARD_ARGS+=" -F=\"${forward_conf}\""
    done

    # 4. 检查是否有变动
    local ARGS_PART_NEW=$(echo "${GOST_LISTEN_ARGS} ${GOST_FORWARD_ARGS}" | xargs)
    local ARGS_PART_CURRENT=$(echo "${CURRENT_LISTEN_ARGS_STR} ${CURRENT_FORWARD_ARGS_STR}" | xargs)

    if [[ "$ARGS_PART_NEW" == "$ARGS_PART_CURRENT" ]]; then
        echo ""
        echo -e "${YELLOW}配置未发生任何变化，已取消操作。${NC}"
        return
    fi

    # 5. 重建并应用配置
    local EXEC_START_CMD="/usr/bin/gost $(echo "${GOST_LISTEN_ARGS}${GOST_FORWARD_ARGS}" | sed 's/^[ \t]*//')"
    
    echo ""
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
    
    echo "--> 正在重载 systemd 配置..."
    systemctl daemon-reload
    echo -e "${GREEN}服务 '${SERVICE_NAME}' 配置已更新！${NC}"
    
    read -p ">> 是否立即重启服务以应用新配置? [Y/n]: " CONFIRM_RESTART < /dev/tty
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
    read -p ">> 你确定要永久删除服务 '${SERVICE_NAME}' 吗? 此操作不可逆！ (y/n): " CONFIRM_DELETE < /dev/tty
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

# --- [新功能] 备份与恢复 ---
function backup_services() {
    echo -e "${CYAN}--- 备份 Gost 服务配置 ---${NC}"
    
    local user_backup_dir
    read -p ">> 请输入备份文件要保存的目录 [默认: /root/gost]: " user_backup_dir < /dev/tty
    local BACKUP_DIR=${user_backup_dir:-/root/gost}

    echo "--> 正在确保备份目录存在: ${BACKUP_DIR}"
    mkdir -p "$BACKUP_DIR"
    if [ $? -ne 0 ]; then
        echo -e "${RED}错误: 无法创建备份目录 ${BACKUP_DIR}。请检查权限。${NC}"
        return
    fi

    # 查找要备份的服务文件
    local service_files_full_path
    mapfile -t service_files_full_path < <(find "${SERVICE_DIR}" -maxdepth 1 -name "${SERVICE_PREFIX}*.service" ! -name "${EXCLUDE_PREFIX}*.service")

    if [ ${#service_files_full_path[@]} -eq 0 ]; then
        echo -e "${YELLOW}未找到任何可备份的 Gost 服务配置。${NC}"
        return
    fi

    local service_files=()
    for file_path in "${service_files_full_path[@]}"; do
        service_files+=("$(basename "$file_path")")
    done

    echo "将要备份以下服务配置:"
    for service_file in "${service_files[@]}"; do
        echo -e " - ${YELLOW}${service_file}${NC}"
    done
    echo ""

    local BACKUP_FILENAME="gost-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    local BACKUP_FILE_PATH="${BACKUP_DIR}/${BACKUP_FILENAME}"

    echo "--> 正在创建备份文件: ${BACKUP_FILE_PATH}"
    # 使用 -C 选项来避免在压缩包中包含完整路径
    tar -czf "$BACKUP_FILE_PATH" -C "$SERVICE_DIR" "${service_files[@]}"

    if [ $? -eq 0 ] && [ -f "$BACKUP_FILE_PATH" ]; then
        echo -e "${GREEN}备份成功！文件已保存至 ${CYAN}${BACKUP_FILE_PATH}${NC}"
    else
        echo -e "${RED}备份失败！${NC}"
    fi
}

function restore_services() {
    echo -e "${CYAN}--- 从备份恢复 Gost 服务配置 ---${NC}"
    
    local user_backup_dir
    read -p ">> 请输入备份文件所在的目录 [默认: /root/gost]: " user_backup_dir < /dev/tty
    local BACKUP_DIR=${user_backup_dir:-/root/gost}
    
    if [ ! -d "$BACKUP_DIR" ]; then
        echo -e "${RED}错误: 备份目录 ${BACKUP_DIR} 不存在。${NC}"
        return
    fi

    local backup_files
    mapfile -t backup_files < <(find "$BACKUP_DIR" -maxdepth 1 -name "gost-*.tar.gz" -printf "%f\n" | sort -r)

    if [ ${#backup_files[@]} -eq 0 ]; then
        echo -e "${RED}未在 ${BACKUP_DIR} 目录中找到任何 'gost' 前缀的备份文件。${NC}"
        return
    fi

    echo -e "${CYAN}--- 请选择要恢复的备份文件 ---${NC}"
    select backup_filename in "${backup_files[@]}" "返回上一级"; do
        case "$backup_filename" in
            "返回上一级")
                echo -e "${YELLOW}操作已取消。${NC}"
                return
                ;;
            "")
                echo -e "${RED}无效的输入，请输入列表中的数字。${NC}"
                ;;
            *)
                local full_backup_path="${BACKUP_DIR}/${backup_filename}"
                echo -e "你选择了恢复备份: ${YELLOW}${backup_filename}${NC}"
                read -p ">> 此操作将覆盖现有的同名服务配置，是否继续? [y/N]: " confirm_restore < /dev/tty
                if [[ "$confirm_restore" != "y" && "$confirm_restore" != "Y" ]]; then
                    echo -e "${YELLOW}操作已取消。${NC}"
                    return
                fi

                echo "--> 正在解压备份文件到 ${SERVICE_DIR}..."
                tar -xzf "$full_backup_path" -C "$SERVICE_DIR"
                if [ $? -ne 0 ]; then
                    echo -e "${RED}恢复失败！解压过程中发生错误。${NC}"
                    return
                fi

                echo "--> 正在重载 systemd 配置..."
                systemctl daemon-reload
                echo -e "${GREEN}配置恢复成功！${NC}"

                local restored_services
                mapfile -t restored_services < <(tar -tf "$full_backup_path")

                if [ ${#restored_services[@]} -gt 0 ]; then
                    # --- [修正] 增加启用开机自启的步骤 ---
                    read -p ">> 是否为所有已恢复的服务 (${#restored_services[@]}个) 启用开机自启? [Y/n]: " confirm_enable_all < /dev/tty
                    if [[ "$confirm_enable_all" != "n" && "$confirm_enable_all" != "N" ]]; then
                        echo "--> 正在启用已恢复服务的开机自启..."
                        for service_file in "${restored_services[@]}"; do
                            echo -n "    -> 正在启用 '${service_file}'..."
                            systemctl enable "$service_file" > /dev/null 2>&1
                            if [ $? -eq 0 ]; then
                                echo -e " ${GREEN}成功${NC}"
                            else
                                echo -e " ${RED}失败${NC}"
                            fi
                        done
                        echo -e "${GREEN}所有已恢复服务的开机自启已启用。${NC}"
                    else
                        echo -e "${YELLOW}未启用开机自启。服务在下次系统重启后将不会自动启动。${NC}"
                    fi
                    
                    echo ""
                    read -p ">> 是否立即重启所有已恢复的服务 (${#restored_services[@]}个)? [Y/n]: " confirm_restart_all < /dev/tty
                    if [[ "$confirm_restart_all" != "n" && "$confirm_restart_all" != "N" ]]; then
                        echo "--> 正在重启已恢复的服务..."
                        for service_file in "${restored_services[@]}"; do
                            echo -n "    -> 正在重启 '${service_file}'..."
                            systemctl restart "$service_file"
                            if [ $? -eq 0 ]; then
                                echo -e " ${GREEN}成功${NC}"
                            else
                                echo -e " ${RED}失败${NC}"
                            fi
                        done
                        echo -e "${GREEN}所有已恢复的服务重启完毕。${NC}"
                    else
                        echo -e "${YELLOW}操作完成，但未重启服务。请稍后手动重启。${NC}"
                    fi
                fi
                return
                ;;
        esac
    done < /dev/tty
}

function update_gost_binary(){
    if [ -f /usr/bin/gost ]; then
        echo -e "${YELLOW}--> 检测到 /usr/bin/gost 已存在。此操作将覆盖它。${NC}"
        read -p ">> 是否继续? (y/n): " confirm_overwrite < /dev/tty
        if [[ "$confirm_overwrite" != "y" ]]; then echo "操作已取消。"; return; fi
    fi
    echo ""
    echo -e "${GREEN}--> 准备安装/更新 Gost 主程序...${NC}"
    echo "------------------------------------------"
    echo "请选择 Gost 的安装方式："
    echo "  1. 自动从 GitHub API 检测最新版本"
    echo "  2. 手动粘贴 Gost 压缩包的直接下载链接"
    echo "------------------------------------------"
    read -p ">> 请输入选项 [1-2，默认: 1]: " INSTALL_CHOICE < /dev/tty
    if [[ "$INSTALL_CHOICE" == "2" ]]; then
        read -p ">> 请粘贴下载链接: " MANUAL_DOWNLOAD_URL < /dev/tty
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
        # 修改：采用更强的双重过滤逻辑
        mapfile -t active_services < <(systemctl list-units --type=service --state=active "*.service" --no-legend | awk '{print $1}' | grep "^${SERVICE_PREFIX}" | grep -v "^${EXCLUDE_PREFIX}")
        
        if [ ${#active_services[@]} -eq 0 ]; then
            echo -e "${YELLOW}未检测到正在运行的 Gost 服务，无需重启。${NC}"
        else
            echo ""
            read -p ">> 是否立即重启所有正在运行的(${#active_services[@]}个)Gost服务以应用新版本? [Y/n]: " confirm_restart_all < /dev/tty
            if [[ "$confirm_restart_all" != "n" && "$confirm_restart_all" != "N" ]]; then
                echo "--> 正在重启所有正在运行的 Gost 服务..."
                for service_fullname in "${active_services[@]}"; do
                    local short_name=${service_fullname#"$SERVICE_PREFIX"}
                    short_name=${short_name%".service"}
                    echo -n "               -> 正在重启服务 '${short_name}'..."
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
    if ! command -v "$ACME_CMD" &> /dev/null; then
        echo -e "${YELLOW}检测到 acme.sh 未安装，正在为您准备安装...${NC}"
        read -p ">> 请输入您的邮箱 (用于 acme.sh 注册和证书续期提醒): " ACME_EMAIL < /dev/tty
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

    read -p ">> 请输入要申请证书的域名 (例如: my.domain.com): " DOMAIN < /dev/tty
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}错误: 域名不能为空。${NC}"; return
    fi
    echo -e "${YELLOW}重要提示: 请确保域名 ${CYAN}${DOMAIN}${NC} ${YELLOW}已正确解析到本服务器的公网 IP 地址。${NC}"
    
    if ss -lnt | grep -q ':80 '; then
        echo -e "${RED}错误: 检测到 80 端口已被占用，无法使用 standalone 模式申请证书。${NC}"
        echo -e "${RED}请先停止占用 80 端口的服务 (如 Nginx, Apache 等) 后再试。${NC}"
        return
    fi
    
    echo "--> 正在为域名 ${DOMAIN} 申请证书 (standalone 模式)..."
    "$ACME_CMD" --issue -d "$DOMAIN" --standalone -k ec-256
    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败！请检查域名解析是否正确或查看上面的错误日志。${NC}"; return
    fi
    
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
    echo -e "现在您可以在配置需要 TLS 的 Gost 服务时使用以上路径了。"
    echo -e "${YELLOW}acme.sh 会自动为您处理证书的续签，无需担心过期问题。${NC}"
}

function generate_self_signed_cert() {
    echo -e "${CYAN}--- 生成自签名 SSL 证书 (OpenSSL) ---${NC}"

    read -p ">> 请输入证书通用名称(CN) [默认: localhost]: " COMMON_NAME < /dev/tty
    COMMON_NAME=${COMMON_NAME:-localhost}

    read -p ">> 请输入证书有效期(天) [默认: 3650]: " DAYS < /dev/tty
    DAYS=${DAYS:-3650}

    read -p ">> 请输入密钥(key)文件保存路径 [默认: /root/private.key]: " KEY_PATH < /dev/tty
    KEY_PATH=${KEY_PATH:-/root/private.key}

    read -p ">> 请输入证书(crt)文件保存路径 [默认: /root/certificate.crt]: " CERT_PATH < /dev/tty
    CERT_PATH=${CERT_PATH:-/root/certificate.crt}

    if [ -f "$KEY_PATH" ] || [ -f "$CERT_PATH" ]; then
        echo -e "${YELLOW}警告: 文件 ${KEY_PATH} 或 ${CERT_PATH} 已存在。${NC}"
        read -p ">> 是否覆盖? [y/N]: " confirm_overwrite < /dev/tty
        if [[ "$confirm_overwrite" != "y" && "$confirm_overwrite" != "Y" ]]; then
            echo -e "${YELLOW}操作已取消。${NC}"
            return
        fi
    fi

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
        echo "现在您可以在配置服务时使用这些路径了。"
    else
        echo -e "${RED}证书生成失败！请检查 openssl 命令或文件权限。${NC}"
    fi
}

function install_script() {
    echo -e "${CYAN}--- 安装/更新 gost-mgr 快捷命令 ---${NC}"
    local SCRIPT_PATH
    SCRIPT_PATH=$(readlink -f "$0")
    local TARGET_PATH="/usr/local/bin/gost-mgr"

    if [ "$SCRIPT_PATH" == "$TARGET_PATH" ]; then
        echo -e "${GREEN}快捷命令已经是最新的 (您正在通过它运行此脚本)。${NC}"
        return
    fi

    echo "此操作将把当前脚本复制到 ${TARGET_PATH}"
    echo "之后，您就可以在系统任何地方通过输入 'gost-mgr' 来运行此面板。"
    read -p ">> 是否继续? [Y/n]: " confirm_install < /dev/tty

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
    echo -e "${GREEN}快捷命令 'gost-mgr' 安装/更新成功！${NC}"
    echo -e "${YELLOW}请重新打开终端，或运行 'source ~/.bashrc' (或 ~/.zshrc 等) 来让命令立即生效。${NC}"
    echo "之后，您可以随时随地输入 ${CYAN}gost-mgr${NC} 来打开此面板。"
}

function main_menu() {
    check_root
    
    local FATAL_DEPS="grep sed awk tar"
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
        echo "      Gost-Generic 多服务管理脚本 v3.3"
        echo "=========================================="
        
        local GOST_VERSION
        if [ -x /usr/bin/gost ]; then
            GOST_VERSION=$(/usr/bin/gost -V 2>/dev/null)
        fi
        
        if [ -n "$GOST_VERSION" ]; then
            echo -e "  当前 Gost 版本: ${GREEN}${GOST_VERSION}${NC}"
        else
            echo -e "  当前 Gost 版本: ${RED}未安装 (请使用选项 15 安装)${NC}"
        fi
        echo "=========================================="

        list_services_for_menu
        echo ""
        echo -e "${GREEN}请选择要执行的操作:${NC}"
        echo "  1. 添加新的 Gost 服务"
        echo "  2. 查看服务详细配置"
        echo "  3. 修改服务配置"
        echo "  ----------------------------------------"
        echo "  4. 启动指定的 Gost 服务"
        echo "  5. 停止指定的 Gost 服务"
        echo "  6. 重启指定的 Gost 服务"
        echo "  7. 启用服务开机自启"
        echo "  8. 禁用服务开机自启"
        echo "  ----------------------------------------"
        echo "  9. 查看指定服务的日志"
        echo "  10. 删除指定的 Gost 服务"
        echo "  11. 备份服务配置"
        echo "  12. 恢复服务配置"
        echo "  ----------------------------------------"
        echo "  13. 申请域名证书 (Let's Encrypt)"
        echo "  14. 生成自签名证书 (OpenSSL)"
        echo "  15. 更新 Gost 主程序 (影响所有服务)"
        echo "  16. 安装/更新快捷命令 (gost-mgr)"
        echo "  17. 退出脚本"
        echo "=========================================="
        read -p "请输入选项 [1-17]: " choice < /dev/tty
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
            11) backup_services ;;
            12) restore_services ;;
            13) apply_certificate ;;
            14) generate_self_signed_cert ;;
            15) update_gost_binary ;;
            16) install_script ;;
            17) echo "退出脚本。"; exit 0 ;;
            *) echo -e "${RED}无效的选项，请重新输入。${NC}" ;;
        esac
        echo ""
        read -p "按 Enter键 返回主菜单..." < /dev/tty
    done
}

# --- 脚本入口 ---
# 重新声明 view_service_details 以便 modify_service 调用
declare -f view_service_details > /dev/null && {
    original_view_service_details=$(declare -f view_service_details)
    view_service_details() {
        if [ -n "$1" ]; then
            local SERVICE_NAME=$1
            local SERVICE_FILE_PATH="${SERVICE_DIR}/${SERVICE_PREFIX}${SERVICE_NAME}.service"
            if [ ! -f "$SERVICE_FILE_PATH" ]; then
                # This is a special call, so just return on error
                return 1
            fi
            local EXEC_LINE=$(grep '^ExecStart=' "$SERVICE_FILE_PATH")
            local GOST_CMD=${EXEC_LINE#*=}
            echo "监听配置 (-L):"
            if echo "$GOST_CMD" | grep -q -- '-L[ =]'; then
                echo "$GOST_CMD" | grep -o -- '-L[ =]"[^"]*"' | while read -r line; do echo -e "  ${YELLOW}${line}${NC}"; done
            else
                echo "  未配置"
            fi
            echo "转发配置 (-F):"
            if echo "$GOST_CMD" | grep -q -- '-F[ =]'; then
                echo "$GOST_CMD" | grep -o -- '-F[ =]"[^"]*"' | while read -r line; do echo -e "  ${YELLOW}${line}${NC}"; done
            else
                echo "  未配置"
            fi
        else
            eval "$original_view_service_details"
        fi
    }
}
main_menu
