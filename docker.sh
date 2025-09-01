#!/bin/bash

#===============================================================================================
#
#          FILE: docker-manager-v5.0.sh
#
#         USAGE: sudo ./docker-manager-v5.0.sh
#
#   DESCRIPTION: 服务级管控的 Docker/Compose 管理器。可深入项目内部，独立启停、修改单个服务。
#
#       OPTIONS: ---
#  REQUIREMENTS: jq, yq, nano/vim (or other editor)
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Gemini
#  ORGANIZATION:
#       CREATED: 2025-09-01
#      REVISION: 5.0
#
#===============================================================================================

# 颜色定义
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[0;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_NC='\033[0m'

# --- 核心检测函数 (与 v4 相同) ---
check_root() { if [[ "$EUID" -ne 0 ]]; then echo -e "${C_RED}错误：此脚本必须以 root 权限运行。${C_NC}"; exit 1; fi; }
check_docker() { if command -v docker &> /dev/null; then return 0; else return 1; fi; }
check_jq() { if command -v jq &> /dev/null; then return 0; else echo -e "${C_RED}依赖 jq 未安装。${C_NC}"; return 1; fi; }
check_yq() { if command -v yq &>/dev/null; then return 0; else echo -e "${C_RED}依赖 yq 未安装。${C_NC}"; return 1; fi; } # 在 v4 中已有自动安装，此处简化
COMPOSE_CMD=""
check_docker_compose() { if docker compose version &>/dev/null; then COMPOSE_CMD="docker compose"; return 0; elif command -v docker-compose &>/dev/null; then COMPOSE_CMD="docker-compose"; return 0; else echo -e "${C_YELLOW}警告：未检测到 Docker Compose。${C_NC}"; return 1; fi; }

# --- 功能函数占位符 (请从 v4 版本完整复制过来) ---
install_docker() { echo "此处应为之前版本中的 install_docker 完整代码"; }
setup_watchtower() { echo "此处应为之前版本中的 setup_watchtower 完整代码"; }
show_status() { docker ps -a; }
modify_container() { echo "此处应为之前版本中的 modify_container 完整代码"; }

# --- Compose 模块 (v5 核心) ---

# 【新】服务管理子菜单
service_control_menu() {
    local project_dir="$1"
    local service_name="$2"
    local project_path="$3"

    while true; do
        clear
        # 读取当前重启策略
        local current_restart_policy
        current_restart_policy=$(cd "$project_dir" && yq e ".services.$service_name.restart" "$project_path" 2>/dev/null)
        if [ "$current_restart_policy" == "null" ]; then current_restart_policy="未设置"; fi

        echo -e "${C_BLUE}正在管理服务: ${C_GREEN}$service_name${C_NC} (项目路径: $project_dir)"
        echo -e "${C_YELLOW}当前重启策略 (自启动): $current_restart_policy${C_NC}"
        echo "-------------------------------------"
        echo "1. 启动 (Start)"
        echo "2. 停止 (Stop)"
        echo "3. 重启 (Restart)"
        echo "4. 删除 (Remove - 会先停止)"
        echo "5. 查看日志 (Logs)"
        echo -e "${C_CYAN}6. 修改重启策略 (自启动)${C_NC}"
        echo "7. 返回"
        read -p "请选择操作 [1-7]: " action

        case $action in
            1) (cd "$project_dir" && $COMPOSE_CMD start "$service_name");;
            2) (cd "$project_dir" && $COMPOSE_CMD stop "$service_name");;
            3) (cd "$project_dir" && $COMPOSE_CMD restart "$service_name");;
            4) (cd "$project_dir" && $COMPOSE_CMD stop "$service_name" && $COMPOSE_CMD rm -f "$service_name");;
            5) (cd "$project_dir" && $COMPOSE_CMD logs -f --tail=100 "$service_name");;
            6) 
                echo -e "${C_CYAN}请选择新的重启策略:${C_NC}"
                select new_policy in "always" "unless-stopped" "on-failure" "no"; do
                    if [ -n "$new_policy" ]; then
                        echo -e "${C_BLUE}正在将 '${service_name}' 的重启策略修改为 '${new_policy}'...${C_NC}"
                        (cd "$project_dir" && yq e -i ".services.$service_name.restart = \"$new_policy\"" "$project_path")
                        echo -e "${C_GREEN}YAML 文件修改成功！${C_NC}"
                        echo -e "${C_YELLOW}请注意：您需要返回项目主菜单，执行 '应用 & 重启 (Up)' 来使此更改生效。${C_NC}"
                        break
                    fi
                done
                ;;
            7) break;;
            *) echo -e "${C_RED}无效的选择。${C_NC}";;
        esac
        read -n 1 -s -r -p "按任意键继续..."
    done
}


# 【新】查看和选择服务状态
view_and_manage_services() {
    local project_dir="$1"
    local project_path="$2"

    # 使用 --format json 获取准确信息
    local services_json
    services_json=$(cd "$project_dir" && $COMPOSE_CMD ps --format json)
    
    if [ -z "$services_json" ]; then
        echo -e "${C_YELLOW}该项目当前没有正在运行或已停止的容器。${C_NC}"
        echo -e "您可以尝试先执行 'Up' 来启动项目。"
        return
    fi
    
    # 使用 jq 解析并格式化输出
    # mapfile 读取可以处理带空格的容器名
    mapfile -t services_list < <(echo "$services_json" | jq -r '.[] | .Service + "|" + .Name + "|" + .State + "|" + .Publishers')

    if [ ${#services_list[@]} -eq 0 ]; then
        echo -e "${C_YELLOW}无法解析服务列表。${C_NC}"; return;
    fi

    echo -e "${C_CYAN}请选择您想管理的单个服务:${C_NC}"
    # 动态生成 select 菜单的选项
    local options=()
    for item in "${services_list[@]}"; do
        local service=$(echo "$item" | cut -d'|' -f1)
        local name=$(echo "$item" | cut -d'|' -f2)
        local state=$(echo "$item" | cut -d'|' -f3)
        local ports=$(echo "$item" | cut -d'|' -f4)
        if [[ "$state" == "running"* ]]; then
            state_color=$C_GREEN
        else
            state_color=$C_RED
        fi
        options+=("服务: $service | 状态: ${state_color}$state${C_NC} | 端口: $ports")
    done
    
    select choice in "${options[@]}"; do
        if [ -n "$choice" ]; then
            # 从选择的字符串中提取出原始的服务名
            local selected_service
            selected_service=$(echo "${services_list[$((REPLY-1))]}" | cut -d'|' -f1)
            service_control_menu "$project_dir" "$selected_service" "$project_path"
            break
        fi
    done
}


# 【重构】项目主菜单
compose_project_menu() {
    local project_path="$1"
    local project_dir
    project_dir=$(dirname "$project_path")

    while true; do
        clear
        local services_info=$(yq e '.services | keys | .[]' "$project_path" 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        echo -e "${C_BLUE}正在管理项目:${C_NC} ${C_GREEN}${project_path}${C_NC}"
        echo -e "${C_CYAN}(服务: $services_info)${C_NC}"
        echo -e "${C_BLUE}---------------------[项目整体操作]---------------------${C_NC}"
        echo "1. 编辑 (Edit) - 修改 compose 文件"
        echo "2. 应用 & 重启 (Up) - 启动/重建整个项目"
        echo "3. 拉取更新 (Pull) - 拉取所有服务的最新镜像"
        echo "4. 停止 & 移除 (Down) - 停止并移除整个项目"
        echo -e "${C_BLUE}---------------------[单个服务控制]---------------------${C_NC}"
        echo -e "${C_CYAN}5. 查看/管理服务状态 (精细化控制)${C_NC}"
        echo "6. 返回"
        echo -e "${C_BLUE}--------------------------------------------------${C_NC}"
        read -p "请选择操作 [1-6]: " project_action
        
        case $project_action in
            1) local editor=${EDITOR:-nano}; if ! command -v "$editor" &>/dev/null; then editor=vim; fi; $editor "$project_path";;
            2) (cd "$project_dir" && $COMPOSE_CMD up -d);;
            3) (cd "$project_dir" && $COMPOSE_CMD pull);;
            4) (cd "$project_dir" && $COMPOSE_CMD down);;
            5) view_and_manage_services "$project_dir" "$project_path";;
            6) break;;
            *) echo -e "${C_RED}无效的选择。${C_NC}";;
        esac
        if [[ "$project_action" -ne 5 ]]; then
            read -n 1 -s -r -p "按任意键继续..."
        fi
    done
}

# --- manage_compose_projects (与 v4 相同) ---
manage_compose_projects() {
    # 此函数与 v4 版本完全相同，用于查找和选择项目。
    # 为简洁此处省略，实际使用时请从 v4 脚本复制过来。
    echo "此处应为 v4 版本中的 manage_compose_projects 完整代码"
}


# --- 主菜单和主循环 ---
show_menu() {
    clear
    echo -e "${C_BLUE}=====================================${C_NC}"
    echo -e "${C_GREEN}    服务级 Docker & Compose 管理器 v5.0   ${C_NC}"
    echo -e "${C_BLUE}=====================================${C_NC}"
    # ... (与 v4 相同)
    echo "1. 安装/检查 Docker 环境"
    echo "2. 启动/管理容器自动更新 (Watchtower)"
    echo "3. 查看所有单容器运行状态 (docker ps)"
    echo "4. 交互式修改单个容器参数"
    echo -e "${C_CYAN}5. 管理 Docker Compose 项目${C_NC} (服务级控制)"
    echo "6. 退出"
}

main() {
    check_root
    # ... (与 v4 相同)
    while true; do
        show_menu
        read -p "请输入您的选择 [1-6]: " option
        case $option in
            1) if check_docker; then echo -e "${C_GREEN}Docker 环境正常。${C_NC}"; else install_docker; fi;;
            2) if check_docker; then setup_watchtower; else echo -e "${C_RED}错误：请先安装 Docker！${C_NC}"; fi;;
            3) if check_docker; then show_status; else echo -e "${C_RED}错误：请先安装 Docker！${C_NC}"; fi;;
            4) if check_docker && check_jq; then modify_container; else echo -e "${C_RED}错误：请先安装 Docker 和 jq！${C_NC}"; fi;;
            5) if check_docker && check_yq; then manage_compose_projects; else echo -e "${C_RED}错误：请先安装 Docker 和 yq！${C_NC}"; fi;;
            6) echo -e "${C_GREEN}感谢使用，再见！${C_NC}"; exit 0;;
            *) echo -e "${C_RED}无效的选项。${C_NC}";;
        esac
        read -n 1 -s -r -p "按任意键返回主菜单..."
    done
}


# ！！！重要！！！
# 1. 这是一个简化的示例，您需要将 v4 版本中完整的 `manage_compose_projects` 函数复制到占位符位置。
# 2. 同样，您需要将 `install_docker`, `setup_watchtower`, `modify_container` 的完整代码也复制过来。
# 3. 确保您的系统已安装 jq 和 yq，脚本中的自动安装功能依赖于常见的包管理器和 wget。

main
