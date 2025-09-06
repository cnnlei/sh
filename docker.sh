#!/bin/bash

# ==============================================================================
# Docker 容器交互式管理工具 v9.8 (功能修复)
#
# v9.8 更新:
# - 修复: “管理重启策略”功能因函数缺失而无法使用的问题，已补全该功能。
#
# v9.7 更新:
# - 修复: 修正了 v9.6 中未生效的主列表详情值（Policy, Ports, Mounts）紫色高亮功能。
#
# v9.6 更新:
# - UI 优化: (失败的尝试) 为主列表中容器的 Policy, Ports, Mounts 等详情的值增加紫色高亮。
# ==============================================================================

# --- 配置颜色输出 ---
if tput setaf 1 >&/dev/null; then
    GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); RED=$(tput setaf 1); CYAN=$(tput setaf 6); BLUE=$(tput setaf 4); MAGENTA=$(tput setaf 5); WHITE=$(tput setaf 7); RESET=$(tput sgr0)
else
    GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; BLUE="\033[0;34m"; MAGENTA="\033[0;35m"; WHITE="\033[1;37m"; RESET="\033[0m"
fi

# --- Helper 函数 ---
log_success() { echo -e "${GREEN}[✓] $1${RESET}"; }
log_info() { echo -e "${YELLOW}[!] $1${RESET}"; }
log_error() { echo -e "${RED}[✗] $1${RESET}" >&2; }
log_header() { echo -e "\n${CYAN}--- $1 ---${RESET}"; }

command_exists() { command -v "$1" &> /dev/null; }
press_enter_to_continue() { read -p "按 Enter 键继续..." ; }

# --- 依赖检查 ---
check_dependencies() {
    if command_exists jq; then return 0; fi
    clear
    log_info "高级功能需要 'jq' (JSON 解析器)。"
    read -p "系统未检测到 jq, 是否需要自动为您安装? (y/N): " choice
    if [[ ! "$choice" =~ ^[yY]$ ]]; then log_error "用户取消安装。部分功能可能无法正常显示。"; press_enter_to_continue; return 1; fi
    
    log_info "正在尝试安装 jq..."
    if command_exists apt-get; then sudo apt-get update && sudo apt-get install -y jq;
    elif command_exists yum; then sudo yum install -y jq;
    elif command_exists dnf; then sudo dnf install -y jq;
    else log_error "无法确定包管理器，请手动安装 jq。"; exit 1; fi

    if command_exists jq; then log_success "jq 安装成功！"; press_enter_to_continue;
    else log_error "jq 安装失败。"; exit 1; fi
}

# --- 安装逻辑 ---
install_docker_if_needed() {
    if command_exists docker; then return 0; fi
    clear
    log_info "首次运行：系统未检测到 Docker。"
    read -p "是否需要自动为您安装 Docker? (y/N): " choice
    if [[ ! "$choice" =~ ^[yY]$ ]]; then log_error "用户取消安装。脚本退出。"; exit 1; fi
    log_info "开始安装 Docker..."
    if ! command_exists curl; then
        log_info "正在安装 curl..."
        if command_exists apt-get; then sudo apt-get update && sudo apt-get install -y curl;
        elif command_exists yum; then sudo yum install -y curl;
        elif command_exists dnf; then sudo dnf install -y curl;
        else log_error "无法安装 curl，请手动安装后再运行脚本。"; exit 1; fi
    fi
    if curl -fsSL https://get.docker.com | sudo sh; then
        sudo usermod -aG docker $USER
        log_success "Docker 安装成功！"
        log_info "重要：请重新登录或执行 'newgrp docker' 以应用权限。"
        press_enter_to_continue
    else
        log_error "Docker 安装失败。"; exit 1
    fi
}

# --- 工具箱：修改 Docker 镜像源 ---
set_docker_mirror() {
    if [[ $EUID -ne 0 ]] && ! command_exists sudo; then
        log_error "此操作需要 root 权限或 sudo。请使用 sudo 运行此脚本。"
        press_enter_to_continue
        return
    fi
    
    DAEMON_JSON="/etc/docker/daemon.json"
    
    local current_mirrors
    if [ -f "$DAEMON_JSON" ]; then
        current_mirrors=$(sudo cat "$DAEMON_JSON" 2>/dev/null | jq -r '."registry-mirrors" | if . then join(", ") else "未设置" end')
    else
        current_mirrors="未设置"
    fi

    clear
    log_header "修改 Docker Hub 镜像加速源"
    log_info "当前镜像源: ${current_mirrors}"
    echo "--------------------------------------------------"
    echo "请选择一个新的镜像加速源:"
    echo "  1) ${CYAN}中科大 (docker.mirrors.ustc.edu.cn)${RESET}"
    echo "  2) ${CYAN}网易 (hub-mirror.c.163.com)${RESET}"
    echo "  3) ${CYAN}DaoCloud (f1361db2.m.daocloud.io)${RESET}"
    echo "  4) ${YELLOW}自定义 (例如阿里云专属地址)${RESET}"
    echo "  c) ${RED}清除镜像源设置${RESET}"
    echo "  q) 返回"
    echo "--------------------------------------------------"
    read -p "请输入选项: " choice

    local mirror_url=""
    local clear_settings=false
    case $choice in
        1) mirror_url="https://docker.mirrors.ustc.edu.cn";;
        2) mirror_url="http://hub-mirror.c.163.com";;
        3) mirror_url="http://f1361db2.m.daocloud.io";;
        4) 
            while true; do
                read -p "请输入自定义的镜像加速器地址 (或输入 'q' 取消): " custom_url
                if [[ "$custom_url" == "q" ]]; then
                    mirror_url=""
                    break
                fi
                if [[ -n "$custom_url" && ! "$custom_url" =~ \  && "$custom_url" =~ \. ]]; then
                    mirror_url="$custom_url"
                    break
                else
                    log_error "无效的地址格式。地址不应包含空格，且必须至少包含一个 '.'。"
                fi
            done
            ;;
        [cC]) clear_settings=true;;
        [qQ]) return;;
        *) log_error "无效选项。"; press_enter_to_continue; return;;
    esac

    local current_json="{}"
    if [ -f "$DAEMON_JSON" ]; then
        current_json=$(sudo cat "$DAEMON_JSON" 2>/dev/null)
    fi
    if ! echo "$current_json" | jq . > /dev/null 2>&1; then
        current_json="{}"
    fi

    local new_json=""
    if [ "$clear_settings" = true ]; then
        read -p "确定要清除所有镜像源设置吗? (y/N): " confirm
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            log_info "正在清除镜像源..."
            new_json=$(echo "$current_json" | jq 'del(."registry-mirrors")')
            log_success "镜像源已清除。"
        else
            log_info "已取消。"; press_enter_to_continue; return
        fi
    elif [ -n "$mirror_url" ]; then
        log_info "正在将镜像源设置为: ${mirror_url}"
        new_json=$(echo "$current_json" | jq --arg mirror "$mirror_url" '."registry-mirrors" = [$mirror]')
    else
        log_info "未做任何更改。"
        press_enter_to_continue
        return
    fi

    sudo mkdir -p /etc/docker
    echo "$new_json" | sudo tee "$DAEMON_JSON" > /dev/null
    log_success "配置文件 ${DAEMON_JSON} 已更新。"

    read -p "配置已更新, 需要重启 Docker 服务才能生效。是否立即重启? (Y/n): " restart_confirm
    if [[ ! "$restart_confirm" =~ ^[nN]$ ]]; then
        log_info "正在重启 Docker 服务..."
        if sudo systemctl restart docker; then
            log_success "Docker 重启成功！"
        else
            log_error "Docker 重启失败。请手动执行 'sudo systemctl restart docker'。"
        fi
    else
        log_info "已取消重启。请记得稍后手动重启 Docker 服务。"
    fi
    press_enter_to_continue
}

# --- 工具箱：清理 Docker 系统 ---
prune_docker_system() {
    clear
    log_header "清理 Docker 系统 (System Prune)"
    log_info "此操作将删除所有已停止的容器、悬空镜像、未使用的网络和构建缓存。"
    log_info "首先，让我们看一下可以回收多少空间:"
    echo "--------------------------------------------------"
    docker system df
    echo "--------------------------------------------------"
    
    log_error "警告: 这是一个不可逆操作！"
    read -p "确定要继续清理吗? (y/N): " confirm
    
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        log_info "正在执行清理操作..."
        docker system prune -f
        log_success "Docker 系统清理完成。"
    else
        log_info "已取消操作。"
    fi
    press_enter_to_continue
}


# --- 工具箱主菜单 ---
show_tools_menu() {
    while true; do
        clear
        log_header "实用工具箱"
        echo "  1) 修改 Docker Hub 镜像加速源"
        echo "  2) 清理 Docker 系统 (prune)"
        echo "  ... 更多功能待定 ..."
        echo ""
        echo "  q) 返回主菜单"
        echo "-------------------------------------"
        read -p "请选择功能: " choice
        
        case $choice in
            1) set_docker_mirror;;
            2) prune_docker_system;;
            [qQ]) return;;
            *) log_error "无效选项。"; press_enter_to_continue;;
        esac
    done
}


# --- (以下为其他未修改的函数，已折叠以保持简洁) ---
# --- 镜像管理功能 ---
manage_images() {
    while true; do
        clear; log_header "Docker 镜像管理"
        mapfile -t images < <(docker images --format "{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}")
        if [ ${#images[@]} -eq 0 ]; then log_info "系统中没有找到任何 Docker 镜像。"; else
            printf "${WHITE}%-4s %-18s %-40s %-15s %s${RESET}\n" "NO." "IMAGE ID" "REPOSITORY" "TAG" "SIZE"
            printf "${WHITE}%-4s %-18s %-40s %-15s %s${RESET}\n" "----" "------------------" "----------------------------------------" "---------------" "----"
            i=1
            for line in "${images[@]}"; do
                IFS=$'\t' read -r id repo tag size <<< "$line"
                printf "%-4s %-18.12s %-40s %-15s %s\n" "$i)" "$id" "$repo" "$tag" "$size"
                i=$((i+1))
            done
        fi
        echo "--------------------------------------------------------------------------------"
        echo "操作指令: d <数字>, d <数字,数字>, dangling, all, q (返回)"
        echo "--------------------------------------------------------------------------------"
        read -p "请输入操作指令: " cmd
        case $cmd in
            [qQ]) return;;
            dangling)
                read -p "确定要删除所有悬空镜像吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then log_info "正在清理悬空镜像..."; docker image prune -f; else log_info "已取消。"; fi
                press_enter_to_continue;;
            all)
                log_info "${RED}警告: 这是一个危险操作，将删除所有未被容器使用的镜像！${RESET}"; read -p "请输入 'yes' 以确认删除: " confirm
                if [[ "$confirm" == "yes" ]]; then log_info "正在删除所有未使用的镜像..."; docker image prune -a -f; else log_info "输入不匹配，已取消删除。"; fi
                press_enter_to_continue;;
            d\ *)
                local to_delete_str=${cmd#d }; local to_delete_indices=${to_delete_str//,/ }; local image_ids_to_delete=(); local image_repos_to_delete=(); local invalid_input=false
                for index in $to_delete_indices; do
                    if [[ "$index" =~ ^[0-9]+$ ]] && [ "$index" -ge 1 ] && [ "$index" -le ${#images[@]} ]; then
                        local selected_line=${images[$((index-1))]}; IFS=$'\t' read -r id repo tag size <<< "$selected_line"
                        image_ids_to_delete+=("$id"); image_repos_to_delete+=("${repo}:${tag}")
                    else log_error "无效的数字: $index"; invalid_input=true; fi
                done
                if [ "$invalid_input" = true ]; then press_enter_to_continue; continue; fi
                if [ ${#image_ids_to_delete[@]} -gt 0 ]; then
                    log_info "将要删除以下镜像:"; for repo in "${image_repos_to_delete[@]}"; do echo " - $repo"; done
                    read -p "确定吗? (y/N): " confirm
                    if [[ "$confirm" =~ ^[yY]$ ]]; then
                        log_info "正在删除镜像..."
                        if ! docker rmi "${image_ids_to_delete[@]}"; then log_error "删除失败。部分镜像可能正在被容器使用。"; else log_success "删除成功。"; fi
                    else log_info "已取消删除。"; fi
                fi
                press_enter_to_continue;;
            *) log_error "无效指令，请重新输入。"; sleep 1;;
        esac
    done
}
# --- 容器更新功能 ---
update_container() {
    local container_id=$1; local container_name=$2; clear; log_header "更新容器: ${BLUE}${container_name}${RESET}"
    log_info "此操作将: 1.拉取新镜像 2.停止并删除当前容器 3.用新镜像和旧配置重建容器。"
    read -p "确定要更新容器 '${container_name}' 吗? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then log_info "已取消更新。"; press_enter_to_continue; return 1; fi
    local inspect_json=$(docker inspect "$container_id"); local image_name=$(echo "$inspect_json" | jq -r '.[0].Config.Image'); local old_image_id=$(echo "$inspect_json" | jq -r '.[0].Image')
    log_info "正在拉取最新镜像: ${image_name}..."; if ! docker pull "$image_name"; then log_error "镜像拉取失败。"; press_enter_to_continue; return 1; fi
    local new_image_id=$(docker inspect --format='{{.Id}}' "$image_name")
    if [[ "$old_image_id" == "$new_image_id" ]]; then
        log_info "镜像已经是最新版本。"; read -p "是否仍要强制使用当前镜像重建容器? (Y/n): " force_rebuild_choice
        if [[ "$force_rebuild_choice" =~ ^[nN]$ ]]; then log_info "已取消重建容器。"; press_enter_to_continue; return 1; fi
        log_info "用户选择强制重建容器..."
    fi
    log_info "正在根据旧容器配置生成新的启动命令..."; local run_cmd_args=(); run_cmd_args+=("run" "-d" "--name" "$container_name")
    local policy_name=$(echo "$inspect_json" | jq -r '.[0].HostConfig.RestartPolicy.Name // "no"')
    if [[ "$policy_name" != "no" && ! -z "$policy_name" ]]; then
        local retry_count=$(echo "$inspect_json" | jq -r '.[0].HostConfig.RestartPolicy.MaximumRetryCount')
        if [[ "$policy_name" == "on-failure" && "$retry_count" -gt 0 ]]; then run_cmd_args+=("--restart" "${policy_name}:${retry_count}"); else run_cmd_args+=("--restart" "$policy_name"); fi
    fi
    mapfile -t ports < <(echo "$inspect_json" | jq -r '.[0].HostConfig.PortBindings | to_entries[] | "-p", "\(.value[0].HostPort):\(.key)"'); [ ${#ports[@]} -gt 0 ] && run_cmd_args+=("${ports[@]}")
    mapfile -t mounts < <(echo "$inspect_json" | jq -r '.[0].Mounts[] | "-v", "\(.Source):\(.Destination)"'); [ ${#mounts[@]} -gt 0 ] && run_cmd_args+=("${mounts[@]}")
    mapfile -t envs < <(echo "$inspect_json" | jq -r '.[0].Config.Env[] | "-e", .'); [ ${#envs[@]} -gt 0 ] && run_cmd_args+=("${envs[@]}")
    run_cmd_args+=("$image_name"); log_info "将要执行以下命令:"
    printf "docker "; for arg in "${run_cmd_args[@]}"; do if [[ "$arg" == *" "* ]]; then printf "'%s' " "$arg"; else printf "%s " "$arg"; fi; done; echo
    read -p "确认执行以上命令吗? (Y/n): " final_confirm
    if [[ "$final_confirm" =~ ^[nN]$ ]]; then log_info "已取消执行。"; press_enter_to_continue; return 1; fi
    log_info "正在停止旧容器..."; docker stop "$container_id" > /dev/null; log_info "正在删除旧容器..."; docker rm "$container_id" > /dev/null; log_info "正在创建并启动新容器..."
    if docker "${run_cmd_args[@]}"; then log_success "容器更新成功！新容器已启动。"; else log_error "容器更新失败。请检查上面的命令和错误信息。"; fi
    press_enter_to_continue; return 0
}
# --- 容器编辑功能 (配置文件模式) ---
edit_container_file() {
    local container_id=$1; local container_name=$2; local inspect_json=$3; local temp_file; temp_file=$(mktemp "/tmp/docker_edit_${container_name}.XXXXXX.conf"); trap 'rm -f "$temp_file"' RETURN
    local image_name=$(echo "$inspect_json" | jq -r '.[0].Config.Image'); local restart_policy=$(echo "$inspect_json" | jq -r '.[0].HostConfig.RestartPolicy.Name // "no"')
    local ports_array=$(echo "$inspect_json" | jq -r '.[0].HostConfig.PortBindings | to_entries | .[] | "\(.value[0].HostPort):\(.key)"' | sed 's/.*/  "&"/' | tr '\n' '\n')
    local volumes_array=$(echo "$inspect_json" | jq -r '.[0].Mounts[] | "\(.Source):\(.Destination)"' | sed 's/.*/  "&"/' | tr '\n' '\n')
    local env_vars_array=$(echo "$inspect_json" | jq -r '.[0].Config.Env[]' | sed 's/.*/  "&"/' | tr '\n' '\n')
    cat > "$temp_file" <<-EOF
# Edit Docker Container Configuration
# Please modify the parameters below. Save and exit to apply changes.
# Exiting without saving, or leaving the file empty, will cancel the operation.
# -----------------------------------------------------------------
IMAGE_NAME="${image_name}"
RESTART_POLICY="${restart_policy}"
PORTS=(
${ports_array}
)
VOLUMES=(
${volumes_array}
)
ENV_VARS=(
${env_vars_array}
)
EOF
    local editor=${EDITOR:-vi}; if ! command_exists "$editor"; then editor=nano; fi; if ! command_exists "$editor"; then editor=vi; fi
    log_info "将在 3 秒后使用 '${editor}' 打开配置文件..."; sleep 3; $editor "$temp_file"
    if [ ! -s "$temp_file" ]; then log_info "配置文件为空，操作已取消。"; press_enter_to_continue; return 1; fi
    log_info "正在读取修改后的配置..."; unset IMAGE_NAME RESTART_POLICY PORTS VOLUMES ENV_VARS; source "$temp_file"
    recreate_container_from_vars "$container_id" "$container_name"; return $?
}
# --- 容器编辑功能 (交互式向导模式) ---
edit_container_interactive() {
    local container_id=$1; local container_name=$2; local inspect_json=$3; local image_name=$(echo "$inspect_json" | jq -r '.[0].Config.Image'); local restart_policy=$(echo "$inspect_json" | jq -r '.[0].HostConfig.RestartPolicy.Name // "no"')
    mapfile -t ports < <(echo "$inspect_json" | jq -r '.[0].HostConfig.PortBindings | to_entries | .[] | "\(.value[0].HostPort):\(.key)"'); mapfile -t volumes < <(echo "$inspect_json" | jq -r '.[0].Mounts[] | "\(.Source):\(.Destination)"'); mapfile -t env_vars < <(echo "$inspect_json" | jq -r '.[0].Config.Env[]')
    while true; do
        clear; log_header "编辑向导: ${BLUE}${container_name}${RESET}"
        echo "当前配置:"; echo "  镜像: ${CYAN}${image_name}${RESET}"; echo "  重启策略: ${CYAN}${restart_policy}${RESET}"; echo "  端口映射: ${CYAN}${ports[*]}${RESET}"; echo "  目录映射: ${CYAN}${volumes[*]}${RESET}"; local env_count=${#env_vars[@]}; echo "  环境变量: ${CYAN}${env_count} 项${RESET}"
        echo "--------------------------------------------------"; echo "请选择要修改的项:"; echo "  1) 修改重启策略"; echo "  2) 修改端口映射"; echo "  3) 修改目录映射"; echo "  4) 修改环境变量 (将打开编辑器)"; echo ""; echo "  s) ${GREEN}保存并重建容器${RESET}"; echo "  q) ${RED}放弃修改并返回${RESET}"; echo "--------------------------------------------------"; read -p "请输入选项: " choice
        case $choice in
            1) read -p "请输入新的重启策略 (no, on-failure, unless-stopped, always) [当前: ${restart_policy}]: " new_policy; if [ -n "$new_policy" ]; then restart_policy=$new_policy; fi;;
            2) read -p "请输入新的端口映射 (格式: 80:80 443:443) [当前: ${ports[*]}]: " -a new_ports; if [ ${#new_ports[@]} -gt 0 ]; then ports=("${new_ports[@]}"); fi;;
            3) read -p "请输入新的目录映射 (格式: /host:/app /data:/db) [当前: ${volumes[*]}]: " -a new_volumes; if [ ${#new_volumes[@]} -gt 0 ]; then volumes=("${new_volumes[@]}"); fi;;
            4) local temp_env_file; temp_env_file=$(mktemp "/tmp/docker_edit_env_${container_name}.XXXXXX.env"); trap 'rm -f "$temp_env_file"' RETURN; printf "%s\n" "${env_vars[@]}" > "$temp_env_file"; local editor=${EDITOR:-vi}; if ! command_exists "$editor"; then editor=nano; fi; log_info "将使用 '${editor}' 打开环境变量文件..."; sleep 2; $editor "$temp_env_file"; mapfile -t env_vars < "$temp_env_file";;
            [sS]) IMAGE_NAME=$image_name; RESTART_POLICY=$restart_policy; PORTS=("${ports[@]}"); VOLUMES=("${volumes[@]}"); ENV_VARS=("${env_vars[@]}"); recreate_container_from_vars "$container_id" "$container_name"; return $?;;
            [qQ]) log_info "已放弃修改。"; press_enter_to_continue; return 1;;
            *) log_error "无效输入，请重试。"; sleep 1;;
        esac
    done
}
# --- 通用容器重建函数 ---
recreate_container_from_vars() {
    local container_id=$1; local container_name=$2; local run_cmd_args=(); run_cmd_args+=("run" "-d" "--name" "$container_name")
    [[ -n "$RESTART_POLICY" && "$RESTART_POLICY" != "no" ]] && run_cmd_args+=("--restart" "$RESTART_POLICY")
    for port in "${PORTS[@]}"; do run_cmd_args+=("-p" "$port"); done; for vol in "${VOLUMES[@]}"; do run_cmd_args+=("-v" "$vol"); done; for env_var in "${ENV_VARS[@]}"; do run_cmd_args+=("-e" "$env_var"); done
    run_cmd_args+=("$IMAGE_NAME"); clear; log_info "将根据您的配置执行以下命令:"
    printf "docker "; for arg in "${run_cmd_args[@]}"; do if [[ "$arg" == *" "* ]]; then printf "'%s' " "$arg"; else printf "%s " "$arg"; fi; done; echo; echo
    read -p "确认执行以上命令吗? (Y/n): " final_confirm
    if [[ "$final_confirm" =~ ^[nN]$ ]]; then log_info "已取消执行。"; press_enter_to_continue; return 1; fi
    log_info "正在停止旧容器..."; docker stop "$container_id" > /dev/null; log_info "正在删除旧容器..."; docker rm "$container_id" > /dev/null; log_info "正在创建并启动新容器..."
    if docker "${run_cmd_args[@]}"; then log_success "容器编辑成功！新容器已启动。"; else log_error "容器编辑失败。请检查上面的命令和错误信息。"; fi
    press_enter_to_continue; return 0
}

# --- 管理重启策略 ---
manage_restart_policy() {
    local container_id=$1
    local current_policy
    current_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$container_id")
    if [ -z "$current_policy" ]; then current_policy="no"; fi

    clear
    log_header "管理重启策略"
    log_info "当前策略: ${current_policy}"
    echo "-------------------------------------"
    echo "请选择一个新的重启策略:"
    echo "  1) no (不自动重启)"
    echo "  2) on-failure (仅在非零状态退出时重启)"
    echo "  3) unless-stopped (除非手动停止，否则总是重启)"
    echo "  4) always (总是重启)"
    echo "  q) 返回"
    echo "-------------------------------------"
    read -p "请输入选项: " choice

    local new_policy=""
    case $choice in
        1) new_policy="no";;
        2) new_policy="on-failure";;
        3) new_policy="unless-stopped";;
        4) new_policy="always";;
        [qQ]) return;;
        *) log_error "无效选项。"; press_enter_to_continue; return;;
    esac

    if [[ "$new_policy" == "$current_policy" ]]; then
        log_info "新策略与当前策略相同，未做任何更改。"
    else
        log_info "正在将重启策略更新为: ${new_policy}..."
        if docker update --restart="$new_policy" "$container_id" > /dev/null; then
            log_success "重启策略更新成功！"
        else
            log_error "更新失败。请检查 Docker 是否正在运行。"
        fi
    fi
    press_enter_to_continue
}

# --- 容器操作菜单 ---
show_container_actions_menu() {
    local container_id=$1; local container_name=$2
    while true; do
        clear; log_header "正在管理容器: ${BLUE}${container_name} (${container_id:0:12})${RESET}"
        local inspect_json; inspect_json=$(docker inspect "$container_id")
        local raw_details; raw_details=$(echo "$inspect_json" | jq -r '.[0] | .State.Status + "\t" + (.State.Running | tostring) + "\t" + .State.StartedAt + "\t" + (.State.ExitCode | tostring) + "\t" + (.RepoTags[0] // .Config.Image // .Image) + "\t" + (.HostConfig.RestartPolicy.Name // "no") + "\t" + .Created + "\t" + (.HostConfig.PortBindings | if . == null or . == {} then "无" else (to_entries | map("\(.value[0].HostPort) -> \(.key)") | join("; ")) end) + "\t" + (.Mounts | if . == [] then "无" else (map("\(.Source) -> \(.Destination)") | join("; ")) end)')
        IFS=$'\t' read -r status is_running started_at exit_code image policy created_at ports mounts <<< "$raw_details"
        
        local status_line=""
        if [[ "$is_running" == "true" ]]; then 
            local start_time_abs=$(date -d "$started_at" '+%Y-%m-%d %H:%M:%S')
            status_line="状态 : ${GREEN}${status}${RESET} (since ${start_time_abs})"
        else 
            status_line="状态 : ${RED}${status}${RESET} (exit code ${exit_code})"
        fi

        # --- 直接打印详情，不再拼接字符串 (格式最终修复) ---
        echo -e "${WHITE}${status_line}${RESET}"
        
        # 运行时间 (仅针对运行中的容器)
        if [[ "$is_running" == "true" ]]; then
            local current_ts=$(date +%s); local start_ts=$(date -d "$started_at" +%s); local diff_seconds=$((current_ts - start_ts)); local uptime_string=""
            local days=$((diff_seconds/86400)); local hours=$(((diff_seconds%86400)/3600)); local mins=$(((diff_seconds%3600)/60)); local secs=$((diff_seconds%60))
            if (( days > 0 )); then uptime_string="${days} 天 ${hours} 小时前"; elif (( hours > 0 )); then uptime_string="${hours} 小时 ${mins} 分钟前"; elif (( mins > 0 )); then uptime_string="${mins} 分钟 ${secs} 秒前"; else uptime_string="${secs} 秒前"; fi
            printf "%s: ${CYAN}%s${RESET}\n" "启动时间" "$uptime_string"
        fi

        # 其他详情，使用全角空格 (　) 填充较短的标签以对齐冒号
        printf "%s: ${CYAN}%s${RESET}\n" "镜像　　" "$image"
        printf "%s: ${CYAN}%s${RESET}\n" "重启策略" "$policy"
        printf "%s: ${CYAN}%s${RESET}\n" "创建时间" "$(date -d "$created_at" '+%Y-%m-%d %H:%M:%S')"
        printf "%s: ${CYAN}%s${RESET}\n" "端口映射" "$ports"
        printf "%s: ${CYAN}%s${RESET}\n" "目录映射" "$mounts"
        
        echo "------------------------------------------------------------------"

        echo -e "  1) ${GREEN}启动${RESET}"; echo -e "  2) ${YELLOW}停止${RESET}"; echo -e "  3) ${YELLOW}重启${RESET}"; echo -e "  4) ${GREEN}查看日志 (实时)${RESET}"; echo -e "  5) ${GREEN}进入容器 (Shell)${RESET}"; echo -e "  6) ${GREEN}查看完整信息 (Inspect JSON)${RESET}"
        local policy_display=$(printf "${BLUE}%s${RESET}" "$policy"); echo -e "  7) ${YELLOW}管理重启策略 (${policy_display}${YELLOW})${RESET}"; echo -e "  8) ${YELLOW}编辑容器 (向导/文件)${RESET}"; echo -e "  9) ${CYAN}更新容器 (拉取新镜像)${RESET}"; echo -e " 10) ${RED}删除容器${RESET}"; echo "------------------------------------------------------------------"
        read -p "请输入数字选择操作, 或输入 'q' 返回上级菜单: " choice
        case $choice in
            1) log_info "正在启动容器..."; docker start "$container_id" && log_success "启动成功。" || log_error "启动失败."; press_enter_to_continue;;
            2) log_info "正在停止容器..."; docker stop "$container_id" && log_success "停止成功。" || log_error "停止失败."; press_enter_to_continue;;
            3) log_info "正在重启容器..."; docker restart "$container_id" && log_success "重启成功。" || log_error "重启失败."; press_enter_to_continue;;
            4) clear; log_header "实时日志 (按 Ctrl+C 退出返回菜单)"; docker logs -f --tail 100 "$container_id";;
            5) clear; log_header "进入容器 Shell"; read -p "请输入要执行的 Shell (默认: /bin/bash, /bin/sh): " shell_to_use
                if [ -z "$shell_to_use" ]; then log_info "未指定 Shell，将依次尝试 /bin/bash 和 /bin/sh..."; docker exec -it "$container_id" /bin/bash || docker exec -it "$container_id" /bin/sh; else log_info "正在尝试进入容器使用指定的 Shell: ${shell_to_use}..."; docker exec -it "$container_id" "$shell_to_use"; fi;;
            6) clear; log_header "容器完整信息 (按 'q' 键退出)"; echo "$inspect_json" | jq . | less -R;;
            7) manage_restart_policy "$container_id";;
            8)
                clear; log_header "选择编辑模式"; echo " 1) ${GREEN}交互式向导模式 (推荐，简单)${RESET}"; echo " 2) ${YELLOW}配置文件模式 (高级，强大)${RESET}"
                read -p "请选择 (默认 1): " edit_mode
                case $edit_mode in 2) edit_container_file "$container_id" "$container_name" "$inspect_json";; *) edit_container_interactive "$container_id" "$container_name" "$inspect_json";; esac
                if [ $? -eq 0 ]; then return; fi;;
            9) update_container "$container_id" "$container_name"; if [ $? -eq 0 ]; then return; fi;;
            10) log_info "警告：这是一个不可逆操作！"; read -p "确定要删除容器 '${container_name}' 吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then log_info "正在删除容器..."; docker rm -f "$container_id" && log_success "删除成功。" || log_error "删除失败."; press_enter_to_continue; return; else log_info "已取消删除。"; press_enter_to_continue; fi;;
            [qQ]) return;;
            *) log_error "无效输入，请重试。"; press_enter_to_continue;;
        esac
    done
}

# --- 主程序 ---
main_loop() {
    while true; do
        clear
        echo "============================================="
        echo "      Docker 容器交互式管理工具 v9.8         "
        echo "============================================="
        
        mapfile -t containers < <(docker ps -a --format "{{.ID}}\t{{.Names}}")
        
        if [ ${#containers[@]} -eq 0 ]; then
            log_info "系统中没有找到任何 Docker 容器。"
        else
            log_header "容器列表"
            printf "${WHITE}%-4s %-22s %-40s %-s${RESET}\n" "NO." "NAME" "IMAGE" "STATUS"
            printf "${WHITE}%-4s %-22s %-40s %-s${RESET}\n" "----" "----------------------" "----------------------------------------" "--------------------------"
            
            i=1
            for line in "${containers[@]}"; do
                IFS=$'\t' read -r id name <<< "$line"; local details_json; details_json=$(docker inspect "$id")
                local parsed_data; parsed_data=$(echo "$details_json" | jq -r '.[0] | (.RepoTags[0] // .Config.Image // .Image | sub(":latest$"; "")) + "\t" + (.State.Running|tostring) + "\t" + .State.StartedAt + "\t" + .State.FinishedAt + "\t" + (.State.ExitCode|tostring) + "\t" + (.HostConfig.RestartPolicy.Name // "no") + "\t" + (.HostConfig.PortBindings | if . == null or . == {} then "无" else (to_entries | map("\(.value[0].HostPort) -> \(.key)") | join(", ")) end) + "\t" + (.Mounts | if . == [] then "无" else (map((.Source | sub(env.HOME; "~")) + " -> " + .Destination) | join(", ")) end)')
                IFS=$'\t' read -r image is_running started_at finished_at exit_code policy ports mounts <<< "$parsed_data"
                local status_string=""; if [[ "$is_running" == "true" ]]; then local start_time=$(date -d "$started_at" '+%m-%d %H:%M'); status_string="Up since ${start_time}"; else if [[ "$finished_at" != "0001-01-01"* ]]; then local finish_time=$(date -d "$finished_at" '+%m-%d %H:%M'); status_string="Exited(${exit_code}) at ${finish_time}"; else status_string="Created"; fi; fi
                local truncated_name=$(printf "%.22s" "$name"); local truncated_image=$(printf "%.40s" "$image")
                if [[ "$is_running" == "true" ]]; then printf "%-4s ${GREEN}%-22s${RESET} %-40s %s\n" "$i)" "$truncated_name" "$truncated_image" "$status_string"; else printf "%-4s ${RED}%-22s${RESET} %-40s %s\n" "$i)" "$truncated_name" "$truncated_image" "$status_string"; fi
                local truncated_ports=$(printf "%.30s" "$ports"); local truncated_mounts=$(printf "%.35s" "$mounts")
                printf "    ${CYAN}-> Policy:${RESET} ${MAGENTA}%-15.15s${RESET} ${CYAN}-> Ports:${RESET} ${MAGENTA}%-30.30s${RESET} ${CYAN}-> Mounts:${RESET} ${MAGENTA}%s${RESET}\n" "$policy" "$truncated_ports" "$truncated_mounts"
                i=$((i+1))
            done
        fi
        
        echo
        log_info "输入 'image' 进入镜像管理, 'tools' (或回车) 进入工具箱, 'q' 退出"
        local term_width=$(tput cols 2>/dev/null || echo 80); printf '%.0s─' $(seq 1 $term_width); echo

        read -p "请输入容器序号或指令: " choice

        case $choice in
            [qQ]) echo "感谢使用，脚本退出。"; break;;
            image) manage_images;;
            ""|tools) show_tools_menu;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#containers[@]} ]; then
                    selected_line=${containers[$((choice-1))]}; IFS=$'\t' read -r container_id container_name <<< "$selected_line"
                    show_container_actions_menu "$container_id" "$container_name"
                else
                    if [ -n "$choice" ]; then log_error "无效输入，请输入列表中的数字或指令。"; press_enter_to_continue; fi
                fi;;
        esac
    done
}

# --- 脚本入口 ---
install_docker_if_needed
check_dependencies
main_loop
