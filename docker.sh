#!/bin/bash

# ==============================================================================
# Docker 容器交互式管理工具 v1.0


# --- 配置颜色输出 ---
if tput setaf 1 >&/dev/null; then
    GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); RED=$(tput setaf 1); CYAN=$(tput setaf 6); BLUE=$(tput setaf 4); MAGENTA=$(tput setaf 5); WHITE=$(tput setaf 7); GRAY=$(tput setaf 8); RESET=$(tput sgr0)
else
    GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; BLUE="\033[0;34m"; MAGENTA="\033[0;35m"; WHITE="\033[1;37m"; GRAY="\033[0;90m"; RESET="\033[0m"
fi

# --- 全局变量 ---
COMPOSE_CMD=""
COMPOSE_DIRS_CONFIG_FILE="$HOME/.docker_manager_compose_dirs"
# 创建YML时的默认目录
DEFAULT_COMPOSE_CREATE_DIR="/root/docker-compose"


# --- Helper 函数 ---
log_success() { echo -e "${GREEN}[✓] $1${RESET}"; }
log_info() { echo -e "${YELLOW}[!] $1${RESET}"; }
log_error() { echo -e "${RED}[✗] $1${RESET}" >&2; }
log_header() { echo -e "\n${CYAN}--- $1 ---${RESET}"; }

command_exists() { command -v "$1" &> /dev/null; }
press_enter_to_continue() { read -p "按 Enter 键继续..." ; }

# 获取可用文本编辑器的函数
get_editor() {
    if [[ -n "$EDITOR" ]] && command_exists "$EDITOR"; then
        echo "$EDITOR"
    elif command_exists "nano"; then
        echo "nano"
    elif command_exists "vi"; then
        echo "vi"
    else
        echo "" # 未找到任何编辑器
    fi
}

# --- 请将下面两个函数添加到 Helper 函数区域 ---

# --- 工具箱：安装快捷方式 ---
install_shortcut() {
    local SCRIPT_PATH
    SCRIPT_PATH=$(readlink -f "$0") # 获取当前脚本的绝对路径
    local SHORTCUT_PATH="/usr/local/bin/docker-mgr"

    log_header "安装终端快捷方式 (docker-mgr)"
    if [[ $EUID -ne 0 ]] && ! command_exists sudo; then
        log_error "此操作需要 root 权限或 sudo。"
        press_enter_to_continue
        return
    fi
    
    # 检查快捷方式是否已存在
    if [ -e "$SHORTCUT_PATH" ]; then
        # 如果已存在，检查它是否指向当前脚本
        if [[ "$(readlink -f "$SHORTCUT_PATH")" == "$SCRIPT_PATH" ]]; then
            log_success "快捷方式 'docker-mgr' 已安装，无需任何操作。"
            press_enter_to_continue
            return
        else
            read -p "快捷方式 'docker-mgr' 已存在但指向其他文件，是否覆盖? (y/N): " confirm
            if [[ ! "$confirm" =~ ^[yY]$ ]]; then
                log_info "已取消安装。"
                press_enter_to_continue
                return
            fi
        fi
    fi
    
    log_info "正在创建符号链接并设置权限..."
# 1. 创建或更新符号链接
if sudo ln -sf "$SCRIPT_PATH" "$SHORTCUT_PATH"; then
    # 2. 为原始脚本文件添加执行权限
    if sudo chmod +x "$SCRIPT_PATH"; then
        log_success "快捷方式 'docker-mgr' 安装/更新成功！"
        log_info "现在您可以在任何地方直接使用 'docker-mgr' 命令了。"
    else
        log_error "快捷方式已创建，但为脚本添加执行权限失败。"
    fi
else
    log_error "安装失败。请检查权限。"
fi
press_enter_to_continue
}

# --- 工具箱：卸载快捷方式 ---
uninstall_shortcut() {
    local SHORTCUT_PATH="/usr/local/bin/docker-mgr"
    
    log_header "卸载终端快捷方式 (docker-mgr)"
    if [[ $EUID -ne 0 ]] && ! command_exists sudo; then
        log_error "此操作需要 root 权限或 sudo。"
        press_enter_to_continue
        return
    fi

    if [ -L "$SHORTCUT_PATH" ]; then # 使用 -L 确保我们只删除符号链接
        read -p "确定要卸载快捷方式 'docker-mgr' 吗? (y/N): " confirm
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            log_info "正在删除符号链接: ${SHORTCUT_PATH}"
            if sudo rm -f "$SHORTCUT_PATH"; then
                log_success "快捷方式 'docker-mgr' 卸载成功。"
            else
                log_error "卸载失败。请检查权限。"
            fi
        else
            log_info "已取消卸载。"
        fi
    else
        log_info "快捷方式 'docker-mgr' 未安装或不是一个符号链接。"
    fi
    press_enter_to_continue
}

# --- 请将这个新菜单函数添加到 Helper 函数区域 ---

# --- 工具箱：快捷方式管理菜单 ---
manage_shortcut_menu() {
    while true; do
        clear
        log_header "管理终端快捷方式 (docker-mgr)"

        # 智能检测安装状态
        local SCRIPT_PATH=$(readlink -f "$0")
        local SHORTCUT_PATH="/usr/local/bin/docker-mgr"
        local install_status_text
        local install_status_color

        if [[ -L "$SHORTCUT_PATH" && "$(readlink -f "$SHORTCUT_PATH")" == "$SCRIPT_PATH" ]]; then
            install_status_color=${GREEN}
            install_status_text="(已安装)"
        else
            install_status_color=${YELLOW}
            install_status_text="(未安装)"
        fi

        echo -e "  1) ${install_status_color}安装 / 更新快捷方式 ${install_status_text}${RESET}"
        echo "  2) 卸载快捷方式"
        echo ""
        echo "  q) 返回工具箱"
        echo "-------------------------------------"
        read -p "请选择功能: " choice

        case $choice in
            1) install_shortcut;;
            2) uninstall_shortcut;;
            [qQ]) return;;
            *) log_error "无效选项。"; press_enter_to_continue;;
        esac
    done
}


# --- 依赖检查 ---
check_dependencies() {
    # 1. 检查 sudo
    if ! command_exists sudo; then
        clear
        log_error "核心依赖 'sudo' 未找到。"
        if [[ $EUID -eq 0 ]]; then
            log_info "当前用户是 root，正在尝试为您安装 sudo..."
            if command_exists apt-get; then apt-get update && apt-get install -y sudo;
            elif command_exists yum; then yum install -y sudo;
            elif command_exists dnf; then dnf install -y sudo;
            else
                log_error "无法确定包管理器，请手动安装 sudo 后再运行此脚本。"
                exit 1
            fi
            if ! command_exists sudo; then
                 log_error "sudo 安装失败，请手动安装。"
                 exit 1
            else
                 log_success "sudo 安装成功！"
                 press_enter_to_continue
            fi
        else
            log_error "当前用户不是 root，且系统中没有 sudo。请联系系统管理员安装 sudo。"
            exit 1
        fi
    fi

    # 2. 检查 jq
    if ! command_exists jq; then
        clear
        log_info "高级功能需要 'jq' (JSON 解析器)。"
        read -p "系统未检测到 jq, 是否需要自动为您安装? (y/N): " choice
        if [[ "$choice" =~ ^[yY]$ ]]; then
            log_info "正在尝试安装 jq..."
            if command_exists apt-get; then sudo apt-get update && sudo apt-get install -y jq;
            elif command_exists yum; then sudo yum install -y jq;
            elif command_exists dnf; then sudo dnf install -y jq;
            else log_error "无法确定包管理器，请手动安装 jq。"; fi

            if command_exists jq; then log_success "jq 安装成功！";
            else log_error "jq 安装失败。"; fi
            press_enter_to_continue
        else
            log_error "用户取消安装。部分功能可能无法正常显示。"; press_enter_to_continue
        fi
    fi
    # --- 可以将这段代码添加到 check_dependencies 函数中 ---

    # 4. 检查 file 命令
    if ! command_exists file; then
        clear
        log_info "核心功能需要 'file' (文件类型识别工具)。"
        read -p "系统未检测到 file, 是否需要自动为您安装? (y/N): " choice
        if [[ "$choice" =~ ^[yY]$ ]]; then
            log_info "正在尝试安装 file..."
            if command_exists apt-get; then sudo apt-get update && sudo apt-get install -y file;
            elif command_exists yum; then sudo yum install -y file;
            elif command_exists dnf; then sudo dnf install -y file;
            else log_error "无法确定包管理器，请手动安装 file。"; fi

            if command_exists file; then log_success "file 安装成功！";
            else log_error "file 安装失败。"; fi
            press_enter_to_continue
        else
            log_error "用户取消安装。部分功能可能无法正常运行。"; press_enter_to_continue
        fi
    fi

    # 3. 检查并设置 docker-compose 命令
    if docker compose version &>/dev/null; then
        COMPOSE_CMD="docker compose"
    elif command_exists docker-compose; then
        COMPOSE_CMD="docker-compose"
    fi

    if [[ -z "$COMPOSE_CMD" ]]; then
        clear
        log_info "推荐使用 'docker-compose' (或 Docker Compose V2 插件)。"
        read -p "系统未检测到 docker-compose, 是否需要自动为您安装? (y/N): " choice
        if [[ "$choice" =~ ^[yY]$ ]]; then
            if ! command_exists curl; then
                log_info "安装 docker-compose 需要 curl，正在尝试安装 curl..."
                if command_exists apt-get; then sudo apt-get update && sudo apt-get install -y curl;
                elif command_exists yum; then sudo yum install -y curl;
                elif command_exists dnf; then sudo dnf install -y curl;
                else log_error "无法安装 curl，请手动安装后再尝试。"; press_enter_to_continue; return; fi
            fi

            local installed_successfully=false
            local kernel_name=$(uname -s | tr '[:upper:]' '[:lower:]')
            local machine_arch=$(uname -m)
            local asset_name="docker-compose-${kernel_name}-${machine_arch}"
            local target_path="/usr/local/bin/docker-compose"

            download_and_verify() {
                local url=$1
                if sudo curl -fL "$url" -o "$target_path"; then
                    if file "$target_path" | grep -q "executable"; then
                        return 0
                    else
                        log_error "下载的文件不是一个有效的可执行文件，已删除。"
                        sudo rm -f "$target_path"
                        return 1
                    fi
                else
                    return 1
                fi
            }

            log_info "正在从 GitHub 获取最新版本的 docker-compose (方法 1: API)..."
            local LATEST_COMPOSE_URL
            LATEST_COMPOSE_URL=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | jq -r ".assets[] | select(.name == \"${asset_name}\") | .browser_download_url" 2>/dev/null)
            
            if [[ -n "$LATEST_COMPOSE_URL" ]]; then
                log_info "已成功获取下载链接，准备下载..."
                if download_and_verify "$LATEST_COMPOSE_URL"; then
                    installed_successfully=true
                else
                    log_error "docker-compose 下载或验证失败 (方法 1)。"
                fi
            else
                log_info "无法通过 API 获取直链 (方法 1 失败)。"
            fi
            
            if [ "$installed_successfully" = false ]; then
                log_info "正在尝试备用方法 (镜像代理)..."
                local LATEST_TAG
                LATEST_TAG=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | jq -r .tag_name 2>/dev/null)
                
                if [[ -z "$LATEST_TAG" ]]; then
                    log_error "无法从 GitHub API 获取最新版本号。"
                else
                    log_info "已获取最新版本号: ${LATEST_TAG}。"
                    declare -a PROXY_URLS=(
                        "https://mirror.ghproxy.com/"
                        "https://ghproxy.net/"
                    )
                    
                    for proxy in "${PROXY_URLS[@]}"; do
                        local FALLBACK_URL="${proxy}https://github.com/docker/compose/releases/download/${LATEST_TAG}/${asset_name}"
                        log_info "正在通过代理 '${proxy}' 下载..."
                        if download_and_verify "$FALLBACK_URL"; then
                            installed_successfully=true
                            break
                        else
                            log_error "通过代理 '${proxy}' 下载失败。正在尝试下一个..."
                        fi
                    done
                fi
            fi

            if [ "$installed_successfully" = true ]; then
                sudo chmod +x "$target_path"
                COMPOSE_CMD="/usr/local/bin/docker-compose"
                log_success "docker-compose 安装成功！"
                log_info "$($COMPOSE_CMD --version)"
            else
                log_error "所有自动安装方法均失败。请手动安装 docker-compose。"
            fi
            press_enter_to_continue
        else
            log_info "用户取消安装。相关功能将不可用。"; press_enter_to_continue
        fi
    fi
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

# --- COMPOSE: Helper functions for directory management ---
load_compose_dirs() {
    if [[ ! -f "$COMPOSE_DIRS_CONFIG_FILE" ]]; then
        touch "$COMPOSE_DIRS_CONFIG_FILE"
    fi
    mapfile -t compose_dirs < "$COMPOSE_DIRS_CONFIG_FILE"
    # 过滤掉空行
    compose_dirs=($(for dir in "${compose_dirs[@]}"; do echo "$dir"; done | grep .))
}

save_compose_dirs() {
    printf "%s\n" "${compose_dirs[@]}" > "$COMPOSE_DIRS_CONFIG_FILE"
}

add_compose_dir() {
    read -e -p "请输入包含 docker-compose yml 文件的目录的绝对路径: " new_dir
    
    # 移除路径末尾的斜杠
    new_dir=${new_dir%/}

    if [[ ! -d "$new_dir" ]]; then
        log_error "错误: 目录 '$new_dir' 不存在。"
        press_enter_to_continue
        return
    fi
    
    # 检查是否存在任何 docker-compose*.yml 或 compose*.yml 文件
    if ! find "$new_dir" -maxdepth 1 -type f \( -name "docker-compose*.yml" -o -name "compose*.yml" \) -print -quit | grep -q .; then
        log_error "错误: 在 '$new_dir' 中未找到任何 'compose*.yml' 或 'docker-compose*.yml' 文件。"
        press_enter_to_continue
        return
    fi

    # 检查目录是否已存在
    for dir in "${compose_dirs[@]}"; do
        if [[ "$dir" == "$new_dir" ]]; then
            log_info "目录 '$new_dir' 已存在于列表中。"
            press_enter_to_continue
            return
        fi
    done

    compose_dirs+=("$new_dir")
    save_compose_dirs
    log_success "目录 '$new_dir' 添加成功。"
    press_enter_to_continue
}

delete_compose_dir() {
    if [ ${#compose_dirs[@]} -eq 0 ]; then
        log_info "没有可删除的目录。"
        press_enter_to_continue
        return
    fi
    
    log_header "选择要删除的目录"
    i=1
    for dir in "${compose_dirs[@]}"; do
        echo "  $i) $dir"
        i=$((i+1))
    done
    echo "  q) 取消"
    read -p "请输入序号: " choice

    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#compose_dirs[@]} ]; then
        local index_to_delete=$((choice-1))
        local dir_to_delete=${compose_dirs[$index_to_delete]}
        read -p "确定要从列表中删除 '$dir_to_delete' 吗? (y/N): " confirm
        if [[ "$confirm" =~ ^[yY]$ ]]; then
            unset 'compose_dirs[index_to_delete]'
            # 重建数组以消除空位
            compose_dirs=("${compose_dirs[@]}")
            save_compose_dirs
            log_success "目录已删除。"
        else
            log_info "已取消删除。"
        fi
    elif [[ "$choice" != "q" ]]; then
        log_error "无效的序号。"
    fi
    press_enter_to_continue
}

# --- COMPOSE: YML 文件创建向导 ---
create_compose_yml() {
    clear
    log_header "创建新的 Docker Compose 项目 (向导)"

    # 1. 获取要创建新项目的父目录
    local base_dir
    read -e -p "请输入要创建新项目的【父目录】 [默认: ${DEFAULT_COMPOSE_CREATE_DIR}]: " base_dir
    if [[ -z "$base_dir" ]]; then
        base_dir="$DEFAULT_COMPOSE_CREATE_DIR"
    fi
    base_dir=${base_dir%/} # 移除末尾斜杠

    # 确保父目录存在，如果不存在则询问是否创建
    if [[ ! -d "$base_dir" ]]; then
        read -p "父目录 '${base_dir}' 不存在, 是否要创建它? (y/N): " create_dir_confirm
        if [[ "$create_dir_confirm" =~ ^[yY]$ ]]; then
            if ! mkdir -p "$base_dir"; then
                log_error "创建父目录 '${base_dir}' 失败。"
                press_enter_to_continue
                return
            fi
            log_success "父目录 '${base_dir}' 创建成功。"
        else
            log_info "操作已取消。"
            press_enter_to_continue
            return
        fi
    fi

    # 2. 获取新项目的名称，这将作为目录名
    local project_name
    while true; do
        read -p "请输入【新项目的名称】 (这将作为目录名, 如: my-app): " project_name
        if [[ -z "$project_name" ]]; then
            log_error "项目名称不能为空。"
        elif [[ ! "$project_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            log_error "项目名称只能包含字母、数字、下划线(_)和连字符(-)。"
        else
            break
        fi
    done

    # 3. 构建新的项目目录路径，并检查是否已存在
    local project_dir_path="${base_dir}/${project_name}"
    if [[ -d "$project_dir_path" ]]; then
        log_error "错误: 项目目录 '${project_dir_path}' 已存在，请换一个项目名称。"
        press_enter_to_continue
        return
    fi
    
    # 4. 创建新的项目目录
    log_info "正在创建新项目目录: ${project_dir_path}"
    if ! mkdir -p "$project_dir_path"; then
        log_error "创建目录 '${project_dir_path}' 失败。"
        press_enter_to_continue
        return
    fi

    # 5. 在新目录中创建空的 docker-compose.yml 文件
    local yml_file_path="${project_dir_path}/docker-compose.yml"
    log_info "正在创建空的配置文件: ${yml_file_path}"
    touch "$yml_file_path"

    if [[ ! -f "$yml_file_path" ]]; then
        log_error "文件创建失败！"
        press_enter_to_continue
        return
    fi
    log_success "文件 '${yml_file_path}' 创建成功！"


    # 6. 自动将新的项目目录添加到管理列表
    log_info "正在自动将新项目目录添加到管理列表..."
    compose_dirs+=("$project_dir_path")
    save_compose_dirs
    log_success "目录 '${project_dir_path}' 已自动添加。"

    # 7. 询问是否立即编辑
    read -p "是否立即编辑新的 YML 文件? (Y/n): " edit_now_confirm
    if [[ ! "$edit_now_confirm" =~ ^[nN]$ ]]; then
        local editor
        editor=$(get_editor)
        if [[ -z "$editor" ]]; then
            log_error "未找到可用的文本编辑器。请手动编辑文件: ${yml_file_path}"
        else
            log_info "将在 2 秒后使用 '${editor}' 打开文件..."
            sleep 2
            $editor "$yml_file_path"
        fi
    fi
    press_enter_to_continue
}

# --- 请用这个【增加了进入容器Shell功能】的版本替换旧的 manage_services_in_directory 函数 ---
manage_services_in_directory() {
    local compose_file=$1
    local project_dir
    project_dir=$(dirname "$compose_file")

    if [[ -z "$compose_file" ]]; then
        log_error "无效的文件路径传入。"
        press_enter_to_continue
        return
    fi

    local choice=""
    while true; do
        clear
        log_header "管理目录: ${BLUE}${project_dir}${RESET}"
        log_info "使用配置文件: ${YELLOW}$(basename "$compose_file")${RESET}"
        
        local compose_output
        compose_output=$($COMPOSE_CMD -f "$compose_file" ps -a -q 2>&1)
        local exit_code=$?
        
        local errors
        errors=$(echo "$compose_output" | grep -v -E "WARN.*(obsolete|deprecated)")

        if [ $exit_code -ne 0 ] && [ -n "$errors" ]; then
            log_error "执行 docker-compose 命令时出错:"
            echo -e "${RED}${errors}${RESET}"
            press_enter_to_continue
            choice="error_occurred" 
        else
            mapfile -t container_ids < <(echo "$compose_output" | grep -v -E "WARN.*(obsolete|deprecated)")
        fi

        if [ ${#container_ids[@]} -eq 0 ] && [[ "$choice" != "error_occurred" ]]; then
            log_info "此项目当前没有已创建的服务容器。"
        elif [[ "$choice" != "error_occurred" ]]; then
            log_header "服务列表"
            for id in "${container_ids[@]}"; do
                local details_json; details_json=$(docker inspect "$id" 2>/dev/null)
                if [ -z "$details_json" ] || [ "$details_json" == "[]" ]; then
                    continue
                fi

                local name; name=$(echo "$details_json" | jq -r '.[0].Name | sub("^/"; "")')
                local parsed_data; parsed_data=$(echo "$details_json" | jq -r '.[0] | (.RepoTags[0] // .Config.Image // .Image) + "\t" + (.State.Running | tostring) + "\t" + .State.StartedAt + "\t" + .State.FinishedAt + "\t" + (.State.ExitCode | tostring) + "\t" + (.HostConfig.RestartPolicy.Name // "no") + "\t" + (.HostConfig.PortBindings | if . == null or . == {} then "N/A" else (to_entries | map((if .value[0].HostIp and .value[0].HostIp != "" then .value[0].HostIp + ":" else "" end) + .value[0].HostPort + " -> " + .key) | join(", ")) end) + "\t" + (.Mounts | if . == [] then "N/A" else (map((.Source | sub(env.HOME; "~")) + " -> " + .Destination) | join(", ")) end)')
                IFS=$'\t' read -r image is_running started_at finished_at exit_code policy ports mounts <<< "$parsed_data"
                
                local status_string=""
                if [[ "$is_running" == "true" ]]; then 
                    local start_time=$(date -d "$started_at" '+%Y-%m-%d %H:%M'); status_string="Up since ${start_time}"
                else 
                    if [[ "$finished_at" != "0001-01-01T00:00:00Z" && "$finished_at" != null ]]; then 
                        local finish_time=$(date -d "$finished_at" '+%Y-%m-%d %H:%M'); status_string="Exited(${exit_code}) at ${finish_time}"
                    else 
                        status_string="Created"
                    fi
                fi
                local name_color=${WHITE}; if [[ "$is_running" == "true" ]]; then name_color=${GREEN}; else name_color=${RED}; fi
                
                printf "%-30.30s %s\n" "${name_color}${name}${RESET}" "$status_string"
                printf "     ${CYAN}├─ Image:${RESET} ${MAGENTA}%s${RESET}\n" "$image"
                printf "     ${CYAN}├─ Policy:${RESET} ${MAGENTA}%s${RESET}\n" "$policy"
                printf "     ${CYAN}├─ Ports:${RESET} ${MAGENTA}%s${RESET}\n" "$ports"
                printf "     ${CYAN}└─ Mounts:${RESET} ${MAGENTA}%s${RESET}\n" "$mounts"
                echo
            done
        fi
        
        echo "--------------------------------------------------"
        echo -e "  1) ${GREEN}启动 / 应用配置 (up -d)${RESET}"
        echo -e "  2) ${CYAN}更新镜像并重建 (pull & up)${RESET}"
        echo -e "  3) ${YELLOW}停止服务 (stop)${RESET}"
        echo -e "  4) ${YELLOW}重启服务 (restart)${RESET}"
        echo -e "  5) ${RED}关闭并移除服务 (down)${RESET}"
        echo -e "  6) ${BLUE}编辑 YML 并重建${RESET}"
        echo -e "  7) ${GREEN}查看实时日志 (logs -f)${RESET}"
        echo -e "  8) ${BLUE}进入容器 Shell${RESET}" # <--- 新增的选项
        echo "--------------------------------------------------"
        echo "  q) 返回目录列表"
        echo "--------------------------------------------------"
        
        if [[ "$choice" == "error_occurred" ]]; then
            choice="" # Reset choice
            continue
        fi

        read -p "请选择操作: " choice

        case $choice in
            1) log_info "正在启动服务或应用新配置..."; $COMPOSE_CMD -f "$compose_file" up -d; press_enter_to_continue;;
            2)
                log_info "此操作将拉取最新镜像并强制重建所有服务！"
                read -p "确定要更新吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    log_info "正在为项目拉取最新镜像..."
                    if $COMPOSE_CMD -f "$compose_file" pull; then
                        log_info "镜像拉取成功，正在强制重建服务..."
                        if $COMPOSE_CMD -f "$compose_file" up -d --force-recreate; then
                            log_success "项目更新并重建成功！"
                        else
                            log_error "项目重建失败！"
                        fi
                    else
                        log_error "镜像拉取失败，已中止操作。"
                    fi
                else
                    log_info "已取消更新。"
                fi
                press_enter_to_continue
                ;;
            3) log_info "正在停止项目..."; $COMPOSE_CMD -f "$compose_file" stop; press_enter_to_continue;;
            4) log_info "正在重启项目..."; $COMPOSE_CMD -f "$compose_file" restart; press_enter_to_continue;;
            5) 
                log_error "警告: 此操作将停止并移除项目的容器、网络！"
                read -p "确定要关闭项目吗? (y/N): " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    log_info "正在关闭项目..."; $COMPOSE_CMD -f "$compose_file" down; log_success "项目已关闭。"
                else
                    log_info "已取消。"
                fi
                press_enter_to_continue
                ;;
            6)
                local editor
                editor=$(get_editor)
                if [[ -z "$editor" ]]; then
                    log_error "系统中未找到可用的文本编辑器 (如 nano 或 vi)。"
                    press_enter_to_continue
                    continue
                fi

                log_info "将在 2 秒后使用 '${editor}' 打开配置文件..."; sleep 2;
                $editor "$compose_file"
                log_info "配置文件已修改。"
                read -p "是否立即使用新配置重建项目? (Y/n): " rebuild_confirm
                if [[ ! "$rebuild_confirm" =~ ^[nN]$ ]]; then
                    log_info "正在拉取新镜像并强制重建服务..."
                    $COMPOSE_CMD -f "$compose_file" pull
                    if $COMPOSE_CMD -f "$compose_file" up -d --build --force-recreate; then
                        log_success "项目重建成功！"
                    else
                        log_error "项目重建失败！"
                    fi
                else
                    log_info "已取消重建。"
                fi
                press_enter_to_continue
                ;;
            7) clear; log_header "实时日志: ${project_dir} (按 Ctrl+C 退出)"; $COMPOSE_CMD -f "$compose_file" logs -f --tail 100;;
            
            # --- 新增的逻辑 ---
            8)
                mapfile -t running_services < <($COMPOSE_CMD -f "$compose_file" ps --services 2>/dev/null)

                if [ ${#running_services[@]} -eq 0 ]; then
                    log_error "此项目中没有正在运行的服务可供进入。"
                    press_enter_to_continue
                    continue
                fi
                
                local selected_service=""
                if [ ${#running_services[@]} -eq 1 ]; then
                    selected_service=${running_services[0]}
                else
                    clear
                    log_header "选择要进入的服务容器"
                    i=1
                    for service in "${running_services[@]}"; do
                        echo "  $i) $service"
                        i=$((i+1))
                    done
                    echo "  q) 取消"
                    read -p "请输入序号: " service_choice

                    if [[ "$service_choice" =~ ^[0-9]+$ ]] && [ "$service_choice" -ge 1 ] && [ "$service_choice" -le ${#running_services[@]} ]; then
                        selected_service=${running_services[$((service_choice-1))]}
                    elif [[ "$service_choice" != "q" ]]; then
                        log_error "无效的序号。"
                        press_enter_to_continue
                        continue
                    fi
                fi
                
                if [[ -n "$selected_service" ]]; then
    clear
    log_info "已选定服务: '${YELLOW}${selected_service}${RESET}'"

    local command_to_run
    # 给出提示，让用户直接回车或输入自定义命令
    read -e -p "请直接回车进入Shell(默认bash/sh)，或输入自定义命令: " command_to_run

    if [[ -z "$command_to_run" ]]; then
        # 用户直接回车，执行默认的、健壮的Shell进入逻辑
        log_info "正在尝试进入 Shell (依次尝试 /bin/bash, /bin/sh)..."
        log_info "输入 'exit' 或按 Ctrl+D 退出"
        sleep 1
        $COMPOSE_CMD -f "$compose_file" exec "$selected_service" /bin/bash || $COMPOSE_CMD -f "$compose_file" exec "$selected_service" /bin/sh
    else
        # 用户输入了自定义命令，直接执行
        log_info "正在容器内执行自定义命令: '${CYAN}${command_to_run}${RESET}'..."
        $COMPOSE_CMD -f "$compose_file" exec "$selected_service" ${command_to_run}
    fi

    # 为了防止非交互式命令（如 ls -l）的输出被立刻清屏，在这里暂停
    press_enter_to_continue

else
    log_info "操作已取消。"
    sleep 1
fi
                ;;
            # --- 逻辑结束 ---
            
            [qQ]) return;;
            *) 
                log_error "无效选项。"
                sleep 1
                ;;
        esac
    done
}

# --- 这是最终版 manage_compose_projects 函数，采用智能拦截方式处理自动发现项目 ---
manage_compose_projects() {
    if [[ -z "$COMPOSE_CMD" ]]; then
        log_error "系统中未找到 'docker compose' 或 'docker-compose' 命令。"
        log_info "请先确保 Docker Compose 已正确安装。"
        press_enter_to_continue
        return
    fi

    declare -g -a compose_dirs=()
    
    while true; do
        load_compose_dirs 
        clear
        log_header "Docker Compose 项目管理"

        declare -a managed_files=()
        for dir in "${compose_dirs[@]}"; do
            mapfile -t files_in_dir < <(find "$dir" -maxdepth 1 -type f \( -name "docker-compose*.yml" -o -name "compose*.yml" \) 2>/dev/null | sort)
            for file in "${files_in_dir[@]}"; do
                managed_files+=("$file")
            done
        done

        declare -a discovered_files=()
        mapfile -t discovered_files < <(docker ps -a --filter "label=com.docker.compose.project" --format '{{.Label "com.docker.compose.project.config_files"}}' | sort -u | grep .)

        declare -a all_manageable_files=()
        mapfile -t all_manageable_files < <( (printf "%s\n" "${managed_files[@]}"; printf "%s\n" "${discovered_files[@]}") | sort -u | grep . )


        if [ ${#all_manageable_files[@]} -eq 0 ]; then
            log_info "在已管理的目录中，且系统中，均未找到任何 Compose YML 文件或项目。"
        else
            printf "${WHITE}%-4s %-12s %-s${RESET}\n" "NO." "来源" "Compose 项目"
            printf "${WHITE}%-4s %-12s %-s${RESET}\n" "----" "------------" "----------------------------------------------------------------------"
            
            i=1
            for compose_file in "${all_manageable_files[@]}"; do
                local project_dir=$(dirname "$compose_file")
                local is_managed=false
                for dir in "${compose_dirs[@]}"; do
                    if [[ "$dir" == "$project_dir" ]]; then
                        is_managed=true
                        break
                    fi
                done

                local source_tag=""
                if [[ "$is_managed" = true ]]; then
                    source_tag="${GREEN}[已管理]${RESET}"
                else
                    source_tag="${YELLOW}[自动发现]${RESET}"
                fi
                
                local display_path="${compose_file#$HOME/}"
                display_path="~/$display_path"

                # 恢复所有项目的序号显示
                printf "\n%-4s %-12b %s\n" "$i)" "${source_tag}" "${CYAN}${display_path}${RESET}"
                
                # ... (后续显示服务列表的逻辑完全不变) ...
                unset container_states
                declare -A container_states
                local ps_output
                ps_output=$($COMPOSE_CMD -f "$compose_file" ps -a --format '{{.ID}}\t{{.Service}}' 2>&1 | grep -v -E "(WARN|level=warning).*obsolete")
                if [ -n "$ps_output" ]; then
                    while IFS=$'\t' read -r id service_name; do
                        if [[ -n "$id" ]]; then
                            local details_json; details_json=$(docker inspect "$id" 2>/dev/null)
                            if [[ -n "$details_json" && "$details_json" != "[]" ]]; then
                                container_states["$service_name"]=$(echo "$details_json" | jq -c '.[0].State')
                            fi
                        fi
                    done <<< "$ps_output"
                fi

                local config_json
                config_json=$($COMPOSE_CMD -f "$compose_file" config --format json 2>/dev/null)
                if [ -z "$config_json" ]; then
                    printf "      ${RED}%s${RESET}\n" "├─ (无法解析配置文件)"
                    i=$((i+1))
                    continue
                fi
                mapfile -t defined_services < <(echo "$config_json" | jq -r '.services | keys[]' | grep .)
                if [ ${#defined_services[@]} -eq 0 ]; then
                        printf "      ${MAGENTA}%s${RESET}\n" "├─ (文件中未定义服务)"
                else
                    printf "      ${WHITE}%-35s %-22s %s${RESET}\n" "  服务名称" "运行状态" "详情 / 时长"
                    printf "      ${WHITE}%-35s %-22s %s${RESET}\n" "  ---------------------------------" "----------------------" "--------------------"
                    local running_list=(); local exited_list=(); local not_created_list=()
                    for service_name in "${defined_services[@]}"; do
                        local display_name="├─ $service_name"
                        if [[ -v "container_states[$service_name]" ]]; then
                            local state_json=${container_states[$service_name]}; local is_running=$(echo "$state_json" | jq -r '.Running')
                            if [[ "$is_running" == "true" ]]; then
                                local started_at=$(echo "$state_json" | jq -r '.StartedAt'); local uptime_string=""; local current_ts=$(date +%s); local start_ts=$(date -d "$started_at" +%s); local diff_seconds=$((current_ts - start_ts)); local days=$((diff_seconds/86400)); local hours=$(((diff_seconds%86400)/3600)); local mins=$(((diff_seconds%3600)/60)); local secs=$((diff_seconds%60)); if (( days > 0 )); then uptime_string="${days} 天 ${hours} 小时前"; elif (( hours > 0 )); then uptime_string="${hours} 小时 ${mins} 分钟前"; elif (( mins > 0 )); then uptime_string="${mins} 分钟 ${secs} 秒前"; else uptime_string="${secs} 秒前"; fi
                                running_list+=("$(printf "      ${GREEN}%-35s %-22s %s${RESET}" "$display_name" "(正在运行)" "$uptime_string")")
                            else
                                exited_list+=("$(printf "      ${RED}%-35s %-22s${RESET}" "$display_name" "(已创建 / 未运行)")")
                            fi
                        else
                            local image_name=$(echo "$config_json" | jq -r --arg srv "$service_name" '.services[$srv].image // "镜像未指定"')
                            not_created_list+=("$(printf "      ${GRAY}%-35s %-22s ${WHITE}%s${RESET}" "$display_name" "(未创建)" "Image: $image_name")")
                        fi
                    done
                    for item in "${running_list[@]}"; do echo -e "$item"; done
                    for item in "${exited_list[@]}"; do echo -e "$item"; done
                    for item in "${not_created_list[@]}"; do echo -e "$item"; done
                fi
                i=$((i+1))
            done
        fi

        echo "--------------------------------------------------------------------------------"
        echo "操作指令: a)添加, d)删除, c)创建, m <序号|all>(添加), <已管理项序号>(进入), q(返回)"
        echo "--------------------------------------------------------------------------------"
        read -p "请输入操作或文件序号: " choice

        case $choice in
            [aA]) add_compose_dir;;
            [dD]) delete_compose_dir;;
            [cC]) create_compose_yml;;
            [qQ]) return;;
            [mM]*)
                local arg_str=${choice#[mM]}; arg_str=$(echo "$arg_str" | xargs)
                declare -a target_indices=(); declare -a invalid_inputs=()
                if [[ "$arg_str" == "all" ]]; then
                    for i in "${!all_manageable_files[@]}"; do target_indices+=($((i + 1))); done
                else
                    local indices_str=${arg_str//,/ }; for num in $indices_str; do if [[ "$num" =~ ^[0-9]+$ ]]; then target_indices+=("$num"); else [[ -n "$num" ]] && invalid_inputs+=("$num"); fi; done
                fi
                declare -a dirs_to_add=();
                for num in "${target_indices[@]}"; do if [ "$num" -ge 1 ] && [ "$num" -le ${#all_manageable_files[@]} ]; then local file_path=${all_manageable_files[$((num-1))]}; dirs_to_add+=("$(dirname "$file_path")"); else invalid_inputs+=("$num"); fi; done
                declare -a unique_new_dirs=();
                if [ ${#dirs_to_add[@]} -gt 0 ]; then mapfile -t unique_new_dirs < <({ printf "%s\n" "${dirs_to_add[@]}"; printf "%s\n" "${compose_dirs[@]}"; } | sort | uniq -u); fi
                if [ ${#unique_new_dirs[@]} -gt 0 ]; then
                    compose_dirs+=("${unique_new_dirs[@]}"); save_compose_dirs
                    log_success "已成功添加以下目录至管理列表:"; for d in "${unique_new_dirs[@]}"; do echo -e "  ${GREEN}- $d${RESET}"; done
                else
                    log_info "没有新的、未被管理的目录可供添加。"
                fi
                if [ ${#invalid_inputs[@]} -gt 0 ]; then log_error "以下输入无效: ${invalid_inputs[*]}"; fi
                press_enter_to_continue
                ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#all_manageable_files[@]} ]; then
                    local selected_file=${all_manageable_files[$((choice-1))]}
                    
                    # --- 核心改动：在这里进行智能判断 ---
                    local project_dir=$(dirname "$selected_file")
                    local is_managed=false
                    for dir in "${compose_dirs[@]}"; do if [[ "$dir" == "$project_dir" ]]; then is_managed=true; break; fi; done

                    if [[ "$is_managed" == true ]]; then
                        # 如果是已管理项目，则进入
                        manage_services_in_directory "$selected_file"
                    else
                        # 如果是自动发现项目，则拦截并提示
                        log_error "此为自动发现项目，无法直接管理。"
                        log_info "请先使用 '${YELLOW}m ${choice}${RESET}' 命令将其目录添加至管理列表。"
                        press_enter_to_continue
                    fi
                else
                    log_error "无效输入或序号。"; sleep 1
                fi
                ;;
        esac
    done
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


# --- 请用这个新版本替换旧的 show_tools_menu 函数 ---
show_tools_menu() {
    while true; do
        clear
        log_header "实用工具箱"
        
        # --- 新增：动态检测快捷方式状态 ---
        local SCRIPT_PATH=$(readlink -f "$0")
        local SHORTCUT_PATH="/usr/local/bin/docker-mgr"
        local shortcut_status_text
        local shortcut_status_color

        if [[ -L "$SHORTCUT_PATH" && "$(readlink -f "$SHORTCUT_PATH")" == "$SCRIPT_PATH" ]]; then
            shortcut_status_color=${GREEN}
            shortcut_status_text="(已安装)"
        else
            shortcut_status_color=${YELLOW}
            shortcut_status_text="(未安装)"
        fi
        # --- 状态检测结束 ---

        echo "  1) 修改 Docker Hub 镜像加速源"
        echo "  2) 清理 Docker 系统 (prune)"
        echo -e "  3) ${shortcut_status_color}管理终端快捷方式 (docker-mgr) ${shortcut_status_text}${RESET}"
        echo ""
        echo "  q) 返回主菜单"
        echo "-------------------------------------"
        read -p "请选择功能: " choice
        
        case $choice in
            1) set_docker_mirror;;
            2) prune_docker_system;;
            3) manage_shortcut_menu;; # 调用新的管理菜单
            [qQ]) return;;
            *) log_error "无效选项。"; press_enter_to_continue;;
        esac
    done
}


# --- 镜像管理功能 ---
manage_images() {
    while true; do
        clear; log_header "Docker 镜像管理"
        mapfile -t images < <(docker images --format '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}')
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
    mapfile -t ports < <(echo "$inspect_json" | jq -r '.[0].HostConfig.PortBindings | to_entries[] | "-p", ((if .value[0].HostIp and .value[0].HostIp != "" then .value[0].HostIp + ":" else "" end) + .value[0].HostPort + ":" + .key)')
    [ ${#ports[@]} -gt 0 ] && run_cmd_args+=("${ports[@]}")
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

# --- 通用容器重建函数 ---
recreate_container() {
    local container_id=$1; shift
    local container_name=$1; shift
    local image_name=$1; shift
    local restart_policy=$1; shift
    
    # 从管道符分隔的字符串中恢复数组
    IFS='|' read -r -a ports <<< "$1"; shift
    IFS='|' read -r -a volumes <<< "$1"; shift
    IFS='|' read -r -a env_vars <<< "$1"; shift

    local run_cmd_args=(); run_cmd_args+=("run" "-d" "--name" "$container_name")
    
    [[ -n "$restart_policy" && "$restart_policy" != "no" ]] && run_cmd_args+=("--restart" "$restart_policy")
    
    for port in "${ports[@]}"; do [[ -n "$port" ]] && run_cmd_args+=("-p" "$port"); done
    for vol in "${volumes[@]}"; do [[ -n "$vol" ]] && run_cmd_args+=("-v" "$vol"); done
    for env_var in "${env_vars[@]}"; do [[ -n "$env_var" ]] && run_cmd_args+=("-e" "$env_var"); done
    
    run_cmd_args+=("$image_name")
    
    clear; log_info "将根据您的配置执行以下命令:"
    printf "docker "; for arg in "${run_cmd_args[@]}"; do if [[ "$arg" == *" "* ]]; then printf "'%s' " "$arg"; else printf "%s " "$arg"; fi; done; echo; echo
    
    read -p "确认执行以上命令吗? (Y/n): " final_confirm
    if [[ "$final_confirm" =~ ^[nN]$ ]]; then log_info "已取消执行。"; press_enter_to_continue; return 1; fi
    
    log_info "正在停止旧容器..."; docker stop "$container_id" > /dev/null
    log_info "正在删除旧容器..."; docker rm "$container_id" > /dev/null
    log_info "正在创建并启动新容器..."
    
    if docker "${run_cmd_args[@]}"; then
        log_success "容器编辑成功！新容器已启动。"
    else
        log_error "容器编辑失败。请检查上面的命令和错误信息。"
    fi
    press_enter_to_continue; return 0
}

# --- 容器编辑功能 (配置文件模式) ---
edit_container_file() {
    local container_id=$1; local container_name=$2; local inspect_json=$3; local temp_file; temp_file=$(mktemp "/tmp/docker_edit_${container_name}.XXXXXX.conf"); trap 'rm -f "$temp_file"' RETURN

    # --- 1. 使用更简单、更健壮的格式生成配置文件 ---
    # 直接使用jq生成 key="value" 格式的行
    cat > "$temp_file" <<-EOF
# Edit Docker Container Configuration
# Please modify the parameters below. Save and exit to apply changes.
# For multiple ports, volumes, or envs, simply add more lines in the format key="value".
# -----------------------------------------------------------------
image_name="$(echo "$inspect_json" | jq -r '.[0].Config.Image')"
restart_policy="$(echo "$inspect_json" | jq -r '.[0].HostConfig.RestartPolicy.Name // "no"')"

# --- Port Mappings (port="host:container") ---
$(echo "$inspect_json" | jq -r '.[0].HostConfig.PortBindings | to_entries | .[] | "port=\"" + ((if .value[0].HostIp and .value[0].HostIp != "" then .value[0].HostIp + ":" else "" end) + .value[0].HostPort + ":" + .key) + "\""')

# --- Volume Mappings (volume="/host:/container") ---
$(echo "$inspect_json" | jq -r '.[0].Mounts[] | "volume=\"\(.Source):\(.Destination)\""')

# --- Environment Variables (env_var="KEY=VALUE") ---
$(echo "$inspect_json" | jq -r '.[0].Config.Env[] | "env_var=\"\(.)\""')
EOF

    local editor
    editor=$(get_editor)
    if [[ -z "$editor" ]]; then
        log_error "系统中未找到可用的文本编辑器 (如 nano 或 vi)。"
        press_enter_to_continue
        return 1
    fi
    log_info "将在 3 秒后使用 '${editor}' 打开配置文件..."; sleep 3; $editor "$temp_file"
    if [ ! -s "$temp_file" ]; then log_info "配置文件为空，操作已取消。"; press_enter_to_continue; return 1; fi
    
    # --- 2. 使用更简单、更健壮的 grep 和 cut 来解析文件 ---
    # 为防止意外，先读取文件内容并处理可能存在的CRLF(Windows换行符)问题
    local file_content
    file_content=$(tr -d '\r' < "$temp_file")

    local new_image_name; new_image_name=$(echo "$file_content" | grep '^image_name=' | head -n 1 | cut -d'=' -f2- | sed 's/^"//;s/"$//')
    local new_restart_policy; new_restart_policy=$(echo "$file_content" | grep '^restart_policy=' | head -n 1 | cut -d'=' -f2- | sed 's/^"//;s/"$//')
    
    mapfile -t new_ports < <(echo "$file_content" | grep '^port=' | cut -d'=' -f2- | sed 's/^"//;s/"$//')
    mapfile -t new_volumes < <(echo "$file_content" | grep '^volume=' | cut -d'=' -f2- | sed 's/^"//;s/"$//')
    mapfile -t new_env_vars < <(echo "$file_content" | grep '^env_var=' | cut -d'=' -f2- | sed 's/^"//;s/"$//')

    # 将数组转换为管道符分隔的字符串以便传递
    local ports_str; ports_str=$(printf "%s|" "${new_ports[@]}")
    local volumes_str; volumes_str=$(printf "%s|" "${new_volumes[@]}")
    local env_vars_str; env_vars_str=$(printf "%s|" "${new_env_vars[@]}")

    recreate_container "$container_id" "$container_name" "$new_image_name" "$new_restart_policy" "$ports_str" "$volumes_str" "$env_vars_str"
    return $?
}

# --- 容器编辑功能 (交互式向导模式) ---
edit_container_interactive() {
    local container_id=$1; local container_name=$2; local inspect_json=$3; local image_name=$(echo "$inspect_json" | jq -r '.[0].Config.Image'); local restart_policy=$(echo "$inspect_json" | jq -r '.[0].HostConfig.RestartPolicy.Name // "no"')
    mapfile -t ports < <(echo "$inspect_json" | jq -r '.[0].HostConfig.PortBindings | to_entries | .[] | ((if .value[0].HostIp and .value[0].HostIp != "" then .value[0].HostIp + ":" else "" end) + .value[0].HostPort + ":" + .key)')
    mapfile -t volumes < <(echo "$inspect_json" | jq -r '.[0].Mounts[] | "\(.Source):\(.Destination)"'); mapfile -t env_vars < <(echo "$inspect_json" | jq -r '.[0].Config.Env[]')
    while true; do
        clear; log_header "编辑向导: ${BLUE}${container_name}${RESET}"
        echo "当前配置:"; echo "  镜像: ${CYAN}${image_name}${RESET}"; echo "  重启策略: ${CYAN}${restart_policy}${RESET}"; echo "  端口映射: ${CYAN}${ports[*]}${RESET}"; echo "  目录映射: ${CYAN}${volumes[*]}${RESET}"; local env_count=${#env_vars[@]}; echo "  环境变量: ${CYAN}${env_count} 项${RESET}"
        echo "--------------------------------------------------"; echo "请选择要修改的项:"; echo "  1) 修改重启策略"; echo "  2) 修改端口映射"; echo "  3) 修改目录映射"; echo "  4) 修改环境变量 (将打开编辑器)"; echo ""; echo "  s) ${GREEN}保存并重建容器${RESET}"; echo "  q) ${RED}放弃修改并返回${RESET}"; echo "--------------------------------------------------"; read -p "请输入选项: " choice
        case $choice in
            1) read -p "请输入新的重启策略 (no, on-failure, unless-stopped, always) [当前: ${restart_policy}]: " new_policy; if [ -n "$new_policy" ]; then restart_policy=$new_policy; fi;;
            2) read -p "请输入新的端口映射 (格式: 80:80 443:443) [当前: ${ports[*]}]: " -a new_ports; if [ ${#new_ports[@]} -gt 0 ]; then ports=("${new_ports[@]}"); fi;;
            3) read -p "请输入新的目录映射 (格式: /host:/app /data:/db) [当前: ${volumes[*]}]: " -a new_volumes; if [ ${#new_volumes[@]} -gt 0 ]; then volumes=("${new_volumes[@]}"); fi;;
            4) 
                local temp_env_file; temp_env_file=$(mktemp "/tmp/docker_edit_env_${container_name}.XXXXXX.env"); trap 'rm -f "$temp_env_file"' RETURN; printf "%s\n" "${env_vars[@]}" > "$temp_env_file"
                local editor
                editor=$(get_editor)
                if [[ -z "$editor" ]]; then
                    log_error "系统中未找到可用的文本编辑器 (如 nano 或 vi)。"
                    press_enter_to_continue
                    continue
                fi
                log_info "将使用 '${editor}' 打开环境变量文件..."; sleep 2; $editor "$temp_env_file"; mapfile -t env_vars < "$temp_env_file";;
            [sS])
                # 将数组转换为管道符分隔的字符串以便传递
                local ports_str; ports_str=$(printf "%s|" "${ports[@]}")
                local volumes_str; volumes_str=$(printf "%s|" "${volumes[@]}")
                local env_vars_str; env_vars_str=$(printf "%s|" "${env_vars[@]}")
                recreate_container "$container_id" "$container_name" "$image_name" "$restart_policy" "$ports_str" "$volumes_str" "$env_vars_str"
                return $?;;
            [qQ]) log_info "已放弃修改。"; press_enter_to_continue; return 1;;
            *) log_error "无效输入，请重试。"; sleep 1;;
        esac
    done
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
        local raw_details; raw_details=$(echo "$inspect_json" | jq -r '.[0] | .State.Status + "\t" + (.State.Running | tostring) + "\t" + .State.StartedAt + "\t" + (.State.ExitCode | tostring) + "\t" + (.RepoTags[0] // .Config.Image // .Image) + "\t" + (.HostConfig.RestartPolicy.Name // "no") + "\t" + .Created + "\t" + (.HostConfig.PortBindings | if . == null or . == {} then "无" else (to_entries | map((if .value[0].HostIp and .value[0].HostIp != "" then .value[0].HostIp + ":" else "" end) + .value[0].HostPort + " -> " + .key) | join("; ")) end) + "\t" + (.Mounts | if . == [] then "无" else (map("\(.Source) -> \(.Destination)") | join("; ")) end)')
        IFS=$'\t' read -r status is_running started_at exit_code image policy created_at ports mounts <<< "$raw_details"
        
        local status_line=""
        if [[ "$is_running" == "true" ]]; then 
            local start_time_abs=$(date -d "$started_at" '+%Y-%m-%d %H:%M:%S')
            status_line="状态 : ${GREEN}${status}${RESET} (since ${start_time_abs})"
        else 
            status_line="状态 : ${RED}${status}${RESET} (exit code ${exit_code})"
        fi

        # --- 直接打印详情 ---
        echo -e "${WHITE}${status_line}${RESET}"
        
        if [[ "$is_running" == "true" ]]; then
            local current_ts=$(date +%s); local start_ts=$(date -d "$started_at" +%s); local diff_seconds=$((current_ts - start_ts)); local uptime_string=""
            local days=$((diff_seconds/86400)); local hours=$(((diff_seconds%86400)/3600)); local mins=$(((diff_seconds%3600)/60)); local secs=$((diff_seconds%60))
            if (( days > 0 )); then uptime_string="${days} 天 ${hours} 小时前"; elif (( hours > 0 )); then uptime_string="${hours} 小时 ${mins} 分钟前"; elif (( mins > 0 )); then uptime_string="${mins} 分钟 ${secs} 秒前"; else uptime_string="${secs} 秒前"; fi
            printf "%s: ${CYAN}%s${RESET}\n" "启动时间" "$uptime_string"
        fi

        printf "%s: ${CYAN}%s${RESET}\n" "镜像    " "$image"
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

# --- 这是你要粘贴进去的【最终修复版】main_loop 函数 ---
main_loop() {
    while true; do
        clear
        echo "============================================="
        echo "      Docker 容器交互式管理工具 v10.19       " # 版本号+0.01
        echo "============================================="
        
        # --- 彻底重构的排序和显示逻辑 ---
        
        # 1. 获取根据规则排好序的容器ID列表
        mapfile -t sorted_ids < <(docker ps -a --format '{{.ID}}\t{{.Label "com.docker.compose.project"}}\t{{.State}}' | while IFS=$'\t' read -r id compose_project state; do
            local type_key
            local state_key

            # 设置类型码: 0=普通容器, 1=Compose容器
            if [[ -n "$compose_project" ]]; then
                type_key="1"
            else
                type_key="0"
            fi

            # 设置状态码: 0=运行中, 1=已停止
            if [[ "$state" == "running" ]]; then
                state_key="0"
            else
                state_key="1"
            fi
            
            # 组合成最终排序码，格式为: 类型_状态
            local sort_key="${type_key}_${state_key}"

            printf "%s\t%s\n" "$sort_key" "$id"
        done | sort -t $'\t' -k1,1 | cut -d $'\t' -f 2-)

        # 2. 准备两个数组分别存放两种容器的ID
        local selectable_container_ids=()
        local compose_container_ids=()

        # 3. 遍历排序后的ID，通过inspect获取准确信息并分离
        for id in "${sorted_ids[@]}"; do
            # 这里的 inspect 仅用于最终分类，排序已完成
            local inspect_json
            inspect_json=$(docker inspect "$id")
            local compose_project
            compose_project=$(echo "$inspect_json" | jq -r '.[0].Config.Labels["com.docker.compose.project"] // ""')

            if [[ -n "$compose_project" && "$compose_project" != "null" ]]; then
                compose_container_ids+=("$id")
            else
                selectable_container_ids+=("$id")
            fi
        done

        if [ ${#sorted_ids[@]} -eq 0 ]; then
            log_info "系统中没有找到任何 Docker 容器。"
        else
            log_header "容器列表"
            printf "${WHITE}%-4s %-25s %-40s %-s${RESET}\n" "NO." "NAME" "IMAGE" "STATUS"
            printf "${WHITE}%-4s %-25s %-40s %-s${RESET}\n" "----" "-------------------------" "----------------------------------------" "--------------------------"
            
              # --- 请用这个【最终版】，完整替换旧的 display_container_details 函数 ---
        display_container_details() {
            local container_id=$1
            local prefix=$2

            local details_json; details_json=$(docker inspect "$container_id")
            local name; name=$(echo "$details_json" | jq -r '.[0].Name | sub("^/"; "")')
            
            # 使用 jq 一次性解析所有需要的数据
            local parsed_data; parsed_data=$(echo "$details_json" | jq -r '.[0] | (.RepoTags[0] // .Config.Image // .Image) + "\t" + (.State.Running | tostring) + "\t" + .State.StartedAt + "\t" + .State.FinishedAt + "\t" + (.State.ExitCode | tostring) + "\t" + (.HostConfig.RestartPolicy.Name // "no") + "\t" + (.HostConfig.PortBindings | if . == null or . == {} then "N/A" else (to_entries | map((if .value[0].HostIp and .value[0].HostIp != "" then .value[0].HostIp + ":" else "" end) + .value[0].HostPort + " -> " + .key) | join(", ")) end) + "\t" + (.Mounts | if . == [] then "N/A" else (map((.Source | sub(env.HOME; "~")) + " -> " + .Destination) | join(", ")) end)')
            IFS=$'\t' read -r image is_running started_at finished_at exit_code policy ports mounts <<< "$parsed_data"
            
            # 格式化状态字符串
            local status_string=""
            if [[ "$is_running" == "true" ]]; then 
                local start_time=$(date -d "$started_at" '+%Y-%m-%d %H:%M')
                status_string="Up since ${start_time}"
            else 
                if [[ "$finished_at" != "0001-01-01T00:00:00Z" && "$finished_at" != null ]]; then 
                    local finish_time=$(date -d "$finished_at" '+%Y-%m-%d %H:%M')
                    status_string="Exited(${exit_code}) at ${finish_time}"
                else 
                    status_string="Created"
                fi
            fi

            # 根据状态决定名字颜色
            local name_color=${WHITE}
            if [[ "$is_running" == "true" ]]; then name_color=${GREEN}; else name_color=${RED}; fi
            
            # --- 打印混合式布局 ---
            # 1. 打印第一行：序号、名称、镜像、状态
            printf "%-4s ${name_color}%-25.25s${RESET} %-40.40s %s\n" "$prefix" "$name" "$image" "$status_string"
            
            # 2. 打印缩进的详细信息 (将数值部分改为紫色)
            printf "     ${CYAN}├─ Policy:${RESET} ${MAGENTA}%s${RESET}\n" "$policy"
            printf "     ${CYAN}├─ Ports:${RESET} ${MAGENTA}%s${RESET}\n" "$ports"
            printf "     ${CYAN}└─ Mounts:${RESET} ${MAGENTA}%s${RESET}\n" "$mounts"
        }
        # --- 替换结束 ---

            # 4. 先显示带序号的普通容器
            i=1
            for id in "${selectable_container_ids[@]}"; do
                display_container_details "$id" "$i)"
                i=$((i+1))
            done

            # 5. 再显示不带可选序号的Compose容器
            for id in "${compose_container_ids[@]}"; do
                display_container_details "$id" "${RED} C)${RESET}"
            done
        fi
        
        echo
        log_info "输入 'image' 进入镜像管理, 'compose' 进入项目管理, 'tools' (或回车) 进入工具箱, 'q' 退出"
        local term_width=$(tput cols 2>/dev/null || echo 80); printf '%.0s─' $(seq 1 $term_width); echo

        read -p "请输入容器序号或指令: " choice

        case $choice in
            [qQ]) echo "感谢使用，脚本退出。"; break;;
            image) manage_images;;
            compose) manage_compose_projects;;
            ""|tools) show_tools_menu;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#selectable_container_ids[@]} ]; then
                    # 从selectable_container_ids数组中安全地获取ID
                    local selected_id=${selectable_container_ids[$((choice-1))]}
                    local container_name
                    container_name=$(docker inspect "$selected_id" | jq -r '.[0].Name | sub("^/"; "")')
                    show_container_actions_menu "$selected_id" "$container_name"
                else
                    if [ -n "$choice" ]; then log_error "无效输入，请输入列表中的数字或指令。"; press_enter_to_continue; fi
                fi;;
        esac
    done
}

# --- 脚本入口 ---
check_dependencies
install_docker_if_needed
main_loop
