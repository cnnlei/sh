#!/bin/bash

# Linux Toolbox by Gemini (Intelligent Sudo Installer)
# A collection of useful Linux administration scripts with a nice UI.

# --- Initial Setup & Checks ---
clear

# --- Colors and Styles ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Helper function to correctly calculate the display width of a string ---
get_display_width() {
    local s="$1"; local len_bytes=${#s}; local len_chars=$(echo -n "$s" | wc -m);
    local num_cjk=$(((len_bytes - len_chars) / 2)); local num_ascii=$((len_chars - num_cjk));
    local display_width=$((num_cjk * 2 + num_ascii)); echo $display_width;
}

# --- Visually Improved print_title function ---
print_title() {
    clear; local title="$1"; local width=$(tput cols); local title_width=$(get_display_width "$title");
    local total_padding=$((width - title_width - 4)); if [ $total_padding -lt 0 ]; then total_padding=0; fi;
    local left_padding=$((total_padding / 2)); local right_padding=$((total_padding - left_padding));
    printf "${CYAN}${BOLD}┌"; for ((i=0; i<width-2; i++)); do printf "─"; done; printf "┐${NC}\n";
    printf "${CYAN}${BOLD}│%*s %s %*s│${NC}\n" $left_padding "" "$title" $right_padding "";
    printf "${CYAN}${BOLD}└"; for ((i=0; i<width-2; i++)); do printf "─"; done; printf "┘${NC}\n\n";
}

# --- Package Manager Detection & Installer Function ---
SUDO_CMD_FOR_INSTALL=""; PKG_MANAGER=""; INSTALL_CMD=""; UPDATE_CMD="";
check_and_install() {
    local pkg_name=$1; local cmd_name=$2;
    if [ "$EUID" -ne 0 ]; then SUDO_CMD_FOR_INSTALL="sudo"; fi;
    if command -v $cmd_name &> /dev/null; then return 0; fi;
    if [ -z "$PKG_MANAGER" ]; then
        if command -v apt-get &> /dev/null; then PKG_MANAGER="apt"; elif command -v dnf &> /dev/null; then PKG_MANAGER="dnf"; elif command -v yum &> /dev/null; then PKG_MANAGER="yum"; elif command -v pacman &> /dev/null; then PKG_MANAGER="pacman"; else PKG_MANAGER="unknown"; fi;
    fi;
    print_title "依赖缺失"; echo -e "${YELLOW}命令 '${cmd_name}' 未找到 (由 ${pkg_name} 包提供)。${NC}";
    if [ "$PKG_MANAGER" == "unknown" ]; then echo -e "${RED}无法识别包管理器, 请手动安装 ${pkg_name}。${NC}"; sleep 3; return 1; fi;
    read -p "是否要现在尝试安装 ${pkg_name}? [Y/n]: " choice;
    if [[ -z "$choice" || "$choice" == "y" || "$choice" == "Y" ]]; then
        case $PKG_MANAGER in
            apt) UPDATE_CMD="$SUDO_CMD_FOR_INSTALL apt-get update"; INSTALL_CMD="$SUDO_CMD_FOR_INSTALL apt-get install -y"; echo -e "${CYAN}运行 apt update...${NC}"; $UPDATE_CMD;;
            dnf) INSTALL_CMD="$SUDO_CMD_FOR_INSTALL dnf install -y" ;;
            yum) INSTALL_CMD="$SUDO_CMD_FOR_INSTALL yum install -y" ;;
            pacman) INSTALL_CMD="$SUDO_CMD_FOR_INSTALL pacman -S --noconfirm" ;;
        esac;
        echo -e "${CYAN}正在使用 ${PKG_MANAGER} 安装 ${pkg_name}...${NC}"; $INSTALL_CMD $pkg_name;
        if command -v $cmd_name &> /dev/null; then echo -e "${GREEN}${pkg_name} 安装成功!${NC}"; sleep 2; return 0; else echo -e "${RED}${pkg_name} 安装失败。${NC}"; sleep 3; return 1; fi;
    else echo -e "${YELLOW}操作已取消。${NC}"; sleep 2; return 1; fi;
}

# --- Privilege Check & sudo setup ---
SUDO_CMD=""; if [ "$EUID" -ne 0 ]; then if ! command -v sudo &> /dev/null; then echo -e "${RED}${BOLD}错误: 'sudo' 未安装。${NC}"; exit 1; fi; SUDO_CMD="sudo"; else if ! command -v sudo &> /dev/null; then check_and_install "sudo" "sudo"; fi; fi;
case $PKG_MANAGER in
    apt) INSTALL_CMD="$SUDO_CMD apt-get install -y"; UPDATE_CMD="$SUDO_CMD apt-get update" ;;
    dnf) INSTALL_CMD="$SUDO_CMD dnf install -y" ;;
    yum) INSTALL_CMD="$SUDO_CMD yum install -y" ;;
    pacman) INSTALL_CMD="$SUDO_CMD pacman -S --noconfirm" ;;
esac;
if ! check_and_install "python3" "python3"; then echo -e "${RED}Python 3 缺失, 脚本无法继续。${NC}"; exit 1; fi;
PID_FILE="/tmp/http_server_pids.log"; touch $PID_FILE;
IPERF_PID_FILE="/tmp/iperf3_server_pids.log"; touch $IPERF_PID_FILE;

# --- All Main Functions ---

manage_swap(){
    list_all_swaps() {
        print_title "查看 / 删除 Swap"; declare -g swap_paths_map=(); declare -g swap_types_map=();
        local active_swaps=$(swapon --show --bytes | tail -n +2); local fstab_swaps=$(grep -E '\sswap\s' /etc/fstab | grep -v '^#');
        local all_swap_paths=$( (echo "$active_swaps" | awk '{print $1}'; echo "$fstab_swaps" | awk '{print $1}') | sort -u);
        if [ -z "$all_swap_paths" ]; then echo -e "${YELLOW}未找到任何配置的 Swap。${NC}"; return 1; fi;
        echo -e "${CYAN}${BOLD}序号\t路径\t\t\t类型\t\t大小\t\t已用\t\t状态${NC}"; echo -e "${CYAN}-------------------------------------------------------------------------------------------------${NC}";
        local index=1; local has_unmanaged_swap=false;
        for path in $all_swap_paths; do
            local size="N/A"; local used="N/A"; local type="N/A"; local status_text=""; local line_color=""; local index_text="${index})";
            local active_info=$(echo "$active_swaps" | grep "^$path\s");
            if [ -n "$active_info" ]; then
                line_color="$GREEN"; status_text="Active"; size=$(echo "$active_info" | awk '{print $3}' | xargs numfmt --to=iec); used=$(echo "$active_info" | awk '{print $4}' | xargs numfmt --to=iec); type=$(echo "$active_info" | awk '{print $2}');
            else
                line_color="$RED"; status_text="Inactive";
                if [ -f "$path" ]; then type="file"; size=$(ls -lh "$path" | awk '{print $5}'); elif [ -b "$path" ]; then type="partition"; size="N/A"; else type="-"; status_text="Inactive (Missing)"; fi;
            fi;
            if [[ "$path" != /* ]]; then index_text="${index})*"; has_unmanaged_swap=true; else swap_paths_map[$index]=$path; swap_types_map[$index]=$type; fi;
            printf "${line_color}%-8s\t%-24s\t%-16s\t%-16s\t%-16s\t%-16s${NC}\n" "$index_text" "$path" "$type" "$size" "$used" "$status_text"; index=$((index + 1));
        done;
        if $has_unmanaged_swap; then echo -e "\n${YELLOW}* 注: 带星号的条目由系统管理, 无法通过此脚本删除。${NC}"; fi; return 0;
    };
    while true; do
        print_title "虚拟内存管理 (Swap)"; echo -e "  ${YELLOW}1.${NC} 查看 / 删除 Swap"; echo -e "  ${YELLOW}2.${NC} 增加 Swap 文件"; echo -e "\n  ${RED}q.${NC} 返回主菜单"; echo ""; read -p "$(echo -e ${MAGENTA}"  -> 请选择: "${NC})" swap_choice;
        case $swap_choice in
            1)
                if ! list_all_swaps; then read -p "$(echo -e "\n${YELLOW}按 Enter 返回...${NC}")"; continue; fi;
                read -p "$(echo -e ${MAGENTA}"\n请输入要删除的序号 (或直接按 Enter 返回): "${NC})" index_to_del; if [ -z "$index_to_del" ]; then continue; fi;
                if [[ ! "$index_to_del" =~ ^[0-9]+$ ]] || [ -z "${swap_paths_map[$index_to_del]}" ]; then echo -e "\n${RED}错误: 无效序号或不可删除!${NC}"; sleep 2; continue; fi;
                local path_to_del="${swap_paths_map[$index_to_del]}"; local type_to_del="${swap_types_map[$index_to_del]}";
                echo -e "\n您将要删除 Swap: ${YELLOW}${path_to_del}${NC}"; read -p "确认? [y/N]: " confirm; if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then echo -e "${YELLOW}操作已取消。${NC}"; sleep 2; continue; fi;
                echo ""; if grep -q "^$path_to_del\s" /proc/swaps; then echo -e "${YELLOW}1. 禁用 Swap...${NC}"; $SUDO_CMD swapoff "$path_to_del" && echo -e "${GREEN}   OK${NC}" || echo -e "${RED}   FAIL${NC}"; fi;
                if grep -q "$path_to_del" /etc/fstab; then echo -e "${YELLOW}2. 从 fstab 移除...${NC}"; $SUDO_CMD sed -i "\|^${path_to_del//\//\\/}[[:space:]]|d" /etc/fstab && echo -e "${GREEN}   OK${NC}" || echo -e "${RED}   FAIL${NC}"; fi;
                if [[ "$type_to_del" == "file" && -f "$path_to_del" ]]; then echo -e "${YELLOW}3. 删除文件...${NC}"; $SUDO_CMD rm -f "$path_to_del" && echo -e "${GREEN}   OK${NC}" || echo -e "${RED}   FAIL${NC}"; elif [ "$type_to_del" == "partition" ]; then echo -e "${CYAN}   这是一个分区, 不会删除物理设备。${NC}"; fi;
                echo -e "\n${GREEN}操作完成。${NC}"; read -p "$(echo -e "\n${YELLOW}按 Enter 继续...${NC}")";;
            2)
                clear; print_title "增加 Swap 文件"; read -p "大小 (例如: 1G, 512M): " swap_size; if ! [[ "$swap_size" =~ ^[0-9]+[MmGgTtKk]$ ]]; then echo -e "\n${RED}格式错误!${NC}"; read -p "..."; continue; fi;
                read -p "路径 (例如: /swapfile_new): " swap_path; if [ -z "$swap_path" ]; then echo -e "\n${RED}路径不能为空!${NC}"; read -p "..."; continue; fi; if [ -e "$swap_path" ]; then echo -e "\n${RED}文件已存在!${NC}"; read -p "..."; continue; fi;
                echo -e "\n${YELLOW}1. 创建文件...${NC}"; if ! $SUDO_CMD fallocate -l "$swap_size" "$swap_path"; then echo -e "\n${RED}创建失败!${NC}"; read -p "..."; continue; fi;
                echo -e "${YELLOW}2. 设置权限...${NC}"; $SUDO_CMD chmod 600 "$swap_path";
                echo -e "${YELLOW}3. 格式化...${NC}"; if ! $SUDO_CMD mkswap "$swap_path"; then echo -e "\n${RED}格式化失败!${NC}"; $SUDO_CMD rm -f "$swap_path"; read -p "..."; continue; fi;
                echo -e "${YELLOW}4. 激活...${NC}"; if ! $SUDO_CMD swapon "$swap_path"; then echo -e "\n${RED}激活失败!${NC}"; $SUDO_CMD rm -f "$swap_path"; read -p "..."; continue; fi;
                echo -e "${YELLOW}5. 添加到 fstab...${NC}"; echo "$swap_path none swap sw 0 0" | $SUDO_CMD tee -a /etc/fstab;
                echo -e "\n${GREEN}Swap 文件创建成功!${NC}"; read -p "...";;
            q) break;;
            *) echo -e "\n${RED}无效选项!${NC}"; sleep 1;;
        esac;
    done;
}

modify_dns(){
    is_valid_ip() { local ip=$1; local stat=1; if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then OIFS=$IFS; IFS='.'; ip=($ip); IFS=$OIFS; [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]; stat=$?; fi; return $stat; }
    while true; do
        print_title "DNS 修改工具"; echo -e "${GREEN}当前 DNS:${NC}"; grep --color=never "nameserver" /etc/resolv.conf || echo -e "  ${YELLOW}(未设置)${NC}"; echo "";
        echo -e "${CYAN}--- 请选择方案 ---${NC}"; echo -e "  ${YELLOW}1.${NC} Google"; echo -e "  ${YELLOW}2.${NC} Cloudflare"; echo -e "  ${YELLOW}3.${NC} OpenDNS"; echo -e "  ${YELLOW}4.${NC} Quad9"; echo -e "  ${YELLOW}5.${NC} 自定义"; echo -e "\n  ${RED}q.${NC} 返回"; echo ""; read -p "$(echo -e ${MAGENTA}"-> 请输入选择: "${NC})" dns_choice;
        local dns1=""; local dns2=""; local user_cancelled=false;
        case $dns_choice in
            1) dns1="8.8.8.8"; dns2="8.8.4.4";; 2) dns1="1.1.1.1"; dns2="1.0.0.1";; 3) dns1="208.67.222.222"; dns2="208.67.220.220";; 4) dns1="9.9.9.9"; dns2="149.112.112.112";;
            5)
                while true; do read -p "主 DNS (输入 'q' 返回): " custom_dns1; if [[ "$custom_dns1" == "q" ]]; then user_cancelled=true; break; fi; if is_valid_ip "$custom_dns1"; then dns1=$custom_dns1; break; else echo -e "${RED}IP 格式错误!${NC}"; fi; done;
                if $user_cancelled; then continue; fi;
                while true; do read -p "备用 DNS (回车跳过, 'q' 返回): " custom_dns2; if [[ "$custom_dns2" == "q" ]]; then user_cancelled=true; break; fi; if [ -z "$custom_dns2" ]; then dns2=""; break; elif is_valid_ip "$custom_dns2"; then dns2=$custom_dns2; break; else echo -e "${RED}IP 格式错误!${NC}"; fi; done;
                if $user_cancelled; then continue; fi;;
            q) return;;
            *) echo -e "\n${RED}无效选项!${NC}"; sleep 1; continue;;
        esac;
        read -p "设置为: ${dns1}${dns2:+, $dns2} ? [Y/n]: " confirm;
        if [[ -z "$confirm" || "$confirm" == "y" || "$confirm" == "Y" ]]; then
            echo "# Generated by Linux Toolbox" | $SUDO_CMD tee /etc/resolv.conf > /dev/null;
            if [ ! -z "$dns1" ]; then echo "nameserver $dns1" | $SUDO_CMD tee -a /etc/resolv.conf > /dev/null; fi;
            if [ ! -z "$dns2" ]; then echo "nameserver $dns2" | $SUDO_CMD tee -a /etc/resolv.conf > /dev/null; fi;
            echo -e "\n${GREEN}DNS 已更新:${NC}"; cat /etc/resolv.conf; read -p "$(echo -e "\n${YELLOW}按 Enter 返回...${NC}")"; break;
        else echo -e "\n${YELLOW}操作已取消。${NC}"; sleep 1; fi;
    done;
}

manage_http_server(){
    while true; do
        print_title "HTTP 服务器管理 (后台运行)"; echo -e "  ${YELLOW}1.${NC} 启动一个新的 HTTP 服务器"; echo -e "  ${YELLOW}2.${NC} 查看 / 停止正在运行的服务器"; echo -e "\n  ${RED}q.${NC} 返回主菜单"; echo "";
        read -p "$(echo -e ${MAGENTA}"  -> 请选择: "${NC})" server_choice;
        case $server_choice in
            1)
                print_title "启动新 HTTP 服务器"; read -p "端口号 (例如: 8000): " port; if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then echo -e "\n${RED}端口无效!${NC}"; sleep 2; continue; fi;
                if grep -q " $port " $PID_FILE && kill -0 $(grep " $port " $PID_FILE | awk '{print $1}') 2>/dev/null; then echo -e "\n${RED}端口 $port 已被占用!${NC}"; sleep 2; continue; fi;
                read -p "共享目录路径 (默认为 '.'): " serve_dir; SERVE_DIR=${serve_dir:-.}; if [ ! -d "$SERVE_DIR" ]; then echo -e "\n${RED}目录不存在!${NC}"; sleep 2; continue; fi;
                ABS_SERVE_DIR=$(cd "$SERVE_DIR" && pwd); LOG_FILE="/tmp/http_server_${port}.log"; original_dir=$(pwd);
                echo -e "\n${YELLOW}正在后台启动服务器...${NC}"; cd "$ABS_SERVE_DIR"; python3 -m http.server --bind :: "$port" &> "$LOG_FILE" & pid=$!; cd "$original_dir";
                echo "$pid $port $ABS_SERVE_DIR" >> $PID_FILE; echo -e "\n${GREEN}服务器启动成功!${NC}"; echo -e "  - PID: $pid, 端口: $port"; echo -e "  - 目录: $ABS_SERVE_DIR"; echo -e "  - 日志: $LOG_FILE"; read -p "...";;
            2)
                while true; do
                    print_title "查看 / 停止服务器"; if [ ! -s "$PID_FILE" ]; then echo -e "${YELLOW}没有正在运行的服务器。${NC}"; read -p "..."; break; fi;
                    temp_pid_file=$(mktemp); has_running_servers=false; while read -r pid port dir; do if kill -0 "$pid" 2>/dev/null; then echo "$pid $port $dir" >> "$temp_pid_file"; has_running_servers=true; fi; done < "$PID_FILE"; mv "$temp_pid_file" "$PID_FILE";
                    if ! $has_running_servers; then echo -e "${YELLOW}所有服务器均已停止。${NC}"; read -p "..."; break; fi;
                    echo -e "${CYAN}${BOLD}序号\tPID\t端口\t状态\t共享目录${NC}"; echo -e "${CYAN}-----------------------------------------------------------------${NC}";
                    declare -a pids_map; declare -a ports_map; local index=1;
                    while read -r pid port dir; do echo -e "${GREEN}${index})\t${pid}\t${port}\t运行中\t${dir}${NC}"; pids_map[$index]=$pid; ports_map[$index]=$port; index=$((index + 1)); done < "$PID_FILE";
                    echo ""; read -p "$(echo -e ${MAGENTA}"\n输入序号停止 (多个用逗号隔开, 或 all), 或 Enter 返回: "${NC})" input_to_kill; if [ -z "$input_to_kill" ]; then break; fi;
                    if [[ "$input_to_kill" == "all" || "$input_to_kill" == "全部" ]]; then
                        echo -e "\n${YELLOW}正在停止所有服务器...${NC}"; for i in "${!pids_map[@]}"; do kill "${pids_map[$i]}"; rm -f "/tmp/http_server_${ports_map[$i]}.log"; done; > "$PID_FILE"; echo -e "${GREEN}所有服务器已停止!${NC}";
                    else
                        for i in $(echo $input_to_kill | tr ',' ' '); do
                            if [[ "$i" =~ ^[0-9]+$ && -n "${pids_map[$i]}" ]]; then
                                pid_to_stop=${pids_map[$i]}; port_to_stop=${ports_map[$i]}; echo -e "${YELLOW}停止序号 ${i} (PID: ${pid_to_stop})...${NC}";
                                kill "$pid_to_stop"; sed -i "/^$pid_to_stop /d" "$PID_FILE"; rm -f "/tmp/http_server_${port_to_stop}.log";
                            else echo -e "${RED}警告: 无效序号 '$i'。${NC}"; fi;
                        done; echo -e "${GREEN}所选服务器已处理!${NC}";
                    fi; sleep 2;
                done;;
            q) break;;
            *) echo -e "\n${RED}无效选项!${NC}"; sleep 1;;
        esac;
    done;
}

manage_iperf3(){
    if ! check_and_install "iperf3" "iperf3"; then return; fi;

    while true; do
        print_title "iperf3 网络性能测试 (高级版)";
        echo -e "  ${YELLOW}1.${NC} 启动一个新的 iperf3 服务端";
        echo -e "  ${YELLOW}2.${NC} 查看 / 停止正在运行的服务端";
        echo -e "  ${YELLOW}3.${NC} 启动 iperf3 客户端进行测试";
        echo -e "\n  ${RED}q.${NC} 返回主菜单";
        echo "";
        read -p "$(echo -e ${MAGENTA}"  -> 请选择: "${NC})" iperf_choice;

        case $iperf_choice in
            1)
                # --- 启动服务端 ---
                print_title "启动新 iperf3 服务端";
                read -p "请输入要监听的端口 [默认: 5201]: " port;
                local PORT=${port:-5201};
                if [[ ! "$PORT" =~ ^[0-9]+$ ]]; then echo -e "\n${RED}端口无效!${NC}"; sleep 2; continue; fi;

                read -p "选择协议 (tcp/udp) [默认: tcp]: " protocol_choice;
                local PROTOCOL=${protocol_choice:-tcp};
                
                read -p "是否为单次模式 (完成后自动退出)? (y/n) [默认: n]: " one_off_choice;
                local ONE_OFF_MODE="持续运行";
                local ONE_OFF_PARAM="";
                if [[ "$one_off_choice" == "y" || "$one_off_choice" == "Y" ]]; then
                    ONE_OFF_MODE="单次模式";
                    ONE_OFF_PARAM="-1";
                fi;

                if [ -f "$IPERF_PID_FILE" ] && grep -q " $PORT " "$IPERF_PID_FILE" && kill -0 $(grep " $PORT " "$IPERF_PID_FILE" | awk '{print $1}') 2>/dev/null; then
                    echo -e "\n${RED}端口 ${PORT} 已被此工具启动的服务占用!${NC}"; sleep 2; continue;
                fi;

                local IPERF_CMD="iperf3 -s -p $PORT $ONE_OFF_PARAM";
                if [[ "$PROTOCOL" == "udp" ]]; then IPERF_CMD+=" -u"; fi;

                local PID_FILE_PATH="/tmp/iperf3_server_${PORT}.pid";
                echo -e "\n${YELLOW}正在后台启动 iperf3 服务端...${NC}";
                echo -e "  ${CYAN}执行命令: $IPERF_CMD${NC}"
                
                $IPERF_CMD --pidfile "$PID_FILE_PATH" < /dev/null &> /dev/null &
                sleep 1; 

                if [ -f "$PID_FILE_PATH" ] && kill -0 $(cat "$PID_FILE_PATH") 2>/dev/null; then
                    local pid=$(cat "$PID_FILE_PATH");
                    # 记录 PID / 端口 / 协议 / 模式 / PID文件路径
                    echo "$pid $PORT $PROTOCOL $ONE_OFF_MODE $PID_FILE_PATH" >> "$IPERF_PID_FILE";
                    echo -e "\n${GREEN}iperf3 服务端启动成功!${NC}";
                    echo -e "  - ${BOLD}PID     : ${pid}${NC}";
                    echo -e "  - ${BOLD}监听端口: ${PORT}${NC}";
                    echo -e "  - ${BOLD}协议    : ${PROTOCOL}${NC}";
                    echo -e "  - ${BOLD}模式    : ${ONE_OFF_MODE}${NC}";
                    echo -e "  - ${BOLD}服务器IP: $(hostname -I | awk '{print $1}')${NC}";
                else
                    echo -e "\n${RED}iperf3 服务端启动失败! 请检查端口是否被其他程序占用。${NC}";
                    rm -f "$PID_FILE_PATH";
                fi;
                read -p "...";;

            2)
                # --- 查看/停止服务端 ---
                while true; do
                    print_title "查看 / 停止 iperf3 服务端";
                    if [ -s "$IPERF_PID_FILE" ]; then
                        temp_pid_file=$(mktemp);
                        while read -r pid port protocol mode pid_path; do
                            if kill -0 "$pid" 2>/dev/null; then
                                echo "$pid $port $protocol $mode $pid_path" >> "$temp_pid_file";
                            else
                                rm -f "$pid_path"; 
                            fi;
                        done < "$IPERF_PID_FILE";
                        mv "$temp_pid_file" "$IPERF_PID_FILE";
                    fi;

                    if [ ! -s "$IPERF_PID_FILE" ]; then
                        echo -e "${YELLOW}没有由本工具启动的 iperf3 服务端正在运行。${NC}";
                        read -p "..."; break;
                    fi;

                    echo -e "${CYAN}${BOLD}%-4s %-8s %-8s %-8s %-12s %-10s %s${NC}" "序号" "PID" "端口" "协议" "模式" "状态" "服务器 IP"
                    echo -e "${CYAN}--------------------------------------------------------------------------------------${NC}";
                    declare -a pids_map; declare -a pid_paths_map;
                    local index=1;
                    local server_ip=$(hostname -I | awk '{print $1}');
                    while read -r pid port protocol mode pid_path; do
                        printf "${GREEN}%-4s %-8s %-8s %-8s %-12s %-10s %s${NC}\n" "${index})" "$pid" "$port" "$protocol" "$mode" "运行中" "$server_ip"
                        pids_map[$index]=$pid;
                        pid_paths_map[$index]=$pid_path;
                        index=$((index + 1));
                    done < "$IPERF_PID_FILE";

                    echo "";
                    read -p "$(echo -e ${MAGENTA}"\n输入序号停止 (或 all), 或按 Enter 返回: "${NC})" input_to_kill;
                    if [ -z "$input_to_kill" ]; then break; fi;

                    if [[ "$input_to_kill" == "all" ]]; then
                        echo -e "\n${YELLOW}正在停止所有 iperf3 服务端...${NC}";
                        for i in "${!pids_map[@]}"; do kill "${pids_map[$i]}"; rm -f "${pid_paths_map[$i]}"; done;
                        > "$IPERF_PID_FILE"; 
                        echo -e "${GREEN}所有服务已停止!${NC}";
                    else
                        for i in $(echo $input_to_kill | tr ',' ' '); do
                            if [[ "$i" =~ ^[0-9]+$ && -n "${pids_map[$i]}" ]]; then
                                echo -e "${YELLOW}停止序号 ${i} (PID: ${pids_map[$i]})...${NC}";
                                kill "${pids_map[$i]}"; rm -f "${pid_paths_map[$i]}";
                                sed -i "/^${pids_map[$i]} /d" "$IPERF_PID_FILE";
                            else
                                echo -e "${RED}警告: 无效序号 '$i'。${NC}";
                            fi;
                        done;
                        echo -e "${GREEN}所选服务已处理!${NC}";
                    fi;
                    sleep 2;
                done;;

            3)
                # --- 启动客户端 ---
                print_title "启动 iperf3 客户端测试";
                read -p "请输入 iperf3 服务器地址: " server_ip;
                if [ -z "$server_ip" ]; then echo -e "\n${RED}服务器地址不能为空!${NC}"; sleep 2; continue; fi;
                
                read -p "请输入服务器端口 [默认: 5201]: " server_port;
                local SERVER_PORT=${server_port:-5201};

                read -p "选择协议 (tcp/udp) [默认: tcp]: " protocol_choice;
                local PROTOCOL=${protocol_choice:-tcp};
                
                # =======================> 新增的输入验证 <=======================
                local DURATION
                while true; do
                    read -p "测试时长(秒) [1-86400, 默认: 10]: " duration_choice
                    DURATION=${duration_choice:-10}
                    if ! [[ "$DURATION" =~ ^[0-9]+$ ]]; then
                        echo -e "\n${RED}错误: 请输入一个有效的数字。${NC}"
                        continue
                    fi
                    if [ "$DURATION" -gt 86400 ]; then
                        echo -e "\n${RED}错误: 测试时长过长, 最大不能超过 86400 秒 (24小时)。${NC}"
                    else
                        break
                    fi
                done
                # ==============================================================

                read -p "并行数据流数量 [默认: 1]: " parallel_choice;
                local PARALLEL=${parallel_choice:-1};

                read -p "是否启用反向模式 (服务器发送, 客户端接收)? (y/n) [默认: n]: " reverse_choice;
                local REVERSE_PARAM="";
                if [[ "$reverse_choice" == "y" || "$reverse_choice" == "Y" ]]; then
                    REVERSE_PARAM="-R";
                fi;

                local IPERF_CMD="iperf3 -c $server_ip -p $SERVER_PORT -t $DURATION -P $PARALLEL $REVERSE_PARAM"
                
                if [[ "$PROTOCOL" == "udp" ]]; then
                    IPERF_CMD+=" -u";
                    local udp_bandwidth="";
                    while [ -z "$udp_bandwidth" ]; do
                        read -p "UDP 模式必须指定带宽 (如 10M, 1G): " udp_bandwidth;
                    done
                    IPERF_CMD+=" -b $udp_bandwidth";
                fi;

                echo "";
                echo -e "${CYAN}------------------------------------------------------${NC}";
                echo -e "${CYAN}            准备执行 iperf3 测试${NC}";
                echo -e "${CYAN}------------------------------------------------------${NC}";
                echo -e "  ${BOLD}服务器 :${NC} $server_ip:$SERVER_PORT";
                echo -e "  ${BOLD}协议   :${NC} $PROTOCOL";
                echo -e "  ${BOLD}时长   :${NC} ${DURATION}s";
                echo -e "  ${BOLD}数据流 :${NC} $PARALLEL";
                echo -e "  ${BOLD}方向   :${NC} ${REVERSE_PARAM:-- (默认: 上传)}";
                echo -e "\n${YELLOW}完整命令: $IPERF_CMD${NC}\n";
                
                # 分开构建命令以处理UDP参数的空格问题
                local final_params=("-c" "$server_ip" "-p" "$SERVER_PORT" "-t" "$DURATION" "-P" "$PARALLEL")
                if [[ -n "$REVERSE_PARAM" ]]; then final_params+=("-R"); fi
                if [[ "$PROTOCOL" == "udp" ]]; then final_params+=("-u" "-b" "$udp_bandwidth"); fi
                
                iperf3 "${final_params[@]}"

                read -p "$(echo -e "\n测试完成。按 Enter 返回...${NC}")";;

            q) break;;
            *) echo -e "\n${RED}无效选项!${NC}"; sleep 1;;
        esac;
    done;
}

manage_hosts_file(){
    if ! check_and_install "nano" "nano"; then return; fi;
    local HOSTS_PATH="/etc/hosts";
    while true; do
        print_title "/etc/hosts 文件管理"; echo -e "  ${YELLOW}1.${NC} 查看 hosts 文件"; echo -e "  ${YELLOW}2.${NC} 编辑 hosts 文件"; echo -e "\n  ${RED}q.${NC} 返回"; echo ""; read -p "$(echo -e ${MAGENTA}"-> 选择: "${NC})" hosts_choice;
        case $hosts_choice in
            1) clear; echo -e "${GREEN}--- 当前 /etc/hosts 内容 ---${NC}"; cat -n $HOSTS_PATH; read -p "$(echo -e "\n${YELLOW}按 Enter 返回...${NC}")";;
            2) clear; echo -e "将使用 nano 编辑器打开..."; read -p "..."; $SUDO_CMD nano $HOSTS_PATH; echo -e "\n${GREEN}OK${NC}"; read -p "$(echo -e "\n${YELLOW}按 Enter 返回...${NC}")";;
            q) break;;
            *) echo -e "\n${RED}无效选项!${NC}"; sleep 1;;
        esac;
    done;
}

# --- [新] Systemd 功能的辅助函数 (紧凑布局) ---
_systemctl_list_services() {
    declare -n map_ref=$1
    local view_mode=$2
    local keyword=$3
    map_ref=()
    local index=1

    local title_suffix="(仅用户服务)"
    if [[ "$view_mode" == "all" ]]; then title_suffix="(全部服务)"; fi
    if [ -n "$keyword" ]; then title_suffix="${title_suffix} | 筛选(名称): “${keyword}”"; fi
    print_title "Systemd 管理 ${title_suffix}"
    echo -e "${CYAN}正在扫描服务 (模式: ${view_mode}), 请稍候...${NC}"
    
    echo ""
    # 移除“服务描述”列, 让布局更紧凑
    printf "${BOLD}%-4s %-45s %-12s %-10s %s${NC}\n" "序号" "服务名称" "开机自启" "运行状态" "服务路径"
    printf "${CYAN}%s${NC}\n" "────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────"

    while IFS= read -r line; do
        if [ -z "$line" ]; then continue; fi
        local unit=$(echo "$line" | awk '{print $1}');
        if [[ "$unit" == *@.service ]]; then continue; fi
        
        # 优化: 不再获取冗长的“描述”信息, 加快扫描速度
        local boot_state=$(echo "$line" | awk '{print $2}');
        local details=$($SUDO_CMD systemctl show -p ActiveState,FragmentPath --value "$unit" 2>/dev/null)
        local active_state=$(echo "$details" | sed -n '1p' | xargs)
        local file_path=$(echo "$details" | sed -n '2p' | xargs)

        if [ -z "$file_path" ]; then file_path="(in-memory unit)"; fi
        
        local should_display_by_view=false
        if [[ "$view_mode" == "all" ]] || [[ "$file_path" == /etc/systemd/system/* ]]; then
            should_display_by_view=true
        fi

        if $should_display_by_view; then
            # 优化: 筛选只针对服务名称
            local should_display_by_keyword=false
            if [ -z "$keyword" ]; then
                should_display_by_keyword=true
            elif [[ "$unit" == *"$keyword"* ]]; then
                should_display_by_keyword=true
            fi

            if $should_display_by_keyword; then
                map_ref[$index]=$unit
                local line_color=""
                if [[ "$active_state" == "active" && "$boot_state" != "enabled" && "$boot_state" != "enabled-runtime" ]]; then
                    line_color=$BLUE
                elif [[ "$active_state" == "active" ]]; then
                    line_color=$GREEN
                else
                    line_color=$RED
                fi
                
                # 新的 printf, 已移除 description
                printf "${line_color}%-4s %-45s %-12s %-10s %s${NC}\n" "${index})" "$unit" "$boot_state" "$active_state" "$file_path"
                
                index=$((index + 1))
            fi
        fi
    done < <(systemctl list-unit-files --type=service --no-pager --plain | tail -n +2 | head -n -1)
    
    if [ ${#map_ref[@]} -eq 0 ]; then
        echo -e "\n${YELLOW}根据当前视图和筛选条件, 未找到任何服务。${NC}"
        return 1
    fi
    return 0
}

# --- [新] Systemd (systemctl) 综合管理主函数 (优化编辑提示) ---
manage_systemctl(){
    declare -A services_map
    local view_mode="user_only" 
    local filter_keyword=""

    while true; do
        clear
        _systemctl_list_services services_map "$view_mode" "$filter_keyword"
        
        local toggle_prompt="[a]全部"; if [[ "$view_mode" == "all" ]]; then toggle_prompt="[a]仅用户"; fi
        echo ""
        read -p "$(echo -e ${MAGENTA}"请输序号, [f]筛选, [c]创建, ${toggle_prompt}, [r]刷新, [q]返回: "${NC})" main_choice

        case $main_choice in
            q|Q) break ;;
            r|R) continue ;;
            a|A)
                if [[ "$view_mode" == "user_only" ]]; then view_mode="all"; else view_mode="user_only"; fi
                continue;;
            f|F)
                read -p "请输入筛选关键字 (留空则清除筛选): " new_keyword
                filter_keyword="$new_keyword"
                continue
                ;;
            c|C)
                # (创建服务的功能代码没有变化, 此处省略)
                print_title "创建新的 Systemd 服务"; read -p "服务名称 (*.service): " srv_name; if [[ -z "$srv_name" || "$srv_name" != *.service ]]; then echo -e "\n${RED}错误: 名称不正确。${NC}"; sleep 2; continue; fi;
                local srv_path="/etc/systemd/system/${srv_name}"; if [ -f "$srv_path" ]; then echo -e "\n${RED}错误: 服务已存在!${NC}"; sleep 2; continue; fi;
                read -p "服务描述 (Description): " srv_desc; read -p "执行的命令 (ExecStart): " srv_exec; read -p "运行用户 [root]: " srv_user; srv_user=${srv_user:-root}; read -p "重启策略 [on-failure]: " srv_restart; srv_restart=${srv_restart:-on-failure};
                echo -e "\n${CYAN}--- 服务文件预览 ---${NC}"; local service_content="[Unit]\nDescription=${srv_desc}\nAfter=network.target\n\n[Service]\nUser=${srv_user}\nExecStart=${srv_exec}\nRestart=${srv_restart}\n\n[Install]\nWantedBy=multi-user.target";
                echo -e "${YELLOW}${service_content}${NC}"; read -p "确认创建? [Y/n]: " confirm;
                if [[ -z "$confirm" || "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    echo -e "$service_content" | $SUDO_CMD tee "$srv_path" > /dev/null; echo -e "\n${GREEN}服务文件已创建${NC}"; echo -e "${CYAN}重载 systemd...${NC}"; $SUDO_CMD systemctl daemon-reload;
                    read -p "是否立即启用并启动? [Y/n]: " enable_now; if [[ -z "$enable_now" || "$enable_now" == "y" || "$enable_now" == "Y" ]]; then $SUDO_CMD systemctl enable --now "$srv_name"; fi;
                    echo -e "\n${GREEN}OK!${NC}";
                else echo -e "\n${YELLOW}已取消。${NC}"; fi; read -p "...";;
            *)
                if [[ "$main_choice" =~ ^[0-9]+$ ]] && [ -n "${services_map[$main_choice]}" ]; then
                    local service_name=${services_map[$main_choice]}
                    while true; do
                        local boot_status_output=$($SUDO_CMD systemctl is-enabled $service_name 2>/dev/null);
                        if [ $? -ne 0 ] && [ -z "$boot_status_output" ]; then boot_status="not-found"; else boot_status=$boot_status_output; fi;
                        local details=$($SUDO_CMD systemctl show -p ActiveState,SubState --value $service_name);
                        local current_status_active=$(echo "$details" | sed -n '1p');
                        local status_color_runtime=$RED; [[ "$current_status_active" == "active" ]] && status_color_runtime=$GREEN;
                        local status_color_boot=$YELLOW; [[ "$boot_status" == "enabled" ]] && status_color_boot=$CYAN;

                        print_title "管理服务: ${service_name}";
                        local plain_status_line="[运行: ${current_status_active} | 自启: ${boot_status}]";
                        local colored_status_line="[运行: ${status_color_runtime}${current_status_active}${NC} | 自启: ${status_color_boot}${boot_status}${NC}]";
                        local width=$(tput cols); local status_width=$(get_display_width "$plain_status_line"); local padding=$(((width - status_width) / 2)); printf "%*s%b\n\n" $padding "" "${colored_status_line}";

                        echo -e "  ${YELLOW}1.${NC} 查看状态 (status)   ${YELLOW}2.${NC} 启动服务 (start)    ${YELLOW}3.${NC} 停止服务 (stop)";
                        echo -e "  ${YELLOW}4.${NC} 重启服务 (restart)  ${YELLOW}5.${NC} 重载配置 (reload)   ${YELLOW}6.${NC} 设为自启 (enable)";
                        echo -e "  ${YELLOW}7.${NC} 取消自启 (disable)  ${CYAN}8.${NC} 编辑配置 (edit)";
                        echo -e "\n  ${RED}q.${NC} 返回服务列表";
                        echo "";
                        read -p "$(echo -e ${MAGENTA}"-> 请选择一个操作: "${NC})" ctl_choice;
                        
                        case $ctl_choice in
                            1) clear; $SUDO_CMD systemctl status $service_name ;;
                            2) clear; $SUDO_CMD systemctl start $service_name && echo -e "\n${GREEN}OK${NC}" || echo -e "\n${RED}FAIL${NC}";;
                            3) clear; $SUDO_CMD systemctl stop $service_name && echo -e "\n${GREEN}OK${NC}" || echo -e "\n${RED}FAIL${NC}";;
                            4) clear; $SUDO_CMD systemctl restart $service_name && echo -e "\n${GREEN}OK${NC}" || echo -e "\n${RED}FAIL${NC}";;
                            5) clear; $SUDO_CMD systemctl reload $service_name && echo -e "\n${GREEN}OK${NC}" || echo -e "\n${RED}FAIL${NC}";;
                            6) clear; $SUDO_CMD systemctl enable $service_name;;
                            7) clear; $SUDO_CMD systemctl disable $service_name;;
                            8) 
                                # --- 核心修正点: 恢复了清晰的说明和按键提示 ---
                                clear
                                echo -e "${YELLOW}即将使用 'systemctl edit' 打开编辑器...${NC}\n"
                                echo -e "这是编辑服务配置的 ${BOLD}推荐方式${NC}, 它会创建一个“覆盖”文件, 而不修改系统原始文件。"
                                echo -e "这样可以确保在系统升级时, 您的自定义配置不会被覆盖。"
                                read -p "$(echo -e "\n${YELLOW}按 Enter 键继续...${NC}")"
                                
                                $SUDO_CMD systemctl edit "$service_name"
                                
                                echo -e "\n${CYAN}编辑会话已结束。${NC}"
                                echo -e "如果您刚才保存了更改, 可能需要重启(restart)服务来使其生效。"
                                ;;
                            q|Q) break ;;
                            *) clear; echo -e "${RED}无效选项!${NC}" ;;
                        esac
                        read -p "$(echo -e "\n${YELLOW}按 Enter 键返回...${NC}")"
                    done
                else
                    echo -e "\n${RED}无效输入!${NC}"; sleep 1;
                fi
                ;;
        esac
    done
}

manage_sync(){
    if ! check_and_install "rsync" "rsync"; then return; fi;
    print_title "目录远程同步/备份 (rsync)"; echo -e "  ${YELLOW}1.${NC} 备份 (本地 -> 远程)"; echo -e "  ${YELLOW}2.${NC} 恢复 (远程 -> 本地)"; echo ""; read -p "$(echo -e ${MAGENTA}"-> 选择模式: "${NC})" sync_mode;
    clear; read -p "本地目录路径: " local_dir; read -p "远程服务器用户名: " remote_user; read -p "远程服务器地址: " remote_host; read -p "远程服务器目录路径: " remote_dir;
    if [ "$sync_mode" == "1" ]; then
        echo -e "\n${CYAN}将执行备份: ${local_dir} -> ${remote_user}@${remote_host}:${remote_dir}${NC}"; read -p "确认? (y/n): " confirm;
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then rsync -avz --progress --delete "$local_dir" "${remote_user}@${remote_host}:${remote_dir}"; echo -e "\n${GREEN}OK${NC}"; else echo "取消."; fi;
    elif [ "$sync_mode" == "2" ]; then
        echo -e "\n${CYAN}将执行恢复: ${remote_user}@${remote_host}:${remote_dir} -> ${local_dir}${NC}"; read -p "确认? (y/n): " confirm;
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then rsync -avz --progress --delete "${remote_user}@${remote_host}:${remote_dir}" "$local_dir"; echo -e "\n${GREEN}OK${NC}"; else echo "取消."; fi;
    else echo -e "\n${RED}无效选项!${NC}"; fi;
    read -p "$(echo -e "\n${YELLOW}按 Enter 返回...${NC}")";
}

# --- Main Menu ---
while true; do
    print_title "Linux 实用工具集"
    echo -e "  ${YELLOW}1.${NC} 虚拟内存管理 (Swap)"
    echo -e "  ${YELLOW}2.${NC} DNS 修改"
    echo -e "  ${YELLOW}3.${NC} HTTP 服务器管理"
    echo -e "  ${YELLOW}4.${NC} iperf3 网络性能测试"
    echo -e "  ${YELLOW}5.${NC} rc.local 文件查看与编辑"
    echo -e "  ${YELLOW}6.${NC} /etc/hosts 文件管理"
    echo -e "  ${YELLOW}7.${NC} Systemd (systemctl) 综合管理"
    echo -e "  ${YELLOW}8.${NC} 目录远程同步 (rsync)"
    echo -e "\n  ${RED}q.${NC} 退出脚本"
    echo ""
    read -p "$(echo -e ${MAGENTA}${BOLD}"  -> 请选择需要的功能: "${NC})" main_choice

    case $main_choice in
        1) manage_swap ;;
        2) modify_dns ;;
        3) manage_http_server ;;
        4) manage_iperf3 ;;
        5) edit_rc_local ;;
        6) manage_hosts_file ;;
        7) manage_systemctl ;;
        8) manage_sync ;;
        q) clear; echo -e "\n${GREEN}感谢使用! 再见!${NC}\n"; exit 0;;
        *) echo -e "\n${RED}无效的选项, 请重新输入.${NC}"; sleep 1;;
    esac
done
