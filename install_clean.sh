#!/bin/bash

# --- Цвета ---
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# --- Проверка root ---
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Запустите с правами root!${NC}"
        exit 1
    fi
}

# --- Подготовка системы (один раз) ---
prepare_system() {
    # Копируем себя в /usr/local/bin
    if [ "$0" != "/usr/local/bin/gokaskad" ]; then
        cp -f "$0" "/usr/local/bin/gokaskad"
        chmod +x "/usr/local/bin/gokaskad"
    fi

    # Включаем IP forwarding и BBR
    grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null

    # Устанавливаем UFW, если нет
    if ! command -v ufw &>/dev/null; then
        apt update -y && apt install -y ufw
    fi

    ufw --force enable
    ufw allow 22/tcp >/dev/null 2>&1

    # Разрешаем forward в настройках UFW
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

    # Убеждаемся, что в before.rules есть секции *nat и *filter
    if ! grep -q "^\*nat" /etc/ufw/before.rules; then
        echo -e "\n*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n" >> /etc/ufw/before.rules
    fi
    if ! grep -q "^\*filter" /etc/ufw/before.rules; then
        cat >> /etc/ufw/before.rules << "EOF"

*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]
# ... остальные стандартные правила UFW будут добавлены при переустановке.
COMMIT
EOF
    fi
}

# --- Функция добавления правила (вставляем перед последним COMMIT в каждой секции) ---
add_rule() {
    local PROTO=$1
    local IN_PORT=$2
    local OUT_PORT=$3
    local TARGET_IP=$4

    # Проверяем, нет ли уже такого DNAT
    if grep -q "^\-A PREROUTING -p $PROTO --dport $IN_PORT -j DNAT --to-destination $TARGET_IP:$OUT_PORT" /etc/ufw/before.rules; then
        echo -e "${YELLOW}Правило уже существует!${NC}"
        return 1
    fi

    # Строки для вставки
    local NAT_LINES="-A PREROUTING -p $PROTO --dport $IN_PORT -j DNAT --to-destination $TARGET_IP:$OUT_PORT\n-A POSTROUTING -d $TARGET_IP -p $PROTO --dport $OUT_PORT -j MASQUERADE"
    local FILTER_LINES="-A ufw-before-input -p $PROTO --dport $IN_PORT -j ACCEPT\n-A ufw-before-forward -p $PROTO --dport $OUT_PORT -j ACCEPT"

    # Вставка в секцию *nat (перед последним COMMIT в этой секции)
    sed -i "/^\*nat$/,/^COMMIT$/ {
        /^COMMIT$/ i\\
$NAT_LINES
    }" /etc/ufw/before.rules

    # Вставка в секцию *filter (перед последним COMMIT в этой секции)
    sed -i "/^\*filter$/,/^COMMIT$/ {
        /^COMMIT$/ i\\
$FILTER_LINES
    }" /etc/ufw/before.rules

    ufw reload
    echo -e "${GREEN}Правило добавлено: $PROTO $IN_PORT -> $TARGET_IP:$OUT_PORT${NC}"
    return 0
}

# --- Удаление правила (по номеру из списка) ---
delete_rule() {
    echo -e "\n${CYAN}--- Активные правила ---${NC}"
    local RULES=()
    local i=1
    while IFS= read -r line; do
        if [[ $line =~ ^\-A\ PREROUTING\ -p\ ([a-z]+)\ --dport\ ([0-9]+)\ -j\ DNAT\ --to-destination\ ([0-9.]+):([0-9]+) ]]; then
            proto=${BASH_REMATCH[1]}
            in_port=${BASH_REMATCH[2]}
            target_ip=${BASH_REMATCH[3]}
            out_port=${BASH_REMATCH[4]}
            RULES+=("$proto:$in_port:$target_ip:$out_port")
            echo -e "${YELLOW}[$i]${NC} $proto $in_port -> $target_ip:$out_port"
            ((i++))
        fi
    done < <(grep '^\-A PREROUTING' /etc/ufw/before.rules)

    if [ ${#RULES[@]} -eq 0 ]; then
        echo -e "${RED}Нет правил для удаления.${NC}"
        read -p "Нажмите Enter..."
        return
    fi

    read -p "Выберите номер правила для удаления (0 отмена): " num
    if [[ $num -eq 0 || $num -gt ${#RULES[@]} ]]; then return; fi

    IFS=':' read -r proto in_port target_ip out_port <<< "${RULES[$((num-1))]}"

    # Удаляем строки из секции *nat
    sed -i "/^\*nat$/,/^COMMIT$/ {
        /^\-A PREROUTING -p $proto --dport $in_port -j DNAT --to-destination $target_ip:$out_port/d
        /^\-A POSTROUTING -d $target_ip -p $proto --dport $out_port -j MASQUERADE/d
    }" /etc/ufw/before.rules

    # Удаляем строки из секции *filter
    sed -i "/^\*filter$/,/^COMMIT$/ {
        /^\-A ufw-before-input -p $proto --dport $in_port -j ACCEPT/d
        /^\-A ufw-before-forward -p $proto --dport $out_port -j ACCEPT/d
    }" /etc/ufw/before.rules

    ufw reload
    echo -e "${GREEN}Правило удалено.${NC}"
    read -p "Нажмите Enter..."
}

# --- Просмотр активных правил ---
list_rules() {
    echo -e "\n${CYAN}--- Активные правила (UFW) ---${NC}"
    echo -e "${MAGENTA}ПРОТОКОЛ\tВХ.ПОРТ\t\tЦЕЛЬ (IP:ПОРТ)${NC}"
    grep '^\-A PREROUTING' /etc/ufw/before.rules | while read -r line; do
        proto=$(echo "$line" | grep -oP '(?<=-p )\w+')
        in_port=$(echo "$line" | grep -oP '(?<=--dport )\d+')
        dest=$(echo "$line" | grep -oP '(?<=--to-destination )[\d.]+:\d+')
        echo -e "$proto\t\t$in_port\t\t$dest"
    done
    echo ""
    read -p "Нажмите Enter..."
}

# --- Меню ---
show_menu() {
    while true; do
        clear
        echo -e "${MAGENTA}"
        echo "**********************************************"
        echo "   Каскадный прокси (UFW) — простая версия"
        echo "**********************************************"
        echo -e "${NC}"
        echo "1) Добавить правило AmneziaWG / WireGuard (UDP, одинаковые порты)"
        echo "2) Добавить правило VLESS / XRay / TProxy / MTProto(TCP, одинаковые порты)"
        echo "3) Добавить кастомное правило (разные порты)"
        echo "4) Показать активные правила"
        echo "5) Удалить правило"
        echo "6) Сбросить ВСЕ добавленные правила (очистить только наши строки)"
        echo "0) Выход"
        read -p "Выбор: " choice

        case $choice in
            1)
                read -p "IP назначения: " target
                read -p "Порт: " port
                add_rule udp "$port" "$port" "$target"
                ;;
            2)
                read -p "IP назначения: " target
                read -p "Порт: " port
                add_rule tcp "$port" "$port" "$target"
                ;;
            3)
                read -p "Протокол (tcp/udp): " proto
                read -p "IP назначения: " target
                read -p "Входящий порт (на этом VPS): " in_port
                read -p "Исходящий порт (на конечном сервере): " out_port
                add_rule "$proto" "$in_port" "$out_port" "$target"
                ;;
            4) list_rules ;;
            5) delete_rule ;;
            6)
                echo -e "${RED}Полная очистка добавленных правил? (y/n)${NC}"
                read -p "" ans
                if [[ "$ans" == "y" ]]; then
                    # Удаляем строки, начинающиеся с "-A PREROUTING" и "-A POSTROUTING" в секции *nat
                    sed -i "/^\*nat$/,/^COMMIT$/ { /^\-A PREROUTING /d; /^\-A POSTROUTING /d; }" /etc/ufw/before.rules
                    # Удаляем строки, начинающиеся с "-A ufw-before-input" и "-A ufw-before-forward" в секции *filter
                    sed -i "/^\*filter$/,/^COMMIT$/ { /^\-A ufw-before-input /d; /^\-A ufw-before-forward /d; }" /etc/ufw/before.rules
                    ufw reload
                    echo -e "${GREEN}Все добавленные правила удалены.${NC}"
                fi
                read -p "Нажмите Enter..."
                ;;
            0) exit 0 ;;
        esac
    done
}

# --- Запуск ---
check_root
prepare_system
show_menu
