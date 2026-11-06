#!/bin/bash
# =============================================================================
# Kaskad UFW helper — управление DNAT-пробросом портов через UFW
# https://github.com/hargluk/kaskad_ufw_only
#
# Использование:
#   ./install_clean.sh           интерактивное меню
#   ./install_clean.sh prepare   установить ufw, настроить sysctl, ip_forward
#   ./install_clean.sh add       добавить правило проброса
#   ./install_clean.sh list      показать правила kaskad
#   ./install_clean.sh delete    удалить правило
#   ./install_clean.sh reset     удалить ВСЕ правила kaskad (только с маркером)
#   ./install_clean.sh help      справка
#
# Все правила, добавленные скриптом, помечаются `-m comment --comment kaskad`
# в /etc/ufw/before.rules. Удаление ("delete"/"reset") затрагивает ТОЛЬКО
# строки с этим маркером — правила, добавленные вручную или другими
# инструментами, не модифицируются.
# =============================================================================

set -euo pipefail

# ---------- Цвета ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ---------- Константы ----------
KASKAD_MARKER='kaskad'
BEFORE_RULES='/etc/ufw/before.rules'
SELF_PATH='/usr/local/bin/gokaskad'
BACKUP_DIR='/etc/ufw/backups'
LOCK_FILE='/var/lock/kaskad.lock'

# ---------- Логирование ----------
log_info()  { echo -e "${GREEN}[*]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[x]${NC} $*" >&2; }
log_step()  { echo -e "${BLUE}→${NC} $*"; }

die() { log_error "$*"; exit 1; }

confirm() {
    local prompt=${1:-"Продолжить?"}
    local answer
    read -r -p "$prompt [y/N]: " answer || return 1
    [[ "$answer" =~ ^[Yy]$ ]]
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Запустите скрипт от root (sudo)"
}

# ---------- Валидация ----------
validate_ipv4() {
    local ip=$1
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    local octet
    for octet in $ip; do
        (( 10#$octet <= 255 )) || return 1
    done
    return 0
}

validate_port() {
    local port=$1
    [[ $port =~ ^[0-9]+$ ]] || return 1
    (( port >= 1 && port <= 65535 ))
}

validate_proto() {
    [[ $1 =~ ^(tcp|udp)$ ]]
}

# ---------- Утилиты ----------
detect_ssh_port() {
    local port
    port=$(grep -E '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null \
           | awk '{print $2}' | head -1)
    echo "${port:-22}"
}

acquire_lock() {
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Другой экземпляр kaskad уже работает (lock: $LOCK_FILE)"
}

backup_before_rules() {
    [ -f "$BEFORE_RULES" ] || return 0
    mkdir -p "$BACKUP_DIR"
    local backup
    backup="${BACKUP_DIR}/before.rules.$(date +%Y%m%d_%H%M%S)"
    cp -a "$BEFORE_RULES" "$backup"
    log_info "Бэкап: $backup"

    # Ротация: оставляем последние 20 бэкапов
    local count
    count=$(ls -1 "${BACKUP_DIR}"/before.rules.* 2>/dev/null | wc -l)
    if [ "$count" -gt 20 ]; then
        ls -1t "${BACKUP_DIR}"/before.rules.* 2>/dev/null \
            | tail -n +21 | xargs -r rm -f || true
    fi
}

latest_backup() {
    ls -1t "${BACKUP_DIR}"/before.rules.* 2>/dev/null | head -1
}

rollback_from_backup() {
    local backup
    backup=$(latest_backup)
    if [ -n "$backup" ]; then
        cp -a "$backup" "$BEFORE_RULES"
        log_warn "Откат из бэкапа: $backup"
    fi
}

ensure_comments_module() {
    modprobe xt_comment 2>/dev/null || true
    if ! iptables -m comment --help >/dev/null 2>&1; then
        die "Модуль xt_comment недоступен. Установите: apt install iptables"
    fi
}

# ---------- Работа с before.rules ----------
ensure_standard_rules() {
    [ -f "$BEFORE_RULES" ] || die "$BEFORE_RULES не найден. Установлен ли ufw?"

    if ! grep -q 'ctstate RELATED,ESTABLISHED' "$BEFORE_RULES" \
       || ! grep -q 'allow all on loopback' "$BEFORE_RULES"; then
        log_warn "В $BEFORE_RULES отсутствуют стандартные правила UFW — восстанавливаем эталон"
        if [ -f /usr/share/ufw/before.rules ]; then
            cp /usr/share/ufw/before.rules "$BEFORE_RULES"
            log_info "Восстановлено из /usr/share/ufw/before.rules"
        else
            log_error "Эталон /usr/share/ufw/before.rules не найден — создаём минимальный"
            cat > "$BEFORE_RULES" <<'EOF'
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]

-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
EOF
        fi
    fi
}

ensure_sections() {
    [ -f "$BEFORE_RULES" ] || die "$BEFORE_RULES не найден"

    local nat_count filter_count
    nat_count=$(grep -c '^\*nat$' "$BEFORE_RULES" 2>/dev/null || true)
    filter_count=$(grep -c '^\*filter$' "$BEFORE_RULES" 2>/dev/null || true)
    nat_count=${nat_count:-0}
    filter_count=${filter_count:-0}

    [ "$nat_count" -le 1 ]    || die "В $BEFORE_RULES больше одной секции *nat — исправьте вручную"
    [ "$filter_count" -le 1 ] || die "В $BEFORE_RULES больше одной секции *filter — исправьте вручную"

    if [ "$nat_count" -eq 0 ]; then
        log_warn "Секция *nat отсутствует — добавляем"
        printf '\n*nat\n:PREROUTING ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n' >> "$BEFORE_RULES"
    fi

    if [ "$filter_count" -eq 0 ]; then
        log_warn "Секция *filter отсутствует — добавляем"
        printf '\n*filter\n:ufw-before-input - [0:0]\n:ufw-before-output - [0:0]\n:ufw-before-forward - [0:0]\n:ufw-not-local - [0:0]\nCOMMIT\n' >> "$BEFORE_RULES"
    fi

    # Проверка целостности: обе секции должны иметь COMMIT
    local commit_count
    commit_count=$(grep -c '^COMMIT$' "$BEFORE_RULES")
    [ "$commit_count" -ge 2 ] || die "В $BEFORE_RULES меньше двух COMMIT — файл повреждён"
}

# Вставка содержимого файла $lines_file перед COMMIT в секции $section
insert_before_commit_in_section() {
    local section=$1
    local lines_file=$2
    local tmp
    tmp=$(mktemp)
    awk -v section="$section" -v lines_file="$lines_file" '
        BEGIN { in_section=0; inserted=0 }
        $0 == section { in_section=1 }
        in_section && !inserted && $0 == "COMMIT" {
            while ((getline line < lines_file) > 0) print line
            close(lines_file)
            inserted = 1
        }
        { print }
        in_section && $0 == "COMMIT" { in_section=0 }
    ' "$BEFORE_RULES" > "$tmp"
    mv "$tmp" "$BEFORE_RULES"
}

# ---------- prepare ----------
prepare_system() {
    require_root
    acquire_lock
    ensure_comments_module

    # Self-install
    local self_real
    self_real=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "$0")
    if [ "$self_real" != "$SELF_PATH" ]; then
        if [ -f "$SELF_PATH" ] && cmp -s "$self_real" "$SELF_PATH"; then
            log_info "Скрипт уже установлен в $SELF_PATH"
        else
            cp -f "$self_real" "$SELF_PATH"
            chmod 755 "$SELF_PATH"
            log_info "Скрипт установлен в $SELF_PATH (запуск: gokaskad)"
        fi
    fi

    # sysctl
    log_step "Настройка sysctl"
    local sysctl_changed=0
    local key val
    while IFS='=' read -r key val; do
        key="${key// /}"
        val="${val// /}"
        [ -z "$key" ] && continue
        local escaped_key
        escaped_key="${key//./\\.}"
        if grep -qE "^[[:space:]]*${escaped_key}[[:space:]]*=" /etc/sysctl.conf 2>/dev/null; then
            local current
            current=$(grep -E "^[[:space:]]*${escaped_key}[[:space:]]*=" /etc/sysctl.conf | head -1 | sed 's/.*=[[:space:]]*//')
            if [ "$current" != "$val" ]; then
                sed -i -E "s|^[[:space:]]*${escaped_key}[[:space:]]*=.*|${key}=${val}|" /etc/sysctl.conf
                sysctl_changed=1
            fi
        else
            echo "${key}=${val}" >> /etc/sysctl.conf
            sysctl_changed=1
        fi
    done <<'SYSCTL'
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYSCTL

    if [ "$sysctl_changed" -eq 1 ]; then
        if ! sysctl -p >/dev/null 2>&1; then
            log_warn "sysctl -p завершился с ошибками — проверьте /etc/sysctl.conf"
        fi
    fi

    # Проверка фактического значения ip_forward
    if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" != "1" ]; then
        die "net.ipv4.ip_forward != 1 — проброс работать не будет"
    fi

    # Установка ufw
    if ! command -v ufw >/dev/null 2>&1; then
        log_step "Установка ufw"
        apt-get update -y
        apt-get install -y --no-install-recommends ufw
    fi

    # before.rules
    log_step "Проверка before.rules"
    backup_before_rules
    ensure_standard_rules
    ensure_sections

    # ufw состояние
    local ufw_active=0
    if ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw_active=1
    fi

    local ssh_port
    ssh_port=$(detect_ssh_port)

    if [ "$ufw_active" -eq 0 ]; then
        log_warn "UFW сейчас выключен."
        log_warn "После включения будут доступны только явно разрешённые порты."
        log_warn "Автоматически открывается SSH: ${ssh_port}/tcp"
        log_warn "Убедитесь, что остальные нужные сервисы разрешены ДО включения."
        if ! confirm "Включить UFW?"; then
            log_info "UFW не включён. Скрипт завершён."
            return 0
        fi
        ufw --force enable
        ufw allow "${ssh_port}/tcp" >/dev/null
    else
        log_info "UFW уже активен — состояние не меняем"
        if ! ufw status 2>/dev/null | grep -qE "^${ssh_port}/tcp\b"; then
            log_warn "SSH (${ssh_port}/tcp) не найден в правилах UFW — добавляем"
            ufw allow "${ssh_port}/tcp" >/dev/null
        fi
    fi

    # Проверка DEFAULT_FORWARD_POLICY
    if [ -f /etc/default/ufw ] \
       && grep -q 'DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw; then
        log_info "DEFAULT_FORWARD_POLICY=DROP — это безопасно."
        log_info "  Скрипт добавляет явные ACCEPT-правила в ufw-before-forward для каждого проброса."
        log_info "  Если проброс не работает, проверьте: ufw status verbose, iptables -t nat -L -n -v"
    fi

    ufw reload >/dev/null 2>&1 || log_warn "ufw reload завершился с ошибкой"

    log_info "Система подготовлена"
}

# ---------- add ----------
add_rule() {
    require_root
    acquire_lock

    command -v ufw >/dev/null 2>&1 \
        || die "ufw не установлен. Сначала выполните: $(basename "$0") prepare"
    [ -f "$BEFORE_RULES" ] \
        || die "before.rules не найден. Сначала выполните: $(basename "$0") prepare"
    ensure_comments_module

    echo "=== Добавление правила проброса ==="
    local proto in_port target_ip out_port

    read -r -p "Протокол (tcp/udp): " proto || die "Ввод отменён"
    proto=${proto,,}
    validate_proto "$proto" || die "Недопустимый протокол: '$proto' (ожидается tcp или udp)"

    read -r -p "Входящий порт на этом сервере: " in_port || die "Ввод отменён"
    validate_port "$in_port" || die "Недопустимый порт: '$in_port'"

    read -r -p "Внутренний IP-адрес назначения: " target_ip || die "Ввод отменён"
    validate_ipv4 "$target_ip" || die "Недопустимый IPv4: '$target_ip'"

    read -r -p "Порт на внутреннем IP: " out_port || die "Ввод отменён"
    validate_port "$out_port" || die "Недопустимый порт: '$out_port'"

    local dnat masq inacc fwacc
    dnat="-A PREROUTING -p ${proto} --dport ${in_port} -j DNAT --to-destination ${target_ip}:${out_port} -m comment --comment ${KASKAD_MARKER}"
    masq="-A POSTROUTING -p ${proto} -d ${target_ip} --dport ${out_port} -j MASQUERADE -m comment --comment ${KASKAD_MARKER}"
    inacc="-A ufw-before-input -p ${proto} --dport ${in_port} -j ACCEPT -m comment --comment ${KASKAD_MARKER}"
    fwacc="-A ufw-before-forward -p ${proto} -d ${target_ip} --dport ${out_port} -j ACCEPT -m comment --comment ${KASKAD_MARKER}"

    if grep -qxF "$dnat" "$BEFORE_RULES" 2>/dev/null; then
        log_warn "Такое правило уже существует"
        return 0
    fi

    backup_before_rules

    local nat_tmp filter_tmp
    nat_tmp=$(mktemp)
    filter_tmp=$(mktemp)
    trap 'rm -f "$nat_tmp" "$filter_tmp"' RETURN

    printf '%s\n%s\n' "$dnat" "$masq" > "$nat_tmp"
    printf '%s\n%s\n' "$inacc" "$fwacc" > "$filter_tmp"

    insert_before_commit_in_section '*nat' "$nat_tmp"
    insert_before_commit_in_section '*filter' "$filter_tmp"

    # Проверка, что вставилось
    local kaskad_count
    kaskad_count=$(grep -cF "m comment --comment ${KASKAD_MARKER}" "$BEFORE_RULES" || true)
    kaskad_count=${kaskad_count:-0}
    if [ "$kaskad_count" -lt 4 ]; then
        rollback_from_backup
        die "Не удалось вставить правила (найдено kaskad-строк: $kaskad_count) — откат"
    fi

    if ! ufw reload >/dev/null 2>&1; then
        rollback_from_backup
        die "ufw reload завершился с ошибкой — откат выполнен"
    fi

    log_info "Правило добавлено: ${proto}/${in_port} → ${target_ip}:${out_port}"
}

# ---------- parse/list ----------
parse_dnat_fields() {
    local line=$1
    local proto in_port dest target_ip out_port
    proto=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="-p") {print $(i+1); exit}}')
    in_port=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="--dport") {print $(i+1); exit}}')
    dest=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i=="--to-destination") {print $(i+1); exit}}')
    target_ip=${dest%:*}
    out_port=${dest##*:}
    printf '%s %s %s %s\n' "$proto" "$in_port" "$target_ip" "$out_port"
}

list_kaskad_rules() {
    grep -F "m comment --comment ${KASKAD_MARKER}" "$BEFORE_RULES" 2>/dev/null \
        | grep '^-A PREROUTING' || true
}

list_rules() {
    [ -f "$BEFORE_RULES" ] || die "$BEFORE_RULES не найден"

    local rules
    rules=$(list_kaskad_rules)

    if [ -z "$rules" ]; then
        log_info "Правил, добавленных kaskad, нет"
        return 0
    fi

    echo "=== Правила kaskad ==="
    printf "%-4s %-6s %-9s %-20s %-9s\n" "#" "PROTO" "IN_PORT" "TARGET_IP" "OUT_PORT"
    local i=1 line proto in_port target_ip out_port
    while IFS= read -r line; do
        read -r proto in_port target_ip out_port < <(parse_dnat_fields "$line")
        printf "%-4d %-6s %-9s %-20s %-9s\n" "$i" "$proto" "$in_port" "$target_ip" "$out_port"
        i=$((i+1))
    done <<< "$rules"
}

# ---------- delete ----------
remove_dnat_rule() {
    local proto=$1 in_port=$2 target_ip=$3 out_port=$4
    local dnat masq inacc fwacc
    dnat="-A PREROUTING -p ${proto} --dport ${in_port} -j DNAT --to-destination ${target_ip}:${out_port} -m comment --comment ${KASKAD_MARKER}"
    masq="-A POSTROUTING -p ${proto} -d ${target_ip} --dport ${out_port} -j MASQUERADE -m comment --comment ${KASKAD_MARKER}"
    inacc="-A ufw-before-input -p ${proto} --dport ${in_port} -j ACCEPT -m comment --comment ${KASKAD_MARKER}"
    fwacc="-A ufw-before-forward -p ${proto} -d ${target_ip} --dport ${out_port} -j ACCEPT -m comment --comment ${KASKAD_MARKER}"

    local tmp
    tmp=$(mktemp)
    grep -vF -e "$dnat" -e "$masq" -e "$inacc" -e "$fwacc" "$BEFORE_RULES" > "$tmp" || true
    mv "$tmp" "$BEFORE_RULES"
}

delete_rule() {
    require_root
    acquire_lock
    [ -f "$BEFORE_RULES" ] || die "$BEFORE_RULES не найден"

    local rules
    rules=$(list_kaskad_rules)

    if [ -z "$rules" ]; then
        log_warn "Правил, добавленных kaskad, нет"
        return 0
    fi

    echo "=== Существующие правила ==="
    local -a proto_arr=() in_arr=() ip_arr=() out_arr=()
    local i=1 line proto in_port target_ip out_port
    while IFS= read -r line; do
        read -r proto in_port target_ip out_port < <(parse_dnat_fields "$line")
        printf "%d) %s/%s → %s:%s\n" "$i" "$proto" "$in_port" "$target_ip" "$out_port"
        proto_arr[$i]=$proto
        in_arr[$i]=$in_port
        ip_arr[$i]=$target_ip
        out_arr[$i]=$out_port
        i=$((i+1))
    done <<< "$rules"

    local choice
    read -r -p "Номер правила для удаления (0 — отмена): " choice || return 0
    [[ "$choice" == "0" ]] && return 0
    [[ "$choice" =~ ^[0-9]+$ ]] || die "Некорректный номер: '$choice'"
    [ -n "${proto_arr[$choice]:-}" ] || die "Правило №$choice не найдено"

    local proto=${proto_arr[$choice]}
    local in_port=${in_arr[$choice]}
    local target_ip=${ip_arr[$choice]}
    local out_port=${out_arr[$choice]}

    backup_before_rules
    remove_dnat_rule "$proto" "$in_port" "$target_ip" "$out_port"

    if ! ufw reload >/dev/null 2>&1; then
        rollback_from_backup
        die "ufw reload завершился с ошибкой — откат выполнен"
    fi

    log_info "Правило удалено: ${proto}/${in_port} → ${target_ip}:${out_port}"
}

# ---------- reset ----------
reset_rules() {
    require_root
    acquire_lock
    [ -f "$BEFORE_RULES" ] || die "$BEFORE_RULES не найден"

    local count
    count=$(grep -cF "m comment --comment ${KASKAD_MARKER}" "$BEFORE_RULES" 2>/dev/null || true)
    count=${count:-0}

    if [ "$count" -eq 0 ]; then
        log_info "Нечего сбрасывать — нет правил kaskad"
        return 0
    fi

    log_warn "Будет удалено строк с маркером kaskad: $count"
    confirm "Продолжить?" || return 0

    backup_before_rules

    local tmp
    tmp=$(mktemp)
    grep -vF "m comment --comment ${KASKAD_MARKER}" "$BEFORE_RULES" > "$tmp" || true
    mv "$tmp" "$BEFORE_RULES"

    if ! ufw reload >/dev/null 2>&1; then
        rollback_from_backup
        die "ufw reload завершился с ошибкой — откат выполнен"
    fi

    log_info "Все правила kaskad удалены"
}

# ---------- menu ----------
show_menu() {
    cat <<'MENU'

╔═══════════════════════════════════════════╗
║          Kaskad UFW helper                ║
║      DNAT port forwarding via UFW         ║
╚═══════════════════════════════════════════╝

  1) Подготовить систему (ufw, sysctl, ip_forward)
  2) Добавить правило проброса
  3) Показать правила kaskad
  4) Удалить правило
  5) Сбросить ВСЕ правила kaskad
  0) Выход
MENU
    echo
    local choice
    read -r -p "Выбор: " choice || exit 0
    case "$choice" in
        1) prepare_system ;;
        2) add_rule ;;
        3) list_rules ;;
        4) delete_rule ;;
        5) reset_rules ;;
        0|q|Q) exit 0 ;;
        *) log_error "Неверный выбор: '$choice'" ;;
    esac
}

# ---------- dispatch ----------
main() {
    local cmd=${1:-}
    case "$cmd" in
        prepare)        prepare_system ;;
        add)            add_rule ;;
        list)           list_rules ;;
        delete)         delete_rule ;;
        reset)          reset_rules ;;
        ""|menu)        show_menu ;;
        -h|--help|help)
            cat <<HELP
Kaskad UFW helper — управление DNAT-пробросом портов через UFW

Использование:
  $(basename "$0")           интерактивное меню
  $(basename "$0") prepare   установить ufw, настроить sysctl, подготовить before.rules
  $(basename "$0") add       добавить правило проброса
  $(basename "$0") list      показать правила kaskad
  $(basename "$0") delete    удалить правило
  $(basename "$0") reset     удалить ВСЕ правила kaskad
  $(basename "$0") help      эта справка

Все правила, добавленные скриптом, помечаются `-m comment --comment kaskad`
в $BEFORE_RULES. Удаление (delete/reset) затрагивает ТОЛЬКО строки
с этим маркером — правила, добавленные вручную, не модифицируются.

Бэкапы: $BACKUP_DIR (последние 20)
HELP
            ;;
        *)
            log_error "Неизвестная команда: $cmd"
            log_info "Доступно: prepare | add | list | delete | reset | help"
            exit 2
            ;;
    esac
}

main "$@"
