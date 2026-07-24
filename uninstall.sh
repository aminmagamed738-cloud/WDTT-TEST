#!/bin/sh
# =============================================================================
#  WDTT Panel — Удаление
#  Запуск: sh <(curl -sSL https://raw.githubusercontent.com/aminmagamed738-cloud/WDTT-TEST/main/uninstall.sh)
# =============================================================================
set -e

SERVICE_NAME="wdtt-panel"
INSTALL_DIR="/opt/wdtt-panel"
LOG_FILE="/var/log/wdtt-panel-install.log"
WG_CONF_DIR="/etc/wireguard"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'
ok()   { printf "${GREEN}[✓]${NC} %s\n" "$*"; }
step() { printf "${YELLOW}[►]${NC} ${BOLD}%s${NC}\n" "$*"; }

check_root() {
    [ "$(id -u)" -eq 0 ] || { printf "${RED}[✗] Запустите от root${NC}\n"; exit 1; }
}

confirm() {
    printf "${YELLOW}[?]${NC} Удалить WDTT Panel полностью? [y/N]: "
    read -r ANSWER
    case "$ANSWER" in
        [yYдД]*) ;;
        *) printf "Отменено.\n"; exit 0 ;;
    esac
}

main() {
    check_root
    confirm

    printf "\n${YELLOW}Удаление WDTT Panel...${NC}\n\n"

    # 1. Стоп и удаление сервиса
    step "Остановка сервиса..."
    systemctl stop  "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true
    ok "Сервис удалён"

    # 2. Стоп только профильных интерфейсов панели. Конфиги помечаются
    # установщиком, поэтому чужие wdtt-* или WireGuard-файлы не затрагиваются.
    step "Отключение интерфейсов WDTT Panel..."
    OWNED_WG=""
    if [ -d "$WG_CONF_DIR" ]; then
        for conf in "$WG_CONF_DIR"/wdtt-*.conf; do
            [ -f "$conf" ] || continue
            if grep -q '^# Managed by wdtt-panel;' "$conf"; then
                iface=$(basename "$conf" .conf)
                OWNED_WG="$OWNED_WG $iface"
            fi
        done
    fi
    for iface in $OWNED_WG; do
        if ip link show "$iface" >/dev/null 2>&1; then
            wg-quick down "$iface" 2>/dev/null || true
        fi
        rm -f "$WG_CONF_DIR/$iface.conf"
    done
    [ -n "$OWNED_WG" ] && ok "Сняты только интерфейсы панели:$OWNED_WG" || ok "Интерфейсы панели не найдены"

    # 3. Удаляем только созданное нами правило firewall.
    if [ -f "$INSTALL_DIR/data/firewall_created" ]; then
        FIREWALL_BACKEND=$(sed -n '1p' "$INSTALL_DIR/data/firewall_created")
        FIREWALL_PORT=$(sed -n '2p' "$INSTALL_DIR/data/firewall_created")
        case "$FIREWALL_BACKEND" in
            ufw) ufw delete allow "$FIREWALL_PORT/tcp" 2>/dev/null || true ;;
            firewalld)
                firewall-cmd --permanent --remove-port="$FIREWALL_PORT/tcp" 2>/dev/null || true
                firewall-cmd --reload 2>/dev/null || true ;;
            iptables) iptables -D INPUT -p tcp --dport "$FIREWALL_PORT" -j ACCEPT 2>/dev/null || true ;;
        esac
        ok "Удалено только созданное панелью правило firewall"
    fi

    # Восстанавливаем прежнее значение forwarding, не удаляя чужие строки
    # конфигурации sysctl.
    if [ -s "$INSTALL_DIR/data/sysctl_previous_ipv4_forward" ]; then
        PREV_FORWARD=$(cat "$INSTALL_DIR/data/sysctl_previous_ipv4_forward")
        sysctl -w net.ipv4.ip_forward="$PREV_FORWARD" >/dev/null 2>&1 || true
    fi
    if [ -f /etc/sysctl.conf ]; then
        sed -i '/^# WDTT_PANEL_MANAGED net.ipv4.ip_forward$/,+1d' /etc/sysctl.conf
    fi

    # 4. Удаление файлов
    step "Удаление файлов..."
    rm -rf "$INSTALL_DIR"
    # Это отдельный runtime, который установщик создаёт только для WDTT.
    # Системный Go и пакеты ОС не удаляются.
    rm -rf /usr/local/go-wdtt
    rm -f /etc/profile.d/wdtt-go.sh
    ok "Файлы $INSTALL_DIR удалены"

    # 5. Удаляем только собственный файл журнала установки. Системные
    # журналы и журналы других сервисов не очищаются.
    step "Удаление журнала установки..."
    rm -f "$LOG_FILE"
    ok "Журнал установки удалён"

    printf "\n${GREEN}╔═══════════════════════════════════════╗${NC}\n"
    printf "${GREEN}║   WDTT Panel полностью удалена.       ║${NC}\n"
    printf "${GREEN}║   Зависимости (Go, Python, WG) не     ║${NC}\n"
    printf "${GREEN}║   удалены — они могли использоваться  ║${NC}\n"
    printf "${GREEN}║   другими программами.                ║${NC}\n"
    printf "${GREEN}╚═══════════════════════════════════════╝${NC}\n\n"
}

main "$@"
