#!/bin/sh
# =============================================================================
#  WDTT Panel — Установщик
#  Репозиторий: https://github.com/aminmagamed738-cloud/WDTT-TEST
#  Запуск: sh <(curl -sSL https://raw.githubusercontent.com/aminmagamed738-cloud/WDTT-TEST/main/install.sh)
# =============================================================================
set -e

REPO_URL="https://github.com/aminmagamed738-cloud/WDTT-TEST"
RAW_URL="https://raw.githubusercontent.com/aminmagamed738-cloud/WDTT-TEST/main"
SOURCE_ARCHIVE_URL="${REPO_URL}/archive/refs/heads/main.tar.gz"
INSTALL_DIR="/opt/wdtt-panel"
DATA_DIR="$INSTALL_DIR/data"
SERVICE_NAME="wdtt-panel"
LOG_FILE="/var/log/wdtt-panel-install.log"
# Публичный IPv4 этого VPS. Можно переопределить при переносе на другой сервер:
# WDTT_PUBLIC_IPV4=203.0.113.10 sh install.sh
DEFAULT_PUBLIC_IPV4="138.124.103.142"

# ── Цвета ─────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { printf "${GREEN}[✓]${NC} %s\n" "$*" | tee -a "$LOG_FILE"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*" | tee -a "$LOG_FILE"; }
err()  { printf "${RED}[✗]${NC} %s\n" "$*" | tee -a "$LOG_FILE"; }
step() { printf "${CYAN}[►]${NC} ${BOLD}%s${NC}\n" "$*" | tee -a "$LOG_FILE"; }
die()  { err "$*"; exit 1; }

# ── Root ──────────────────────────────────────────────────────────────────────
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "Запустите от root: sudo sh install.sh"
    fi
}

# ── ОС ───────────────────────────────────────────────────────────────────────
detect_os() {
    OS_ID=""; PKG_MGR=""
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
    fi
    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop) PKG_MGR="apt" ;;
        centos|rhel|rocky|almalinux|oracle) PKG_MGR="yum"
            command -v dnf >/dev/null 2>&1 && PKG_MGR="dnf" ;;
        fedora) PKG_MGR="dnf" ;;
        arch|manjaro) PKG_MGR="pacman" ;;
        *) PKG_MGR="apt"; warn "Неизвестная ОС ($OS_ID), пробуем apt" ;;
    esac
    ok "ОС: ${PRETTY_NAME:-$OS_ID} | PM: $PKG_MGR"
}

# ── Свободный порт ────────────────────────────────────────────────────────────
find_free_port() {
    _start="${1:-8080}"
    _port="$_start"
    while true; do
        if ! ss -lntu 2>/dev/null | grep -q ":$_port " && \
           ! netstat -lntu 2>/dev/null | grep -q ":$_port "; then
            echo "$_port"; return
        fi
        _port=$((_port + 1))
        [ "$_port" -gt 65000 ] && die "Нет свободного порта от $_start"
    done
}

valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null
}

# ── Установка пакетов ─────────────────────────────────────────────────────────
pkg_install() {
    case "$PKG_MGR" in
        apt)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >>"$LOG_FILE" 2>&1 ;;
        dnf)  dnf install -y "$@" >>"$LOG_FILE" 2>&1 ;;
        yum)  yum install -y "$@" >>"$LOG_FILE" 2>&1 ;;
        pacman) pacman -S --noconfirm --needed "$@" >>"$LOG_FILE" 2>&1 ;;
    esac
}

install_deps() {
    step "Установка зависимостей..."
    case "$PKG_MGR" in
        apt)
            DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOG_FILE" 2>&1 || true
            pkg_install python3 python3-pip python3-venv git curl wget wireguard wireguard-tools ;;
        dnf|yum)
            pkg_install python3 python3-pip git curl wget wireguard-tools ;;
        pacman)
            pkg_install python python-pip git curl wget wireguard-tools ;;
    esac
    ok "Зависимости установлены"
}

# ── Go ────────────────────────────────────────────────────────────────────────
install_go() {
    if command -v go >/dev/null 2>&1; then
        GO_VER=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
        MAJOR=$(echo "$GO_VER" | cut -d. -f1)
        MINOR=$(echo "$GO_VER" | cut -d. -f2)
        if [ "$MAJOR" -gt 1 ] || { [ "$MAJOR" -eq 1 ] && [ "$MINOR" -ge 26 ]; }; then
            ok "Go уже установлен ($GO_VER)"
            return
        fi
    fi

    step "Установка отдельного Go 1.26 для WDTT..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GO_ARCH="amd64" ;;
        aarch64|arm64) GO_ARCH="arm64" ;;
        armv7*)  GO_ARCH="armv6l" ;;
        *) die "Неподдерживаемая архитектура: $ARCH" ;;
    esac
    GO_TAR="go1.26.0.linux-${GO_ARCH}.tar.gz"
    GO_URL="https://go.dev/dl/$GO_TAR"

    cd /tmp
    if ! curl -fsSL "$GO_URL" -o "$GO_TAR" 2>>"$LOG_FILE"; then
        die "Не удалось скачать Go"
    fi
    GO_ROOT="/usr/local/go-wdtt"
    rm -rf "$GO_ROOT"
    mkdir -p "$GO_ROOT"
    tar -C "$GO_ROOT" --strip-components=1 -xzf "$GO_TAR" >>"$LOG_FILE" 2>&1
    rm -f "$GO_TAR"

    export PATH="$GO_ROOT/bin:$PATH"
    printf 'export PATH="%s/bin:$PATH"\n' "$GO_ROOT" > /etc/profile.d/wdtt-go.sh
    ok "Go $(go version | awk '{print $3}') установлен в $GO_ROOT"
}

# ── Сборка go_client ──────────────────────────────────────────────────────────
build_go_client() {
    step "Сборка go_client из исходников WDTT..."
    if [ -d "/usr/local/go-wdtt/bin" ]; then
        export PATH="/usr/local/go-wdtt/bin:$PATH"
    fi
    export GOPATH="/tmp/go-build-wdtt"
    export GOCACHE="/tmp/go-cache-wdtt"

    BUILD_DIR="/tmp/wdtt-build-$$"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Используем полный архив этого репозитория. Никаких сторонних или старых
    # реализаций клиента: go_client собирается из того же исходника, который
    # поставляется пользователю в полном ZIP.
    if ! curl -fsSL "$SOURCE_ARCHIVE_URL" -o wdtt-panel.tar.gz >>"$LOG_FILE" 2>&1; then
        die "Не удалось скачать полный исходный архив WDTT Panel."
    fi
    mkdir -p wdtt-src
    if ! tar -xzf wdtt-panel.tar.gz --strip-components=1 -C wdtt-src >>"$LOG_FILE" 2>&1; then
        die "Архив исходников повреждён или недоступен."
    fi

    SOURCE_TREE="$BUILD_DIR/wdtt-src"

    # Ищем go_client и в корневом архиве, и в полном архиве с каталогом
    # wdtt-panel-release/ на верхнем уровне.
    GO_CLIENT_DIR=""
    for d in "wdtt-src/go_client" "wdtt-src/wdtt-panel-release/go_client"; do
        [ -d "$d" ] && GO_CLIENT_DIR="$d" && break
    done

    if [ -z "$GO_CLIENT_DIR" ] || [ ! -f "$GO_CLIENT_DIR/main.go" ]; then
        # Ищем рекурсивно
        GO_CLIENT_DIR=$(find "$BUILD_DIR" -name "main.go" -path "*/go_client/*" -exec dirname {} \; 2>/dev/null | head -1)
    fi

    if [ -z "$GO_CLIENT_DIR" ]; then
        die "Папка go_client не найдена в репозитории WDTT. Попробуйте вручную: см. README."
    fi

    ok "go_client найден: $GO_CLIENT_DIR"
    cd "$GO_CLIENT_DIR"

    # Сборка
    if ! go build -o "$INSTALL_DIR/go_client" -ldflags="-s -w" . >>"$LOG_FILE" 2>&1; then
        die "Ошибка сборки go_client. Смотрите лог: $LOG_FILE"
    fi
    chmod +x "$INSTALL_DIR/go_client"
    cd /
    ok "go_client собран: $INSTALL_DIR/go_client"
}

# ── Панель ────────────────────────────────────────────────────────────────────
install_panel() {
    step "Установка WDTT Panel..."

    # Берём панель из того же полного исходника, из которого только что
    # собрали go_client. Это поддерживает обе структуры GitHub-архива.
    mkdir -p "$INSTALL_DIR/panel/templates" "$INSTALL_DIR/panel/static" "$DATA_DIR"

    PANEL_ROOT="$SOURCE_TREE"
    if [ ! -f "$PANEL_ROOT/panel/app.py" ] && [ -f "$SOURCE_TREE/wdtt-panel-release/panel/app.py" ]; then
        PANEL_ROOT="$SOURCE_TREE/wdtt-panel-release"
    fi
    [ -f "$PANEL_ROOT/panel/app.py" ] || die "В полном исходнике не найдена панель."

    for f in "panel/app.py" "panel/manager.py" "panel/requirements.txt"; do
        DEST="$INSTALL_DIR/$f"
        mkdir -p "$(dirname $DEST)"
        cp "$PANEL_ROOT/$f" "$DEST"
    done
    for f in "panel/templates/index.html" "panel/templates/login.html"; do
        DEST="$INSTALL_DIR/$f"
        cp "$PANEL_ROOT/$f" "$DEST"
    done
    if [ -d "$PANEL_ROOT/panel/static" ]; then
        cp -r "$PANEL_ROOT/panel/static/." "$INSTALL_DIR/panel/static/"
    fi

    # Python venv
    python3 -m venv "$INSTALL_DIR/venv" >>"$LOG_FILE" 2>&1
    "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip >>"$LOG_FILE" 2>&1
    "$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/panel/requirements.txt" >>"$LOG_FILE" 2>&1

    # Копируем app.py и manager.py в корень для простого запуска
    cp "$INSTALL_DIR/panel/app.py"     "$INSTALL_DIR/app.py"
    cp "$INSTALL_DIR/panel/manager.py" "$INSTALL_DIR/manager.py"
    mkdir -p "$INSTALL_DIR/templates"
    cp -r "$INSTALL_DIR/panel/templates/"* "$INSTALL_DIR/templates/"
    mkdir -p "$INSTALL_DIR/static"
    cp -r "$INSTALL_DIR/panel/static/." "$INSTALL_DIR/static/" 2>/dev/null || true

    rm -rf "$BUILD_DIR" "$GOPATH" "$GOCACHE"
    ok "Панель установлена"
}

# ── Пароль ────────────────────────────────────────────────────────────────────
generate_credentials() {
    # Повторная установка не должна менять пароль, который уже показан
    # владельцу. Файл доступен только root.
    if [ -s "$DATA_DIR/.initial_password" ]; then
        PANEL_PASSWORD=$(cat "$DATA_DIR/.initial_password")
        export WDTT_DEFAULT_PASSWORD="$PANEL_PASSWORD"
        ok "Сохранён существующий пароль панели"
        return
    fi
    # Генерируем случайный пароль
    if command -v openssl >/dev/null 2>&1; then
        PANEL_PASSWORD=$(openssl rand -base64 12 | tr -d '=/+' | head -c 16)
    else
        PANEL_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16 2>/dev/null || echo "wdtt$(date +%s)")
    fi
    export WDTT_DEFAULT_PASSWORD="$PANEL_PASSWORD"
}

# ── Systemd-сервис ────────────────────────────────────────────────────────────
install_service() {
    step "Установка systemd-сервиса..."
    # Освобождаем порт старой версии перед проверкой. Профили и данные при
    # этом не трогаются; чужая служба на сохранённом порту заставит выбрать
    # новый свободный порт.
    systemctl stop "$SERVICE_NAME" >>"$LOG_FILE" 2>&1 || true
    if valid_port "$(cat "$DATA_DIR/panel_port" 2>/dev/null || true)"; then
        SAVED_PANEL_PORT=$(cat "$DATA_DIR/panel_port")
        if ! ss -lntu 2>/dev/null | grep -q ":$SAVED_PANEL_PORT " && \
           ! netstat -lntu 2>/dev/null | grep -q ":$SAVED_PANEL_PORT "; then
            PANEL_PORT_USED="$SAVED_PANEL_PORT"
        else
            warn "Сохранённый порт $SAVED_PANEL_PORT занят другим сервисом; выбираем новый."
            PANEL_PORT_USED=$(find_free_port 8080)
        fi
    else
        PANEL_PORT_USED=$(find_free_port 8080)
    fi

    # Секрет сессии также сохраняем между повторными установками.
    if [ -s "$DATA_DIR/.secret_key" ]; then
        SECRET_KEY=$(cat "$DATA_DIR/.secret_key")
    else
        SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || tr -dc 'a-f0-9' < /dev/urandom | head -c 64)
        printf '%s\n' "$SECRET_KEY" > "$DATA_DIR/.secret_key"
        chmod 600 "$DATA_DIR/.secret_key"
    fi

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=WDTT Panel — VPS управление трафиком VK-звонков
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment=WDTT_DATA_DIR=$DATA_DIR
Environment=WDTT_PANEL_HOST=0.0.0.0
Environment=WDTT_PANEL_PORT=$PANEL_PORT_USED
Environment=WDTT_SECRET_KEY=$SECRET_KEY
Environment=WDTT_DEFAULT_PASSWORD=$PANEL_PASSWORD
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
KillMode=mixed
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >>"$LOG_FILE" 2>&1
    systemctl enable "$SERVICE_NAME" >>"$LOG_FILE" 2>&1
    systemctl restart "$SERVICE_NAME" >>"$LOG_FILE" 2>&1 || true
    sleep 2

    ok "Сервис $SERVICE_NAME запущен на порту $PANEL_PORT_USED"
    echo "$PANEL_PORT_USED" > "$DATA_DIR/panel_port"
    chmod 600 "$DATA_DIR/panel_port"
}

# ── ip forwarding ─────────────────────────────────────────────────────────────
setup_sysctl() {
    step "Настройка IP forwarding..."
    if [ ! -f "$DATA_DIR/sysctl_previous_ipv4_forward" ]; then
        sysctl -n net.ipv4.ip_forward 2>/dev/null > "$DATA_DIR/sysctl_previous_ipv4_forward" || echo 0 > "$DATA_DIR/sysctl_previous_ipv4_forward"
    fi
    sysctl -w net.ipv4.ip_forward=1 >>"$LOG_FILE" 2>&1 || true
    if ! grep -q "^# WDTT_PANEL_MANAGED net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null; then
        printf '\n# WDTT_PANEL_MANAGED net.ipv4.ip_forward\nnet.ipv4.ip_forward = 1\n' >> /etc/sysctl.conf
    fi
    ok "IP forwarding включён"
}

# ── Firewall ──────────────────────────────────────────────────────────────────
setup_firewall() {
    PANEL_PORT_USED=$(cat "$DATA_DIR/panel_port" 2>/dev/null || echo 8080)
    step "Открываем порт $PANEL_PORT_USED в firewall..."
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        if ufw status 2>/dev/null | grep -Eq "^[[:space:]]*${PANEL_PORT_USED}/tcp[[:space:]]"; then
            echo existing > "$DATA_DIR/firewall_backend"
        else
            ufw allow "$PANEL_PORT_USED/tcp" >>"$LOG_FILE" 2>&1 || true
            printf 'ufw\n%s\n' "$PANEL_PORT_USED" > "$DATA_DIR/firewall_created"
        fi
        ok "ufw: порт $PANEL_PORT_USED открыт"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --permanent --query-port="$PANEL_PORT_USED/tcp" >/dev/null 2>&1; then
            echo existing > "$DATA_DIR/firewall_backend"
        else
            firewall-cmd --permanent --add-port="$PANEL_PORT_USED/tcp" >>"$LOG_FILE" 2>&1 || true
            printf 'firewalld\n%s\n' "$PANEL_PORT_USED" > "$DATA_DIR/firewall_created"
        fi
        firewall-cmd --reload >>"$LOG_FILE" 2>&1 || true
        ok "firewalld: порт $PANEL_PORT_USED открыт"
    elif command -v iptables >/dev/null 2>&1; then
        if iptables -C INPUT -p tcp --dport "$PANEL_PORT_USED" -j ACCEPT 2>/dev/null; then
            echo existing > "$DATA_DIR/firewall_backend"
        else
            iptables -I INPUT -p tcp --dport "$PANEL_PORT_USED" -j ACCEPT >>"$LOG_FILE" 2>&1 || true
            printf 'iptables\n%s\n' "$PANEL_PORT_USED" > "$DATA_DIR/firewall_created"
        fi
        ok "iptables: порт $PANEL_PORT_USED открыт"
    fi
}

# ── Итог ─────────────────────────────────────────────────────────────────────
show_summary() {
    PANEL_PORT_USED=$(cat "$DATA_DIR/panel_port" 2>/dev/null || echo 8080)
    # Никогда не используем IPv6 для адреса панели: этот VPS опубликован по
    # IPv4 138.124.103.142. Переменная нужна только для переноса установщика.
    SERVER_IP="${WDTT_PUBLIC_IPV4:-$DEFAULT_PUBLIC_IPV4}"
    case "$SERVER_IP" in
        *:*|''|*[!0-9.]*)
            SERVER_IP="$DEFAULT_PUBLIC_IPV4"
            ;;
    esac

    printf "\n"
    printf "${GREEN}╔══════════════════════════════════════════════════╗${NC}\n"
    printf "${GREEN}║         WDTT Panel успешно установлена!          ║${NC}\n"
    printf "${GREEN}╚══════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "  ${BOLD}Адрес панели:${NC}    http://${SERVER_IP}:${PANEL_PORT_USED}\n"
    printf "  ${BOLD}Логин:${NC}           admin\n"
    printf "  ${BOLD}Пароль входа:${NC}    ${YELLOW}${PANEL_PASSWORD}${NC}\n"
    printf "\n"
    printf "  ${CYAN}Управление:${NC}\n"
    printf "    systemctl status  %s\n" "$SERVICE_NAME"
    printf "    systemctl restart %s\n" "$SERVICE_NAME"
    printf "    journalctl -u %s -f\n" "$SERVICE_NAME"
    printf "\n"
    printf "  ${CYAN}Удаление:${NC}\n"
    printf "    sh <(curl -sSL ${RAW_URL}/uninstall.sh)\n"
    printf "\n"
    printf "${YELLOW}[!] Сохраните пароль! После перезапуска он не отображается.${NC}\n"
    printf "${YELLOW}[!] Смените пароль через Настройки в панели.${NC}\n"
    printf "\n"

    # Сохраняем пароль в файл (для восстановления)
    echo "$PANEL_PASSWORD" > "$DATA_DIR/.initial_password"
    chmod 600 "$DATA_DIR/.initial_password"
    printf "  Пароль сохранён в: ${DATA_DIR}/.initial_password\n\n"
}

# ── MAIN ─────────────────────────────────────────────────────────────────────
main() {
    mkdir -p "$(dirname $LOG_FILE)"
    echo "=== WDTT Panel Install $(date) ===" >> "$LOG_FILE"

    printf "\n${CYAN}${BOLD}"
    printf "  ██╗    ██╗██████╗ ████████╗████████╗  ██████╗  █████╗ ███╗   ██╗███████╗██╗\n"
    printf "  ██║    ██║██╔══██╗╚══██╔══╝╚══██╔══╝  ██╔══██╗██╔══██╗████╗  ██║██╔════╝██║\n"
    printf "  ██║ █╗ ██║██║  ██║   ██║      ██║     ██████╔╝███████║██╔██╗ ██║█████╗  ██║\n"
    printf "  ██║███╗██║██║  ██║   ██║      ██║     ██╔═══╝ ██╔══██║██║╚██╗██║██╔══╝  ██║\n"
    printf "  ╚███╔███╔╝██████╔╝   ██║      ██║     ██║     ██║  ██║██║ ╚████║███████╗███████╗\n"
    printf "   ╚══╝╚══╝ ╚═════╝    ╚═╝      ╚═╝     ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝\n"
    printf "${NC}\n"
    printf "  VPS-панель для управления трафиком VK-звонков\n"
    printf "  Репозиторий: ${REPO_URL}\n\n"

    check_root
    detect_os
    install_deps
    install_go
    mkdir -p "$INSTALL_DIR" "$DATA_DIR"
    build_go_client
    generate_credentials
    install_panel
    setup_sysctl
    install_service
    setup_firewall
    show_summary
}

main "$@"
