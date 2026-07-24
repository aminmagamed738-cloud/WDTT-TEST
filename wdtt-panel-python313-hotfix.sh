#!/bin/sh
# WDTT Panel hotfix for Debian 13 / Python 3.13.
# Does not remove profiles, passwords, WireGuard configs, or dependencies.
set -eu

INSTALL_DIR="${WDTT_PANEL_DIR:-/opt/wdtt-panel}"
FILES="$INSTALL_DIR/manager.py $INSTALL_DIR/panel/manager.py"

if [ "$(id -u)" -ne 0 ]; then
    echo "Запустите hotfix от root." >&2
    exit 1
fi

changed=0
for file in $FILES; do
    [ -f "$file" ] || continue
    tmp="${file}.tmp.$$"
    sed \
        -e 's/target=self\._handle, args=(conn,)/target=self._handle_connection, args=(conn,)/' \
        -e 's/^    def _handle(self, client: socket\.socket):$/    def _handle_connection(self, client: socket.socket):/' \
        "$file" > "$tmp"
    if ! cmp -s "$file" "$tmp"; then
        cp -p "$file" "${file}.bak-python313"
        mv "$tmp" "$file"
        changed=1
    else
        rm -f "$tmp"
    fi
done

if [ "$changed" -eq 1 ]; then
    systemctl restart wdtt-panel
    echo "WDTT Panel перезапущена с исправлением Python 3.13."
else
    echo "Исправление уже применено или файлы панели не найдены."
fi

systemctl --no-pager --full status wdtt-panel | sed -n '1,16p'