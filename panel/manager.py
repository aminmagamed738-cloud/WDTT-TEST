"""
WDTT Panel — Connection Manager
Управляет go_client процессами, WireGuard конфигами и SOCKS5-прокси
"""

import os
import re
import json
import socket
import struct
import select
import subprocess
import threading
import time
import logging
import fcntl
import ipaddress
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field, asdict

log = logging.getLogger("wdtt.manager")

GO_CLIENT_BIN = os.environ.get("WDTT_GO_CLIENT", "/opt/wdtt-panel/go_client")
WG_CONF_DIR   = os.environ.get("WDTT_WG_CONF_DIR", "/etc/wireguard")
WG_IFACE_PREFIX = "wdtt-"

# ────────────────────────────────────────────────────────────────────────────
# Вспомогательные функции
# ────────────────────────────────────────────────────────────────────────────

def find_free_port(start: int = 9000, proto: str = "udp") -> int:
    """Ищет свободный порт начиная с start."""
    for p in range(start, start + 500):
        try:
            kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
            s = socket.socket(socket.AF_INET, kind)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except OSError:
            continue
    raise RuntimeError(f"Нет свободного порта от {start} до {start+500}")


def port_is_free(port: int, proto: str) -> bool:
    """Проверяет loopback-порт перед повторным использованием профиля."""
    if not 1 <= int(port) <= 65535:
        return False
    kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
    try:
        with socket.socket(socket.AF_INET, kind) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", int(port)))
        return True
    except OSError:
        return False


def normalize_socks_host(value: str) -> str:
    """SOCKS5 панели должен быть доступен только локальным сервисам VPS."""
    value = (value or "127.0.0.1").strip()
    if value not in ("127.0.0.1", "::1"):
        raise ValueError("SOCKS5 разрешён только на 127.0.0.1 или ::1")
    return value


def _run(cmd: List[str], check=False) -> Tuple[int, str, str]:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if check and r.returncode != 0:
        raise RuntimeError(f"Команда {cmd} вернула {r.returncode}: {r.stderr}")
    return r.returncode, r.stdout, r.stderr


def iface_exists(name: str) -> bool:
    rc, _, _ = _run(["ip", "link", "show", name])
    return rc == 0


def iface_ip(name: str) -> Optional[str]:
    """Возвращает первый IPv4-адрес интерфейса."""
    try:
        rc, out, _ = _run(["ip", "-4", "addr", "show", name])
        if rc != 0:
            return None
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out)
        return m.group(1) if m else None
    except Exception:
        return None


def normalize_vk_hash(raw: str) -> str:
    """Нормализует VK-ссылку или хеш к чистому хешу."""
    raw = raw.strip().strip("<>\"'")
    low = raw.lower()
    # Извлекаем из URL
    idx = low.find("/call/join/")
    if idx >= 0:
        raw = raw[idx + len("/call/join/"):]
    elif low.startswith("http://") or low.startswith("https://"):
        return ""
    # Отрезаем query/fragment
    for ch in "?#/":
        i = raw.find(ch)
        if i != -1:
            raw = raw[:i]
    return raw.strip("/").strip()


# ────────────────────────────────────────────────────────────────────────────
# SOCKS5 прокси-сервер (минимальный, без внешних зависимостей)
# ────────────────────────────────────────────────────────────────────────────

SOCKS5_VERSION = 5
SO_BINDTODEVICE = 25  # Linux


class Socks5Server(threading.Thread):
    """Миниатюрный SOCKS5 TCP-прокси. Подключается напрямую через VPS (без WireGuard-привязки)."""

    def __init__(self, listen_host: str, listen_port: int, bind_iface: str = "", route_mark: int = 0):
        super().__init__(daemon=True, name="socks5-server")
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.bind_iface = bind_iface    # оставлено для совместимости, не используется
        self.route_mark = route_mark    # оставлено для совместимости, не используется
        self._running = False
        self._srv: Optional[socket.socket] = None
        self.ready = threading.Event()
        self.start_error = ""
        # ── Счётчики трафика ─────────────────────────────────────────────
        self._stats_lock = threading.Lock()
        self.bytes_in: int = 0          # байты от клиента к серверу
        self.bytes_out: int = 0         # байты от сервера к клиенту
        self.active_connections: int = 0
        self.total_connections: int = 0

    def get_stats(self) -> dict:
        with self._stats_lock:
            return {
                "bytes_in":          self.bytes_in,
                "bytes_out":         self.bytes_out,
                "active_connections": self.active_connections,
                "total_connections":  self.total_connections,
            }

    def stop(self):
        self._running = False
        if self._srv:
            try:
                self._srv.close()
            except Exception:
                pass

    def run(self):
        self._running = True
        try:
            self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._srv.bind((self.listen_host, self.listen_port))
            self._srv.listen(128)
            self._srv.settimeout(1.0)
            self.ready.set()
            log.info("SOCKS5 слушает %s:%d (iface=%s)", self.listen_host, self.listen_port, self.bind_iface)
            while self._running:
                try:
                    conn, addr = self._srv.accept()
                    t = threading.Thread(
                        target=self._handle_connection, args=(conn,), daemon=True
                    )
                    t.start()
                except socket.timeout:
                    continue
        except Exception as e:
            self.start_error = str(e)
            self.ready.set()
            log.error("SOCKS5 сервер упал: %s", e)

    def _make_outbound(self) -> socket.socket:
        """Создаёт исходящий сокет через стандартный маршрут VPS (без WireGuard-привязки).
        Трафик идёт напрямую — так SOCKS5 работает корректно с 3x-ui и любым TCP-клиентом."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s

    def _relay(self, client: socket.socket, remote: socket.socket):
        """Двунаправленный релей с подсчётом байт."""
        client.settimeout(300)
        remote.settimeout(300)
        fds = [client, remote]
        try:
            while True:
                r, _, x = select.select(fds, [], fds, 60)
                if x:
                    break
                if not r:
                    break
                for src in r:
                    dst = remote if src is client else client
                    try:
                        data = src.recv(65536)
                    except Exception:
                        return
                    if not data:
                        return
                    try:
                        dst.sendall(data)
                    except Exception:
                        return
                    # Считаем: client→remote = bytes_in, remote→client = bytes_out
                    with self._stats_lock:
                        if src is client:
                            self.bytes_in += len(data)
                        else:
                            self.bytes_out += len(data)
        finally:
            for s in (client, remote):
                try:
                    s.close()
                except Exception:
                    pass

    def _handle_connection(self, client: socket.socket):
        with self._stats_lock:
            self.active_connections += 1
            self.total_connections += 1
        try:
            # SOCKS5 handshake
            client.settimeout(10)
            header = client.recv(2)
            if len(header) < 2 or header[0] != SOCKS5_VERSION:
                return
            nmethods = header[1]
            if nmethods:
                client.recv(nmethods)
            # No auth required
            client.sendall(b"\x05\x00")

            # Request
            req = client.recv(4)
            if len(req) < 4 or req[1] != 1:  # только CONNECT
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 10)
                return

            atyp = req[3]
            if atyp == 1:  # IPv4
                addr_data = client.recv(4)
                host = socket.inet_ntoa(addr_data)
            elif atyp == 3:  # domain
                ln = client.recv(1)[0]
                host = client.recv(ln).decode(errors="replace")
            elif atyp == 4:  # IPv6
                addr_data = client.recv(16)
                host = socket.inet_ntop(socket.AF_INET6, addr_data)
            else:
                client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 10)
                return

            port_data = client.recv(2)
            port = struct.unpack("!H", port_data)[0]

            # Прямое соединение через VPS (без WireGuard-привязки)
            remote = self._make_outbound()
            try:
                remote.settimeout(15)
                remote.connect((host, port))
            except Exception as e:
                log.warning("SOCKS5 connect %s:%d ОШИБКА: %s", host, port, e)
                client.sendall(b"\x05\x04\x00\x01" + b"\x00" * 10)
                try:
                    remote.close()
                except Exception:
                    pass
                return

            log.debug("SOCKS5 → %s:%d OK", host, port)
            local_ip = socket.inet_aton("0.0.0.0")
            client.sendall(b"\x05\x00\x00\x01" + local_ip + b"\x00\x00")
            client.settimeout(None)

            self._relay(client, remote)

        except Exception as e:
            log.debug("SOCKS5 handler: %s", e)
        finally:
            with self._stats_lock:
                self.active_connections -= 1
            try:
                client.close()
            except Exception:
                pass


# ────────────────────────────────────────────────────────────────────────────
# Модель профиля подключения
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class Profile:
    id: str
    name: str
    server: str          # IP:PORT WDTT сервера
    password: str        # пароль подключения
    hashes: List[str] = field(default_factory=list)
    workers: int = 24
    listen_port: int = 0    # UDP-порт для go_client (0 = автовыбор)
    socks_port: int = 0     # TCP-порт SOCKS5 (0 = автовыбор)
    socks_host: str = "127.0.0.1"
    fingerprint: str = "firefox"
    wg_iface: str = ""
    route_mark: int = 0
    route_table: int = 0
    enabled: bool = True
    # Runtime (не сохраняются)
    status: str = "stopped"      # stopped / connecting / connected / error
    wg_ip: str = ""
    last_error: str = ""
    connected_at: float = 0.0

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items()
                if k not in ("status", "wg_ip", "last_error", "connected_at")}


# ────────────────────────────────────────────────────────────────────────────
# Менеджер подключений
# ────────────────────────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self, data_dir: Optional[str] = None):
        data_dir = data_dir or os.environ.get(
            "WDTT_DATA_DIR", "/opt/wdtt-panel/data"
        )
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self._profiles: Dict[str, Profile] = {}
        self._processes: Dict[str, subprocess.Popen] = {}
        self._socks5_servers: Dict[str, Socks5Server] = {}
        self._log_lines: Dict[str, List[str]] = {}
        self._reserved_ports = set()
        self._lock = threading.Lock()
        self._load()

    # ── Persistence ─────────────────────────────────────────────────────────

    def _profiles_file(self):
        return os.path.join(self.data_dir, "profiles.json")

    def _load(self):
        path = self._profiles_file()
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                data = json.load(f)
            for d in data:
                p = Profile(**{k: v for k, v in d.items() if k in Profile.__dataclass_fields__})
                self._profiles[p.id] = p
                self._log_lines[p.id] = []
        except Exception as e:
            log.error("Ошибка загрузки профилей: %s", e)

    def _save(self):
        path = self._profiles_file()
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump([p.to_dict() for p in self._profiles.values()], f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    # ── CRUD профилей ────────────────────────────────────────────────────────

    def list_profiles(self) -> List[dict]:
        with self._lock:
            result = []
            for p in self._profiles.values():
                d = p.to_dict()
                d["status"] = p.status
                d["wg_ip"] = p.wg_ip
                d["last_error"] = p.last_error
                d["connected_at"] = p.connected_at
                srv = self._socks5_servers.get(p.id)
                d["socks_stats"] = srv.get_stats() if srv else {
                    "bytes_in": 0, "bytes_out": 0,
                    "active_connections": 0, "total_connections": 0,
                }
                result.append(d)
            return result

    def add_profile(self, data: dict) -> Profile:
        import uuid
        pid = str(uuid.uuid4())[:8]
        raw_hashes = data.get("hashes", [])
        if isinstance(raw_hashes, str):
            raw_hashes = [h.strip() for h in re.split(r"[\n,;]+", raw_hashes) if h.strip()]
        hashes = [h for h in (normalize_vk_hash(h) for h in raw_hashes) if h]
        try:
            socks_host = normalize_socks_host(data.get("socks_host", "127.0.0.1"))
        except ValueError:
            socks_host = "127.0.0.1"
        p = Profile(
            id=pid,
            name=data.get("name", f"Профиль {pid}"),
            server=data.get("server", ""),
            password=data.get("password", ""),
            hashes=hashes,
            workers=int(data.get("workers", 24)),
            listen_port=int(data.get("listen_port", 0)),
            socks_port=int(data.get("socks_port", 0)),
            socks_host=socks_host,
            fingerprint=data.get("fingerprint", "firefox"),
            enabled=bool(data.get("enabled", True)),
        )
        with self._lock:
            self._profiles[pid] = p
            self._log_lines[pid] = []
            self._save()
        return p

    def update_profile(self, pid: str, data: dict) -> Optional[Profile]:
        with self._lock:
            p = self._profiles.get(pid)
            if not p:
                return None
            if "name" in data:
                p.name = data["name"]
            if "server" in data:
                p.server = data["server"]
            if "password" in data:
                p.password = data["password"]
            if "hashes" in data:
                raw = data["hashes"]
                if isinstance(raw, str):
                    raw = [h.strip() for h in re.split(r"[\n,;]+", raw) if h.strip()]
                p.hashes = [h for h in (normalize_vk_hash(h) for h in raw) if h]
            if "workers" in data:
                p.workers = int(data["workers"])
            if "listen_port" in data:
                p.listen_port = int(data["listen_port"])
            if "socks_port" in data:
                p.socks_port = int(data["socks_port"])
            if "socks_host" in data:
                p.socks_host = normalize_socks_host(data["socks_host"])
            if "fingerprint" in data:
                p.fingerprint = data["fingerprint"]
            if "enabled" in data:
                p.enabled = bool(data["enabled"])
            self._save()
            return p

    def delete_profile(self, pid: str) -> bool:
        # Capture the wg_iface before stopping (stop() clears runtime state).
        with self._lock:
            p = self._profiles.get(pid)
            wg_iface = p.wg_iface if p else ""
        self.stop(pid)
        with self._lock:
            if pid in self._profiles:
                del self._profiles[pid]
                self._log_lines.pop(pid, None)
                self._save()
        # BUG FIX: wg-quick down leaves the .conf file in /etc/wireguard/.
        # Remove it so stale configs don't accumulate on disk.
        if wg_iface and re.fullmatch(r"wdtt-[a-z0-9-]{1,10}", wg_iface):
            conf_path = os.path.join(WG_CONF_DIR, f"{wg_iface}.conf")
            try:
                if os.path.exists(conf_path):
                    os.remove(conf_path)
                    log.info("Удалён конфиг профиля: %s", conf_path)
            except Exception as e:
                log.warning("Не удалось удалить конфиг %s: %s", conf_path, e)
        with self._lock:
            return pid not in self._profiles

    def get_logs(self, pid: str, last_n: int = 200) -> List[str]:
        with self._lock:
            lines = self._log_lines.get(pid, [])
            return lines[-last_n:]

    def _append_log(self, pid: str, line: str):
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {line}"
        with self._lock:
            buf = self._log_lines.setdefault(pid, [])
            buf.append(entry)
            if len(buf) > 2000:
                del buf[:500]

    # ── Управление процессами ────────────────────────────────────────────────

    def start(self, pid: str) -> bool:
        with self._lock:
            p = self._profiles.get(pid)
            if not p:
                return False
            if pid in self._processes:
                return True  # уже запущен
            if not p.hashes:
                p.status = "error"
                p.last_error = "Нет VK-хешей"
                return False
            if not p.server:
                p.status = "error"
                p.last_error = "Не указан WDTT-сервер"
                return False
            if not p.password:
                p.status = "error"
                p.last_error = "Не указан пароль подключения"
                return False
            if not os.path.exists(GO_CLIENT_BIN):
                p.status = "error"
                p.last_error = f"go_client не найден: {GO_CLIENT_BIN}"
                return False

            def reserve_port(preferred: int, start: int, proto: str) -> int:
                if (
                    preferred
                    and preferred not in self._reserved_ports
                    and port_is_free(preferred, proto)
                ):
                    self._reserved_ports.add(preferred)
                    return preferred
                candidate = start
                while candidate in self._reserved_ports or not port_is_free(candidate, proto):
                    candidate += 1
                    if candidate > start + 500:
                        raise RuntimeError(f"Нет свободного порта от {start}")
                self._reserved_ports.add(candidate)
                return candidate

            try:
                listen_port = reserve_port(p.listen_port, 9000, "udp")
                socks_port = reserve_port(p.socks_port, 10808, "tcp")
            except RuntimeError as exc:
                self._reserved_ports.discard(locals().get("listen_port", 0))
                self._reserved_ports.discard(locals().get("socks_port", 0))
                p.status = "error"
                p.last_error = str(exc)
                return False
            if not p.wg_iface:
                p.wg_iface = f"{WG_IFACE_PREFIX}{pid}"[:15]
            if not p.route_table or not p.route_mark:
                # Keep each profile in its own policy-routing namespace.
                # Resolve the rare hash collision instead of reusing a table.
                candidate = 10000 + (int(pid[:6], 16) % 40000)
                used = {
                    other.route_table
                    for other in self._profiles.values()
                    if other.id != pid and other.route_table
                }
                while candidate in used:
                    candidate += 1
                    if candidate > 49999:
                        candidate = 10000
                p.route_table = candidate
                p.route_mark = 0x100000 + candidate
            p.listen_port = listen_port
            p.socks_port  = socks_port
            p.status = "connecting"
            p.wg_ip = ""
            p.last_error = ""
            p.connected_at = 0.0
            self._log_lines[pid] = []
            self._save()

        self._append_log(
            pid,
            f"Запуск: сервер={p.server}, хешей={len(p.hashes)}, "
            f"UDP={listen_port}, SOCKS5={p.socks_host}:{socks_port}, "
            f"интерфейс={p.wg_iface}",
        )

        cmd = [
            GO_CLIENT_BIN,
            "-listen", f"127.0.0.1:{listen_port}",
            "-vk",    ",".join(p.hashes),
            "-peer",  p.server,
            "-n",     str(p.workers),
            "-device-id", f"wdtt-panel-{pid}",
            "-captcha-mode", "auto",
            "-fingerprint",  p.fingerprint,
        ]
        if p.password:
            cmd += ["-password", p.password]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            with self._lock:
                self._reserved_ports.discard(listen_port)
                self._reserved_ports.discard(socks_port)
            with self._lock:
                p = self._profiles.get(pid)
                if p:
                    p.status = "error"
                    p.last_error = str(e)
            self._append_log(pid, f"ОШИБКА запуска: {e}")
            return False

        with self._lock:
            self._processes[pid] = proc

        t = threading.Thread(
            target=self._reader_thread,
            args=(
                pid,
                proc,
                listen_port,
                socks_port,
                p.wg_iface,
                p.socks_host,
                p.route_table,
                p.route_mark,
            ),
            daemon=True,
            name=f"reader-{pid}",
        )
        t.start()
        return True

    def stop(self, pid: str):
        with self._lock:
            proc = self._processes.pop(pid, None)
            srv  = self._socks5_servers.pop(pid, None)
            p    = self._profiles.get(pid)
            if p:
                self._reserved_ports.discard(p.listen_port)
                self._reserved_ports.discard(p.socks_port)
            if p:
                p.status = "stopped"
                p.wg_ip = ""
                p.connected_at = 0.0

        if proc:
            try:
                proc.stdin and proc.stdin.write("STOP\n")
                proc.stdin and proc.stdin.flush()
            except Exception:
                pass
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        if srv:
            srv.stop()

        # Снимаем только профильный WireGuard-интерфейс.
        if p:
            self._wg_down(p.wg_iface)
        self._append_log(pid, "Остановлено.")

    def stop_all(self):
        pids = list(self._processes.keys())
        for pid in pids:
            self.stop(pid)

    # ── Фоновый поток чтения stdout go_client ───────────────────────────────

    def _reader_thread(
        self,
        pid: str,
        proc: subprocess.Popen,
        listen_port: int,
        socks_port: int,
        wg_iface: str,
        socks_host: str,
        route_table: int,
        route_mark: int,
    ):
        wg_conf_lines: List[str] = []
        capturing_wg = False
        wg_applied = False
        effective_listen_port = listen_port

        try:
            for raw_line in proc.stdout:
                line = raw_line.rstrip()
                if not line:
                    continue

                self._append_log(pid, line)

                if line.startswith("WDTT_LOCAL_UDP_PORT="):
                    try:
                        effective_listen_port = int(line.split("=", 1)[1].strip())
                        with self._lock:
                            p = self._profiles.get(pid)
                            if p:
                                p.listen_port = effective_listen_port
                                self._save()
                        self._append_log(
                            pid,
                            f"Фактический UDP-порт go_client: {effective_listen_port}",
                        )
                    except (TypeError, ValueError):
                        self._append_log(pid, f"Некорректный порт go_client: {line}")
                    continue

                # Детектируем блок WireGuard-конфига
                if "WireGuard Конфиг" in line or "WireGuard Config" in line:
                    capturing_wg = True
                    wg_conf_lines = []
                    continue
                if capturing_wg:
                    # Граница блока
                    if "╚" in line or "════" in line:
                        capturing_wg = False
                        if wg_conf_lines and not wg_applied:
                            raw_conf = "\n".join(wg_conf_lines)
                            # Патчим endpoint на go_client (127.0.0.1:listen_port)
                            conf = self._patch_wg_conf(
                                raw_conf,
                                effective_listen_port,
                                wg_iface,
                                route_table,
                                route_mark,
                            )
                            success, client_ip = self._wg_apply(
                                conf,
                                wg_iface,
                            )
                            if success:
                                wg_applied = True
                                with self._lock:
                                    p = self._profiles.get(pid)
                                    if p:
                                        p.status = "connected"
                                        p.wg_ip = client_ip
                                        p.connected_at = time.time()
                                self._append_log(pid, f"✓ WireGuard поднят, IP={client_ip}")
                                # Запускаем SOCKS5 на WG-интерфейсе
                                socks_started = self._start_socks5(
                                    pid,
                                    socks_host,
                                    socks_port,
                                    wg_iface,
                                    route_mark,
                                )
                                if not socks_started:
                                    with self._lock:
                                        p = self._profiles.get(pid)
                                        if p:
                                            p.status = "error"
                                            p.last_error = "Не удалось запустить SOCKS5"
                                    self._wg_down(wg_iface)
                            else:
                                with self._lock:
                                    p = self._profiles.get(pid)
                                    if p:
                                        p.status = "error"
                                        detail = client_ip or "неизвестная ошибка wg-quick"
                                        p.last_error = f"Ошибка применения WireGuard: {detail}"
                                self._append_log(
                                    pid,
                                    f"ОШИБКА WireGuard: {client_ip or 'неизвестная ошибка wg-quick'}",
                                )
                        continue
                    # Убираем рамку из символов ║
                    clean = line.replace("║", "").strip()
                    if clean:
                        wg_conf_lines.append(clean)
                    continue

                # Ошибки
                if "FATAL_AUTH" in line:
                    with self._lock:
                        p = self._profiles.get(pid)
                        if p:
                            p.status = "error"
                            p.last_error = line

        except Exception as e:
            self._append_log(pid, f"[reader] {e}")
        finally:
            proc.wait()
            cleanup_resources = False
            with self._lock:
                current_proc = self._processes.get(pid)
                if current_proc is proc:
                    self._processes.pop(pid, None)
                    cleanup_resources = True
                elif current_proc is None:
                    cleanup_resources = True
                p = self._profiles.get(pid)
                if p:
                    self._reserved_ports.discard(listen_port)
                    self._reserved_ports.discard(p.listen_port)
                    self._reserved_ports.discard(p.socks_port)
                if p and cleanup_resources and p.status not in ("stopped", "error"):
                    p.status = "stopped"
                    p.wg_ip = ""
            if cleanup_resources:
                with self._lock:
                    srv = self._socks5_servers.pop(pid, None)
                if srv:
                    srv.stop()
                self._wg_down(wg_iface)
            self._append_log(pid, "go_client завершён.")

    # ── WireGuard ────────────────────────────────────────────────────────────

    @staticmethod
    def _patch_wg_conf(
        conf: str,
        listen_port: int,
        iface: str,
        route_table: int,
        route_mark: int,
    ) -> str:
        """Патчит endpoint и создаёт изолированную policy-routing таблицу."""
        lines = []
        has_table_off = False
        interface_index = None
        for line in conf.splitlines():
            stripped = line.strip()
            if stripped.startswith("Endpoint"):
                lines.append(f"Endpoint = 127.0.0.1:{listen_port}")
            elif stripped.startswith("Table"):
                lines.append("Table = off")
                has_table_off = True
            elif stripped.startswith("DNS"):
                # Не меняем глобальный DNS VPS.
                continue
            else:
                lines.append(line)
            if stripped == "[Interface]":
                interface_index = len(lines) - 1
        if not has_table_off and interface_index is not None:
            lines.insert(interface_index + 1, "Table = off")
            interface_index += 1
        # wg-quick executes these only for this config, so profiles do not
        # overwrite each other's routes or ip rules.
        if interface_index is not None:
            insert_at = interface_index + 1
            while insert_at < len(lines) and (
                lines[insert_at].strip().startswith("Table =")
                or lines[insert_at].strip().startswith("PostUp =")
                or lines[insert_at].strip().startswith("PostDown =")
            ):
                insert_at += 1
            # BUG FIX: route_table is in the 10000-49999 range.  Linux's main
            # routing table sits at priority 32766 — any ip rule with a higher
            # numeric priority is evaluated *after* main, so the VPS default
            # route wins and WireGuard traffic never flows.  We map route_table
            # into the 1000-30999 band (always < 32766) so our rule is
            # evaluated before main, regardless of the profile's UUID hash.
            route_priority = (route_table % 30000) + 1000
            # Determine the VPS outbound interface dynamically so the MASQUERADE
            # rule works regardless of whether the NIC is eth0, ens3, etc.
            get_wan = "$(ip route show default | head -1 | awk '{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}')"
            route_lines = [
                f"PostUp = ip route add default dev {iface} table {route_table}",
                f"PostUp = ip rule add fwmark {route_mark} table {route_table} priority {route_priority}",
                # Allow forwarded packets from the WireGuard tunnel and apply NAT
                # so the inner-tunnel source IP (e.g. 10.x.x.x) is rewritten to
                # the VPS public IP before packets leave to the internet.
                f"PostUp = iptables -A FORWARD -i {iface} -j ACCEPT",
                f"PostUp = iptables -A FORWARD -o {iface} -m state --state RELATED,ESTABLISHED -j ACCEPT",
                f"PostUp = iptables -t nat -A POSTROUTING -o {get_wan} -j MASQUERADE",
                f"PostDown = iptables -D FORWARD -i {iface} -j ACCEPT 2>/dev/null || true",
                f"PostDown = iptables -D FORWARD -o {iface} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true",
                f"PostDown = iptables -t nat -D POSTROUTING -o {get_wan} -j MASQUERADE 2>/dev/null || true",
                f"PostDown = ip rule del fwmark {route_mark} table {route_table} priority {route_priority} 2>/dev/null || true",
                f"PostDown = ip route del default dev {iface} table {route_table} 2>/dev/null || true",
            ]
            lines[insert_at:insert_at] = route_lines
        return "\n".join(lines) + "\n"

    @staticmethod
    def _wg_apply(conf: str, iface: str) -> Tuple[bool, str]:
        """Записывает WG-конфиг и поднимает интерфейс. Возвращает (ok, client_ip)."""
        os.makedirs(WG_CONF_DIR, exist_ok=True)
        if not re.fullmatch(r"wdtt-[a-z0-9-]{1,10}", iface):
            log.error("Отказ: недопустимое имя WireGuard-интерфейса: %r", iface)
            return False, f"недопустимое имя интерфейса {iface!r}"
        conf_path = os.path.join(WG_CONF_DIR, f"{iface}.conf")
        try:
            # После рестарта панели systemd может убить go_client, но оставить
            # его профильный WG-интерфейс. Убираем только интерфейс с нашим
            # префиксом, иначе wg-quick up завершится ошибкой "already exists".
            if iface_exists(iface):
                log.warning("Удаляю оставшийся интерфейс профиля %s", iface)
                ConnectionManager._wg_down(iface)
                if iface_exists(iface):
                    _run(["ip", "link", "del", iface])
                if iface_exists(iface):
                    return False, f"старый интерфейс {iface} не удалось удалить"

            with open(conf_path, "w") as f:
                f.write("# Managed by wdtt-panel; do not edit.\n")
                f.write(conf)
            os.chmod(conf_path, 0o600)

            rc, out, err = _run(["wg-quick", "up", iface])
            if rc != 0:
                detail = (err.strip() or out.strip() or f"код выхода {rc}")
                log.error("wg-quick up: %s", detail)
                # PostUp мог создать интерфейс до ошибки policy routing.
                ConnectionManager._wg_down(iface)
                return False, detail[-1000:]

            # Даём интерфейсу секунду поднятся
            for _ in range(10):
                ip = iface_ip(iface)
                if ip:
                    return True, ip
                time.sleep(0.5)
            return True, ""
        except Exception as e:
            log.error("_wg_apply: %s", e)
            ConnectionManager._wg_down(iface)
            return False, str(e)

    @staticmethod
    def _wg_down(iface: str):
        if iface and iface_exists(iface):
            _run(["wg-quick", "down", iface])
            # Если wg-quick не смог прочитать старый конфиг или выполнить
            # PostDown, удаляем только профильный интерфейс как fallback.
            if iface_exists(iface) and iface.startswith(WG_IFACE_PREFIX):
                _run(["ip", "link", "del", iface])

    # ── SOCKS5 ───────────────────────────────────────────────────────────────

    def _start_socks5(
        self,
        pid: str,
        socks_host: str,
        socks_port: int,
        bind_iface: str,
        route_mark: int,
    ) -> bool:
        """Запускает SOCKS5 только на указанном адресе и через профильный WG."""
        with self._lock:
            old = self._socks5_servers.pop(pid, None)
        if old:
            old.stop()

        try:
            socks_host = normalize_socks_host(socks_host)
        except ValueError as exc:
            self._append_log(pid, f"ОШИБКА SOCKS5: {exc}")
            return False
        srv = Socks5Server(
            socks_host,
            socks_port,
            bind_iface,
            route_mark,
        )
        srv.start()
        srv.ready.wait(timeout=3)
        if srv.start_error or not srv.ready.is_set():
            self._append_log(
                pid,
                f"ОШИБКА запуска SOCKS5: {srv.start_error or 'bind timeout'}",
            )
            srv.stop()
            return False

        with self._lock:
            self._socks5_servers[pid] = srv

        self._append_log(
            pid,
            f"✓ SOCKS5 запущен {socks_host}:{socks_port} "
            f"(трафик только через {bind_iface})",
        )
        return True


# Глобальный экземпляр
manager = ConnectionManager()
