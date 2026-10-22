#!/usr/bin/env bash
#
# LAB/run.sh — monte le lab PHP2Shell en config bridge.
#
#   ./run.sh up      build + démarrage (ports 8486/8483 sur toutes les interfaces)
#   ./run.sh status  état du conteneur + URLs + IP LAN
#   ./run.sh down    arrêt et suppression du conteneur
#   ./run.sh clean   down + suppression de l'image
#
# LAB UNIQUEMENT : les portes sont des endpoints RCE non authentifiés.
# Ne les expose que sur des réseaux que vous contrôlez.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="php2shell-lab"
CONTAINER="php2shell-lab"
HTTP_PORT="${HTTP_PORT:-8486}"
HTTPS_PORT="${HTTPS_PORT:-8483}"

# colima (macOS) : socket + config sans keychain si nécessaire
if [ -z "${DOCKER_HOST:-}" ] && [ -S "$HOME/.colima/default/docker.sock" ]; then
    mkdir -p /tmp/dockcfg
    [ -f /tmp/dockcfg/config.json ] || echo '{"auths":{}}' > /tmp/dockcfg/config.json
    export DOCKER_CONFIG=/tmp/dockcfg
    export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
fi

case "${1:-up}" in
    up)
        docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -t "$IMAGE" "$HERE"
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
        docker run -d --name "$CONTAINER" \
            --network bridge \
            -p "$HTTP_PORT:80" -p "$HTTPS_PORT:443" \
            "$IMAGE" >/dev/null
        sleep 2
        V=$(docker exec "$CONTAINER" php -r 'echo PHP_VERSION;' 2>/dev/null || echo '?')
        LAN=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo IP_HOTE)
        echo "[+] conteneur $CONTAINER : PHP $V"
        echo "    local : http://127.0.0.1:$HTTP_PORT   https://127.0.0.1:$HTTPS_PORT (auto-signé)"
        echo "    lan   : http://$LAN:$HTTP_PORT        https://$LAN:$HTTPS_PORT"
        echo "    portes: /remote_app.php (C:)   /enum.php (E:)   /check.php"
        [ "$V" = "8.5.11" ] || echo "[!] PHP $V != 8.5.11 attendu (version vulnérable de référence)"
        ;;
    status)
        docker ps --filter "name=$CONTAINER" --format '{{.Names}}  {{.Status}}  {{.Ports}}'
        docker exec "$CONTAINER" php /var/www/html/check.php 2>/dev/null | sed -n '1,6p' || true
        ;;
    down)
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
        echo "[+] conteneur supprimé"
        ;;
    clean)
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
        docker image rm -f "$IMAGE" >/dev/null 2>&1 || true
        echo "[+] conteneur et image supprimés"
        ;;
    *)
        echo "usage: $0 {up|status|down|clean}" >&2; exit 2 ;;
esac
