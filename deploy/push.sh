#!/usr/bin/env bash
# Деплой unlim-proxy на общий сервер: залить рабочее дерево и пересобрать.
#
# Как на Railway (`railway up` отправлял рабочую директорию), только явно и со
# списком исключений — в LeadGeneration уже случалось, что в прод уехал чужой
# полуфабрикат из грязного дерева.
#
#   ./deploy/push.sh            — залить и пересобрать
#   ./deploy/push.sh --no-build — только залить и перезапустить (правка config.toml)
set -euo pipefail

HOST="${PLATFORM_HOST:-root@62.238.50.62}"
KEY="${PLATFORM_KEY:-$HOME/.ssh/platform_ed25519}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# STACK_NAME и STACK_ROOT — источник истины в deploy/stack.env, чтобы имя стека
# не разъезжалось между compose, push и каталогом на диске.
# shellcheck source=stack.env
set -a; source "$REPO_ROOT/deploy/stack.env"; set +a
: "${STACK_NAME:?нет STACK_NAME в deploy/stack.env}"
: "${STACK_ROOT:?нет STACK_ROOT в deploy/stack.env}"

REMOTE_DIR="$STACK_ROOT/app"
SSH=(ssh -i "$KEY" -o StrictHostKeyChecking=accept-new "$HOST")
DC="docker compose --env-file $STACK_ROOT/deploy/stack.env -p $STACK_NAME"

if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]]; then
  echo "!! рабочее дерево грязное — на сервер уедет незакоммиченное:"
  git -C "$REPO_ROOT" status --short --untracked-files=no
  read -rp "продолжить? [y/N] " a; [[ "$a" == [yY] ]] || exit 1
fi

echo "== заливаю $REPO_ROOT -> $HOST:$REMOTE_DIR"
# data/ исключён жёстко: там 175 МБ proxies.db и ~215 МБ geo-баз сервера. Без
# этой строки rsync --delete затёр бы прод локальной копией. Исключённое
# --delete не трогает, так что каталог на сервере в безопасности вдвойне.
rsync -az --delete \
  -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
  --exclude 'data/' \
  --exclude '.git/' \
  --exclude '.github/' \
  --exclude '.venv/' \
  --exclude 'venv/' \
  --exclude 'node_modules/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '*.egg-info/' \
  --exclude '.pytest_cache/' \
  --exclude '.ruff_cache/' \
  --exclude '.mypy_cache/' \
  --exclude '.turbo/' \
  --exclude '.next/' \
  --exclude 'dist/' \
  --exclude 'build/' \
  --exclude 'coverage/' \
  --exclude 'artifacts/' \
  --exclude 'graphify-out/' \
  --exclude '.playwright-mcp/' \
  --exclude '*.log' \
  --exclude '*.db' \
  --exclude '*.db-wal' \
  --exclude '*.db-shm' \
  --exclude '*.mmdb' \
  --exclude '*.mmdb.gz' \
  --exclude '.env' \
  --exclude '.DS_Store' \
  "$REPO_ROOT/" "$HOST:$REMOTE_DIR/"

# stack.env читает сам compose (--env-file), поэтому он должен лежать по
# абсолютному пути ВНЕ app/ — иначе при первом же --delete он бы уехал вместе с
# деревом. Секретов в нём нет, версия из гита всегда правильная, перезаписываем.
echo "== кладу stack.env в $STACK_ROOT/deploy/"
"${SSH[@]}" "mkdir -p $STACK_ROOT/deploy $STACK_ROOT/data"
rsync -az -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
  "$REPO_ROOT/deploy/stack.env" "$HOST:$STACK_ROOT/deploy/stack.env"

# Без .env контейнер поднимется с пустым API_KEY, то есть с открытым пулом.
"${SSH[@]}" "test -s $STACK_ROOT/.env" || {
  echo "!! нет $STACK_ROOT/.env — см. deploy/.env.server.example (API_KEY обязателен)"
  exit 1
}

if [[ "${1:-}" == "--no-build" ]]; then
  # Ловушка, в которую легко попасть: src/ запечён в образ (Dockerfile COPY), а
  # bind-монтом наружу висит только config.toml. Без сборки rsync честно кладёт
  # новый код на диск сервера, docker compose up -d говорит "Started", healthz
  # отвечает — и работает при этом СТАРЫЙ код из образа. Молча.
  #
  # Поэтому сверяем src/ на диске с src/ в работающем контейнере. Сходятся —
  # правка действительно не в коде, можно перезапускать. Не сходятся — отказ.
  HASH="find src -name '*.py' -exec sha256sum {} + | sort -k2 | sha256sum | cut -c1-16"
  LOCAL=$(cd "$REPO_ROOT" && eval "$HASH")
  RUNNING=$("${SSH[@]}" "cd $REMOTE_DIR/deploy && $DC exec -T unlimproxy sh -c \"cd /app && $HASH\"" 2>/dev/null | tr -d '\r')
  if [[ -n "$RUNNING" && "$LOCAL" != "$RUNNING" ]]; then
    echo "!! --no-build, но src/ отличается от кода в контейнере ($LOCAL != $RUNNING)"
    echo "   код запечён в образ, перезапуск его не подхватит — ./deploy/push.sh без флага"
    exit 1
  fi
  echo "== без сборки, перезапускаю"
  "${SSH[@]}" "cd $REMOTE_DIR/deploy && $DC up -d"
else
  echo "== сборка и перезапуск"
  "${SSH[@]}" "cd $REMOTE_DIR/deploy && $DC build && $DC up -d"
fi

echo "== статус"
"${SSH[@]}" "cd $REMOTE_DIR/deploy && $DC ps"
echo "== здоровье (первые ~90с healthcheck ещё starting, это норма)"
"${SSH[@]}" "cd $REMOTE_DIR/deploy && $DC exec -T unlimproxy python -c \"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=5).read().decode())\"" || true
