#!/usr/bin/env bash
# Снять живой снимок SQLite ВНУТРИ Railway-контейнера, перед переездом.
#
# Зачем отдельный скрипт, а не `cp proxies.db`:
#
#   storage.py:168 включает journal_mode=WAL и synchronous=NORMAL. В этом режиме
#   свежие записи лежат НЕ в proxies.db, а в proxies.db-wal — на момент проверки
#   там было 62,9 МБ, то есть примерно треть базы. Скопировать один .db значит
#   приехать на новый сервер со вчерашним состоянием пула и без части индексов
#   в согласованном виде.
#
#   PRAGMA wal_checkpoint(TRUNCATE) вливает WAL обратно в основной файл и
#   обнуляет его. А поскольку приложение продолжает писать, дальше берём не cp,
#   а backup API SQLite: он держит согласованность, даже если во время копии
#   прошла транзакция. Просто cp живой базы такой гарантии не даёт.
#
# Запуск (на инстансе Railway, из корня проекта /app):
#   railway ssh
#   bash deploy/checkpoint-and-copy.sh
#
# Забрать результат: путь и размер скрипт печатает в конце.
#
#   ВКЛЮЧИТЬ geo:  WITH_GEO=1 bash deploy/checkpoint-and-copy.sh
#   Другой выход:  OUT_DIR=/app/data/_migrate bash deploy/checkpoint-and-copy.sh
set -euo pipefail

DB="${DB:-/app/data/proxies.db}"
# По умолчанию /tmp, а не том: на томе 673 МБ и почти всё занято базой и geo,
# гигабайтный архив рядом с ними просто не поместится.
OUT_DIR="${OUT_DIR:-/tmp/unlimproxy-migrate}"
WITH_GEO="${WITH_GEO:-0}"

[[ -f "$DB" ]] || { echo "!! нет базы: $DB"; exit 1; }

mkdir -p "$OUT_DIR"
SNAP="$OUT_DIR/proxies.db"

echo "== до чекпойнта"
ls -l "$DB" "$DB-wal" "$DB-shm" 2>/dev/null || true

# sqlite3 как CLI в python:3.12-slim не установлен — есть только библиотека
# через модуль python. Поэтому вся работа отсюда.
python3 - "$DB" "$SNAP" <<'PY'
import sqlite3, sys, os

src_path, dst_path = sys.argv[1], sys.argv[2]
for leftover in (dst_path, dst_path + "-wal", dst_path + "-shm"):
    if os.path.exists(leftover):
        os.remove(leftover)

def wal_size():
    return os.path.getsize(src_path + "-wal") if os.path.exists(src_path + "-wal") else 0

src = sqlite3.connect(src_path, timeout=60)
before = wal_size()
# Пишущее соединение: TRUNCATE требует права на запись в WAL.
busy, _, _ = src.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
after = wal_size()
# Вторая и третья колонки ответа при TRUNCATE всегда нули — они описывают WAL
# ПОСЛЕ усечения, а он к этому моменту пуст. Проверено локально: (0,0,0) при
# успешном чекпойнте, который перелил 292 КБ в основной файл. Единственное
# осмысленное доказательство — размер файла до и после.
print(f"   wal_checkpoint: busy={busy}, WAL {before} -> {after} байт")
if busy:
    # busy=1 значит, что чей-то читатель не дал усечь WAL. Данные не потеряны —
    # backup ниже всё равно возьмёт согласованный снимок, — но стоит знать.
    print("   !! WAL усечь не дали (активный читатель); снимок всё равно целостный")

dst = sqlite3.connect(dst_path)
# Онлайн-backup: страницы копируются под блокировкой по кускам, изменения во
# время копии переигрываются. Именно поэтому приложение можно не останавливать.
with dst:
    src.backup(dst, pages=2000, progress=None)
dst.execute("PRAGMA journal_mode=DELETE")   # снимок кладём одним файлом, без WAL

ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
print(f"   integrity_check: {ok}")
if ok != "ok":
    sys.exit("!! снимок битый, переезжать с ним нельзя")

rows_src = src.execute("SELECT count(*) FROM proxies").fetchone()[0]
rows_dst = dst.execute("SELECT count(*) FROM proxies").fetchone()[0]
print(f"   proxies: источник {rows_src}, снимок {rows_dst}")
# Расхождение в несколько строк — норма: база живая и пишет прямо сейчас.
if rows_dst < rows_src * 0.99:
    sys.exit(f"!! снимок потерял {rows_src - rows_dst} строк — это не дрейф, это ошибка")

src.close()
dst.close()
PY

echo "== пакую"
TAR="$OUT_DIR/unlimproxy-data.tar.gz"
TAR_ARGS=(-C "$OUT_DIR" proxies.db)
if [[ "$WITH_GEO" == "1" ]]; then
  # По умолчанию geo НЕ берём: dbip-city-lite + iplocate-asn/country это ~215 МБ,
  # и цикл geo_refresh скачает их на новом сервере сам с публичных URL из
  # config.toml. Тащить их через свой канал незачем — только если хочется, чтобы
  # обогащение стартовало без окна ожидания.
  echo "   + geo (~215 МБ)"
  TAR_ARGS+=(-C /app/data geo)
fi
tar -czf "$TAR" "${TAR_ARGS[@]}"

echo
echo "== готово"
ls -lh "$TAR"
echo
echo "Забрать на ноутбук (одной командой, без промежуточного файла на томе):"
echo "  railway ssh \"cat $TAR\" > unlimproxy-data.tar.gz"
echo
echo "Разложить на новом сервере:"
echo "  scp -i ~/.ssh/platform_ed25519 unlimproxy-data.tar.gz root@62.238.50.62:/tmp/"
echo "  ssh -i ~/.ssh/platform_ed25519 root@62.238.50.62 \\"
echo "    'mkdir -p /opt/stacks/unlimproxy/data && tar -xzf /tmp/unlimproxy-data.tar.gz -C /opt/stacks/unlimproxy/data'"
echo
echo "Проверить ПОСЛЕ распаковки, до старта контейнера:"
echo "  sqlite3 /opt/stacks/unlimproxy/data/proxies.db 'PRAGMA integrity_check; SELECT count(*) FROM proxies;'"
