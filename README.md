# bdu-fstec-mcp

MCP-сервер, дающий Claude (и любому MCP-клиенту) доступ к БДУ ФСТЭК — российской базе данных угроз безопасности информации. Работает без геоблокировки: снимок хранится в [публичном зеркале](https://github.com/velvetway/bdu-fstec-mirror) как готовая SQLite-база и раздаётся через `raw.githubusercontent.com`.

## Зачем

- `bdu.fstec.ru` геоблокирует всё, что не Россия: Claude Cloud, GitHub Actions `ubuntu-latest`, AWS, GCP — туда не попадут.
- В российской ИБ-compliance (152-ФЗ, 187-ФЗ, ГОСТ Р 57580) ключевой идентификатор уязвимости — `BDU:YYYY-NNNNN`, не `CVE`.
- В awesome-mcp-servers до сих пор нет MCP для БДУ.

## Возможности

Четыре инструмента поверх **86 664 записей** (снимок 18.04.2026, источник обновлён 31.12.2025):

- `search_bdu_vulnerabilities` — поиск с ранжированием по FTS5 и фильтрами:
  - полнотекстовый запрос с корректной токенизацией кириллицы;
  - `min_cvss`, `min_severity` (низкий/средний/высокий/критический);
  - `year` (год обнаружения);
  - `vendor` (подстрока имени вендора);
  - `has_exploit` (только уязвимости с известным эксплойтом).
- `get_bdu_vulnerability` — полная запись по идентификатору БДУ.
- `find_bdu_by_cve` — обратный маппинг CVE → БДУ.
- `get_bdu_stats` — статистика снимка и проверка актуальности.

## Производительность

| Операция | Время (86k записей) |
| --- | --- |
| Холодный старт (скачать 49 МБ SQLite + распаковать) | 5–10 с, один раз |
| Последующие старты | <50 мс |
| `search_bdu_vulnerabilities` c FTS5 | 10–30 мс |
| `find_bdu_by_cve` | 1–5 мс |
| `get_bdu_vulnerability` | <5 мс |

## Установка

```bash
pip install bdu-fstec-mcp
```

Или локально:

```bash
git clone https://github.com/velvetway/bdu-fstec-mcp
cd bdu-fstec-mcp
pip install -e .
```

## Запуск в Claude Code

В `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "bdu-fstec": { "command": "bdu-fstec-mcp" }
  }
}
```

## CLI

```bash
bdu-fstec-mcp            # запустить stdio-сервер (по умолчанию)
bdu-fstec-mcp run        # то же самое
bdu-fstec-mcp stats      # показать статистику локального снимка
bdu-fstec-mcp refresh    # принудительно перекачать свежий снимок
```

## Переменные окружения

| Переменная | По умолчанию | Описание |
| --- | --- | --- |
| `BDU_FSTEC_DB_URL` | адрес в зеркале | URL к `bdu.sqlite.gz`. |
| `BDU_FSTEC_STATS_URL` | адрес в зеркале | URL к `stats.json`. |
| `BDU_FSTEC_CACHE_DIR` | `$XDG_CACHE_HOME/bdu-fstec-mcp` | Каталог локального кэша. |
| `BDU_FSTEC_STALENESS_DAYS` | `30` | После скольких дней предупреждать о старом снимке. |
| `BDU_FSTEC_REQUEST_TIMEOUT` | `120` | Таймаут HTTP-запросов (с). |

## Пример диалога

> **Я:** Что есть у ФСТЭК по CVE-2024-1086?
>
> **Claude** *(вызывает `find_bdu_by_cve("CVE-2024-1086")`)*:
>
> Найдена 1 запись БДУ — **BDU:2024-01187**, use-after-free в `nft_verdict_init()` ядра Linux, CVSS 7.8. Подтверждена производителем, эксплойт существует. Затронуты Astra Linux Special Edition 1.7, РЕД ОС 7.3, Альт 8 СП и ещё 10 дистрибутивов.

> **Я:** Критические уязвимости Astra Linux за 2025 год, где есть эксплойт.
>
> **Claude** *(вызывает `search_bdu_vulnerabilities(query="Astra Linux", min_severity="критический", year=2025, has_exploit=true)`)*:
>
> Найдено 4 результата…

## Архитектура

```
src/bdu_fstec_mcp/
    __init__.py       пакетные константы
    _config.py        конфигурация через env
    _cli.py           CLI-обёртка (run/refresh/stats)
    cache.py          скачивание и staleness-проверка снимка
    store.py          SQLite+FTS5 запросы и DTO-гидратация
    models.py         неизменяемые dataclass-модели
    formatters.py     pretty-print для LLM
    server.py         MCP stdio-сервер и диспетчер тулов
```

Данные живут в отдельном репозитории [bdu-fstec-mirror](https://github.com/velvetway/bdu-fstec-mirror). MCP их только читает.

## Разработка

```bash
pip install -e '.[dev]'
pytest          # 35 тестов, <1 с
```

Покрыты: FTS5-экранирование, фильтры, маппинг CVE→БДУ, скачивание и fallback кэша, staleness-проверки, форматтеры.

## Правовая сторона

- Данные БДУ — публичная информация, размещённая ФСТЭК России на `https://bdu.fstec.ru`.
- Проект не аффилирован с ФСТЭК России.
- Код — MIT. Данные остаются собственностью ФСТЭК России.
- При ссылке на результаты указывайте источник.

## Связанные проекты

- [velvetway/minreestr-mcp](https://github.com/velvetway/minreestr-mcp) — MCP для поиска российского ПО в каталоге Минцифры / каталогпо.рф.
- [velvetway/bdu-fstec-mirror](https://github.com/velvetway/bdu-fstec-mirror) — зеркало БДУ, источник данных для этого MCP.
