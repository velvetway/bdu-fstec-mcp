# bdu-fstec-mcp

MCP-сервер, дающий Claude (и любому другому MCP-клиенту) доступ к БДУ ФСТЭК — российской базе уязвимостей. Работает без геоблокировки: снимок данных хранится в [публичном зеркале](https://github.com/velvetway/bdu-fstec-mirror) и загружается через `raw.githubusercontent.com`.

## Что умеет

Пять инструментов поверх ~86 000 записей БДУ:

- `search_bdu_vulnerabilities(query, limit=10)` — полнотекстовый поиск по имени, описанию и уязвимому ПО.
- `get_bdu_vulnerability(bdu_id)` — полная запись по идентификатору `BDU:YYYY-NNNNN` (CVSS, решение, CWE, источники, эксплойт-статус).
- `find_bdu_by_cve(cve_id)` — обратный маппинг `CVE → БДУ`.
- `list_bdu_by_vendor(vendor, limit=10)` — уязвимости по вендору (Astra Linux, Kaspersky, Positive Technologies, Microsoft, …).
- `get_bdu_stats()` — статистика снимка.

## Зачем

- `bdu.fstec.ru` геоблокирует не-RU IP. Claude Cloud, GitHub Actions, AWS — никто туда не зайдёт.
- В российской ИБ-compliance БДУ — ключевой идентификатор (`BDU:`), а не `CVE:`. Без него не собрать модель угроз по ГОСТ Р 57580 / 152-ФЗ / 187-ФЗ.
- В awesome-mcp-servers до сих пор нет MCP для БДУ.

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

## Запуск

В `~/.claude/settings.json` для Claude Code:

```json
{
  "mcpServers": {
    "bdu-fstec": { "command": "bdu-fstec-mcp" }
  }
}
```

При первом вызове сервер скачает снимок (~28 МБ gzip) в `~/.cache/bdu-fstec-mcp/` и построит in-memory индексы. Последующие старты — мгновенно.

## Пример диалога

> **Я:** Есть у нас что-нибудь в БДУ по Astra Linux?
>
> **Claude** *(вызывает `list_bdu_by_vendor("Астра", limit=5)`)*:
>
> Найдено 5 уязвимостей у вендора «Астра»:
> - **BDU:2024-03456** — Уязвимость ядра Astra Linux Special Edition 1.7, CVSS 8.1, решение — патч 1.7.4.
> - **BDU:2024-02987** — Локальное повышение привилегий в `astra-systemd`, CVSS 7.8…
> - …

> **Я:** А на CVE-2024-1234 что у ФСТЭК?
>
> **Claude** *(вызывает `find_bdu_by_cve("CVE-2024-1234")`)*:
>
> Найдено 2 записей БДУ для CVE-2024-1234: BDU:2024-02345, BDU:2024-02346.

## Источник данных

Снимок данных обновляется в зеркале [velvetway/bdu-fstec-mirror](https://github.com/velvetway/bdu-fstec-mirror). Текущая версия: 86 664 записи, BDU:2014-00001 → BDU:2026-05547, последнее обновление источника 31.12.2025.

Для обновления локального кэша — удалите `~/.cache/bdu-fstec-mcp/vulxml.xml.gz`, MCP перекачает свежий снимок.

## Разработка

```bash
pip install -e '.[dev]'
pytest
```

## Правовая сторона

- Данные БДУ — публичные, размещены ФСТЭК России на `https://bdu.fstec.ru`.
- Проект не аффилирован с ФСТЭК России.
- Код под MIT. Данные остаются собственностью ФСТЭК России.
- При ссылке на результаты указывайте источник.

## Связанные проекты

- [velvetway/minreestr-mcp](https://github.com/velvetway/minreestr-mcp) — MCP для поиска российского ПО в реестре Минцифры / каталогпо.рф.
- [velvetway/bdu-fstec-mirror](https://github.com/velvetway/bdu-fstec-mirror) — зеркало БДУ (источник данных для этого MCP).
