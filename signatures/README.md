# Базы сигнатур SecCorp

Здесь лежат исходники баз, из которых `sigtool` собирает подписанные обновления.

```
signatures/
├── base/       ← всё содержимое этой папки попадает в пакет обновления
└── samples/    ← безопасные тестовые файлы (в пакет не попадают)
```

## Поддерживаемые форматы

| Формат | Расширения | Что это |
|---|---|---|
| ClamAV, хэши | `.hdb` `.hsb` `.hdu` `.hsu` | MD5 / SHA-1 / SHA-256 файла: `хэш:размер:имя` |
| ClamAV, фрагменты кода | `.ndb` `.ndu` | Шестнадцатеричные шаблоны с `??`, `*`, `{n-m}`, `(a\|b)` |
| ClamAV, исключения | `.fp` `.sfp` `.ign` `.ign2` | Ложные срабатывания и отключённые сигнатуры |
| ClamAV, контейнеры | `.cvd` `.cld` `.cud` | Официальные архивы баз (`main`, `daily`) |
| YARA (подмножество) | `.yar` `.yara` | Правила со строками, hex, regex, `at`, `in`, `of`, `filesize`, `uint16/32` |
| Списки хэшей | `.txt` `.csv` `.sha256` `.md5` | Один хэш в строке или CSV-экспорт MalwareBazaar |

В `base/` для примера лежат `custom-test.yar` и `custom-test.hsb`. Оба срабатывают
на безопасный файл `samples/custom-test.txt`:

```bash
cargo run -p seccom-sigtool -- stats signatures/base
cargo run -p seccom-sigtool -- test --input signatures/base signatures/samples/custom-test.txt
```

## Сборка и публикация обновления

```bash
# Один раз: пара ключей Ed25519. Секретный ключ храните вне репозитория.
cargo run -p seccom-sigtool -- keygen --out ~/seccom-keys

# Каждый выпуск: пакет + update.json, подписанные секретным ключом
cargo run -p seccom-sigtool -- build \
  --input signatures/base \
  --version 2026.10.13.1 \
  --key ~/seccom-keys/update_signing.key \
  --out dist-db/

# Проверка перед загрузкой на сервер
cargo run -p seccom-sigtool -- verify \
  --bundle dist-db/seccom-db-2026.10.13.1.tar.gz \
  --index dist-db/update.json \
  --pubkey ~/seccom-keys/update_signing.pub
```

Загрузите оба файла из `dist-db/` на HTTPS-сервер. Приложения, собранные с
`SECCOM_UPDATE_PUBKEY` (содержимое `update_signing.pub`) и `SECCOM_UPDATE_URL`
(адрес `update.json`), будут проверять и устанавливать обновления сами.
Версия должна расти: старые пакеты приложение не принимает.

## Готовые открытые базы

- **ClamAV**: Microsoft Store-сборка включает FreshClam и загружает официальные базы
  напрямую с зеркала ClamAV после установки; сами базы в пакет SecCorp не включаются.
  Не размещайте и не распространяйте CVD от имени SecCorp без проверки условий их
  использования. Лицензия ClamAV-программы — GPL-2.0; подробности по включённому
  FreshClam и исходникам приведены в `build/windows/THIRD-PARTY-NOTICES.txt`.
- **MalwareBazaar** (abuse.ch): CSV-экспорт хэшей, ссылки на экспорт —
  на странице bazaar.abuse.ch/export. Для API abuse.ch нужен бесплатный Auth-Key.
