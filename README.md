# GophKeeper

Клиент-серверный менеджер приватных данных на Go. CLI хранит логины/пароли, текст, файлы и банковские карты с произвольными текстовыми метаданными. Данные шифруются на клиенте; сервер хранит шифротекст в PostgreSQL.

## Быстрый запуск

Нужны Go 1.26.6+ и PostgreSQL (либо Docker для базы).

```sh
cp .env.example .env
# Установите уникальный POSTGRES_PASSWORD в .env.
docker compose up -d
make build
export DATABASE_URL='postgres://gophkeeper:YOUR_PASSWORD@127.0.0.1:54329/gophkeeper?sslmode=disable'
./bin/gophkeeper-server --dev-http --listen 127.0.0.1:8443
```

Это локальный режим разработки: HTTP разрешён только на loopback. Для удалённого сервера обязательны TLS-сертификат и ключ:

```sh
./bin/gophkeeper-server --listen 0.0.0.0:8443 --tls-cert server.pem --tls-key server-key.pem
```

Для удалённой PostgreSQL используйте `sslmode=verify-full` и доверенный CA. Для собственного CA сервера клиент принимает `--ca ca.pem`; проверка сертификата не отключается.

В другом терминале:

```sh
./bin/gophkeeper register --server http://127.0.0.1:8443 --dev-http --login alice
./bin/gophkeeper add --dev-http --input examples/text.json
./bin/gophkeeper list --dev-http
./bin/gophkeeper get --dev-http --id RECORD_ID
./bin/gophkeeper version
```

Задаются **два разных пароля**: пароль входа (12–72 байта) и пароль хранилища (12–1024 байта). Пароль хранилища не передаётся серверу. Его восстановления нет. Ввод скрыт. Для автоматизации доступны `--auth-password-file` и `--vault-password-file`. Примеры содержат только демонстрационные значения.

## Записи

```sh
./bin/gophkeeper add --dev-http --input examples/credentials.json
./bin/gophkeeper add --dev-http --input examples/card.json
./bin/gophkeeper edit --dev-http --id RECORD_ID --input examples/text.json
./bin/gophkeeper add --dev-http --input examples/binary.json --file /path/to/document.bin
./bin/gophkeeper get --dev-http --id FILE_ID --output /path/to/new-document.bin
./bin/gophkeeper delete --dev-http --id RECORD_ID
./bin/gophkeeper sync --dev-http
./bin/gophkeeper logout --dev-http
```

`edit` заменяет запись целиком, включая metadata. `get` выводит секрет по явному запросу. `list` показывает ID, тип, заголовок и metadata. Бинарный экспорт требует нового пути и не перезаписывает файлы.

## Несколько клиентов и конфликты

Для второго клиента используйте другую машину либо отдельный кэш:

```sh
./bin/gophkeeper login --server http://127.0.0.1:8443 --dev-http --login alice --cache /tmp/second-client.json
./bin/gophkeeper list --dev-http --cache /tmp/second-client.json
```

Обычные команды синхронизируют данные. `--offline` позволяет читать кэш и ставить изменения в очередь без сети. Разрешено одно ожидающее изменение на запись: перед следующим редактированием выполните `sync`. Для разных записей изменения накапливаются независимо.

При конфликте локальное изменение сохраняется. Выбор версии явный:

```sh
./bin/gophkeeper status
./bin/gophkeeper resolve --dev-http --id RECORD_ID --keep local
# Или --keep remote, чтобы отбросить локальное изменение.
./bin/gophkeeper sync --dev-http
```

Если серверная запись удалена, `--keep local` сохраняет содержимое под новым ID. Удалённый ID не воскрешается. Синхронизация нескольких записей не является общей транзакцией: успешные операции сохраняются, оставшиеся остаются в очереди.

Кэш по умолчанию: `os.UserConfigDir()/gophkeeper/cache.json`. На Unix файлы создаются с правами 0600, новый каталог — 0700. На Windows защищайте профиль ACL средствами ОС. Ключ и пароль хранилища не сохраняются; токен хранится в кэше. Блокировка `.lock` предотвращает одновременную запись двух процессов. После аварии удаляйте её только убедившись, что клиент не работает.

## Проверки и сборки

```sh
make check       # GoDoc, gofmt, go vet, race, unit coverage >=70%
make release     # Linux, macOS, Windows; amd64 и arm64
GOPHKEEPER_TEST_DATABASE_URL='postgres://USER:PASS@localhost:5432/DISPOSABLE_DB?sslmode=disable' make integration
```

Интеграционные тесты используют реальный PostgreSQL и создают тестовых пользователей — только одноразовая база. GitHub Actions запускает проверки, тесты на трёх ОС и кросс-сборки. Артефакт `binaries` содержит бинарники. Тег `v*` запускает выпуск CLI с версией, датой, commit и SHA256SUMS.

Лимиты: файл до 8 МиБ, зашифрованная запись до 12 МиБ, активные данные аккаунта до 64 МиБ, до 1000 записей с учётом удалённых. OTP, TUI, смена паролей и восстановление ключа не реализованы. Выбран HTTP/JSON; бинарный протокол необязателен по ТЗ.

## Документация

- [Требования и приёмка](docs/requirements.md)
- [Архитектура](docs/architecture.md)
- [Безопасность](docs/security.md)
- [Разработка и инструкции проекта](docs/development.md)
- [OpenAPI](api/openapi.yaml)
- [Происхождение кода](NOTICE.md)
