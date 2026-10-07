# Звіт з лабораторної роботи № 2

##Інформація про роботу

- Студент(ка): Корбут Данило Андрійович
- Група: ІБ (спеціальність 125 «Кібербезпека та захист інформації»)
- Варіант / профіль: спільний baseline 2-A «Трекер інцидентів», профіль A «Пошук»
- Заявлений рівень: Добрий («Добре»)
- Початковий тег / базовий commit: `v0.1.0` / `<BASE_COMMIT_SHA>`
- Версія scaffold (`.scaffolds/lab-02.json`): `lab-02-start-v1`
- Гілка: `lab/2-input-sqli`
- Vulnerable commit: `<VULNERABLE_SHA>`
- Fixed commit: `<FIXED_SHA>`
- Підсумковий тег: `v0.2.0`

## Контракт створення та серверна валідація

### Таблиця контракту `POST /api/incidents` (Baseline 2-A)

| Поле / елемент | Категорія | Правило перевірки / встановлення | Поведінка при порушенні |
| :--- | :--- | :--- | :--- |
| `title` | Приймає від клієнта (`CreateIncidentRequest`) | Обов'язкове (не порожнє після `Trim()`); довжина до `Trim()` $\le 160$ символів; нормалізується через `Trim()` | `400 Bad Request`, `ValidationProblem`, ключ `title` |
| `description` | Приймає від клієнта (`CreateIncidentRequest`) | Обов'язкове (не порожнє після `Trim()`); довжина до `Trim()` $\le 4000$ символів; для `High`/`Critical` довжина після `Trim()` $\ge 40$ символів (`T-09`) | `400 Bad Request`, `ValidationProblem`, ключ `description` |
| `severity` | Приймає від клієнта (`CreateIncidentRequest`) | Обов'язкове; `Enum.TryParse<IncidentSeverity>(..., ignoreCase: true)` + `Enum.IsDefined`: лише `Low`, `Medium`, `High`, `Critical` | `400 Bad Request`, `ValidationProblem`, ключ `severity` (мовчазна підміна на `Low` заборонена) |
| `occurredAtUtc` | Приймає від клієнта (`CreateIncidentRequest`) | Обов'язковий `DateTimeOffset?`; не пізніше `now.AddMinutes(5)`; перед записом конвертується через `.ToUniversalTime()` | `400 Bad Request`, `ValidationProblem`, ключ `occurredAtUtc` |
| Активний дублікат `title` (`T-03`) | Предметний інваріант (Business Rule) | У БД не повинно бути інциденту з тим самим нормалізованим `Title` (з урахуванням регістру) у статусах `New`, `Triaged`, `InProgress`, `Resolved` (`Closed` не блокує) | `409 Conflict`, `Problem Details` |
| `Id`, `OwnerUserId`, `Status`, `CreatedAtUtc`, `UpdatedAtUtc` | Server-managed поля (відсутні у Request DTO) | Встановлюються виключно сервером: `Guid.NewGuid()`, `DbSeeder.AliceId`, `IncidentStatus.New`, `now` (UTC) | Зайві поля у вхідному JSON ігноруються (захист від Overposting) |
| `CreatedIncidentResponse` | Response DTO (`201 Created`) | Повертає лише `Id`, `Title`, `Severity`, `Status`, `OccurredAtUtc`, `CreatedAtUtc` та заголовок `Location` | Внутрішні навігаційні властивості сутності `Incident` клієнту не повертаються |

### Контрольна точка CP-01
- **Чому потрібні обидві перевірки `Enum.TryParse` і `Enum.IsDefined`:** `Enum.TryParse` перетворює будь-який числовий рядок (наприклад, `"7"`) на значення базового типу `(IncidentSeverity)7`, навіть якщо такого елемента в `enum` не існує. `Enum.IsDefined` перевіряє, чи входить розпарсене значення до переліку визначених констант (`Low`, `Medium`, `High`, `Critical`), гарантуючи повернення `400 Bad Request` для `"7"`.
- **Чому `<select>` у браузері не замінює серверну валідацію:** HTML-форма та клієнтський JavaScript виконуються у середовищі користувача і легко обходяться прямим HTTP-запитом (`curl`, Postman, HTTP Client). Єдиною межею довіри є серверний обробник API.
- **Захист від Overposting:** Запит із додатковими полями `"id"`, `"status": "Closed"`, `"ownerUserId"` створює інцидент із новим серверним `Id`, статусом `"New"` та власником `Alice` (`DbSeeder.AliceId`), бо `CreateIncidentRequest` не містить цих властивостей.

## Security-сценарій: SQL injection у пошуку

1. **Контекст і гіпотеза:** Локальний endpoint `GET /api/incidents/search` приймає недовірені query-параметри `q` та `sortBy`. Існує ризик того, що ці значення конкатенуються з текстом SQL-команди до її передачі в PostgreSQL і змінюють логічну структуру запиту.
2. **Стан до (`vulnerable commit`):** Коміт `<VULNERABLE_SHA>`. Файл `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`, метод `MapLab02Endpoints`. Збирання SQL виконувалося конкатенацією рядків:
   `var sql = "SELECT * FROM incidents WHERE title ILIKE '%" + (q ?? "") + "%' OR description ILIKE '%" + (q ?? "") + "%' ORDER BY " + orderClause + " LIMIT 50";` із подальшим викликом `db.Incidents.FromSqlRaw(sql)`.
3. **Мінімальний PoC:** Використано виключно дозволений локальний read-only сценарій C із методичних рекомендацій (`tests/http/lab-02-checks.http`, сценарій `S-01`).
4. **Спостереження (CP-02):**
   - Звичайний пошук `?q=USB` повернув `200 OK` та 1 запис (`...0005`).
   - Пошук відсутнього значення `?q=zz-no-match` повернув `200 OK` та `[]`.
   - Контрольний ввід `S-01` повернув `200 OK` та **всі 5 записів таблиці `incidents`** (`...0004`, `...0005`, `...0003`, `...0002`, `...0001`). У логах EF Core зафіксовано `Parameters=[]`.
   - Пошук легітимного прізвища з апострофом `?q=O%27Brien` та слова `?q=комп'ютерного` завершився помилкою `500 Internal Server Error` (`Npgsql.PostgresException 42601: syntax error at or near "Brien"`).
5. **Першопричина (Root Cause):** Змішування недовірених даних (`q` та `sortBy`) зі структурою SQL-команди через рядкову конкатенацію перед передачею в `FromSqlRaw`. Апостроф у `q` закривав рядковий літерал `ILIKE`, після чого `OR TRUE` ставав частиною предикату `WHERE`, а `-- ` коментував залишок запиту.
6. **Виправлення (CP-03):**
   - У коміті `<FIXED_SHA>` `FromSqlRaw` замінено на LINQ-запит із `EF.Functions.ILike(incident.Title, pattern, "\\") || EF.Functions.ILike(incident.Description, pattern, "\\")`.
   - Додано функцію `EscapeLike`, яка екранує `\`, `%` та `_`, забезпечуючи буквальний пошук підрядка (literal substring). Значення `pattern` передається в PostgreSQL виключно як окремий параметр (`@pattern` / `@pattern0`), тому жоден символ не може змінити синтаксичне дерево SQL.
   - Для `sortBy` реалізовано суворий серверний `allowlist` (`createdAtUtc`, `severity`, `status`) з явним числовим ранжуванням (`CASE WHEN` у SQL) та стабільним другим ключем `.ThenBy(incident => incident.Id)`. Невідоме значення `sortBy` повертає `400 Bad Request` із ключем `sortBy` до звернення до БД.
7. **Retest і позитивна регресія:**
   - На `<FIXED_SHA>` контрольний сценарій `S-02` повертає `200 OK` та порожній масив `[]`. У журналі EF Core фіксується `Parameters=[@pattern='?', @pattern0='?', @p='?']` та `ILIKE @pattern ESCAPE '\'`.
   - Легітимні запити з апострофом (`O'Brien` -> запис `...0004`, `комп'ютерного` -> запис `...0003`) та `USB` (`...0005`) повертають `200 OK` і точні очікувані записи. Пошук `?q=%25` повертає `[]`.
8. **Залишковий ризик та обмеження:**
   - Перевірка дубліката заголовка через `AnyAsync` перед `SaveChangesAsync` не захищає від стану гонитви (race condition) при одночасних паралельних запитах: у промисловій системі її необхідно доповнити частковим унікальним індексом у PostgreSQL (`CREATE UNIQUE INDEX ... WHERE status <> 'Closed'`) та обробкою `DbUpdateException`.
   - У поточному стані `OwnerUserId` призначається зі статичного `DbSeeder.AliceId` (автентифікацію та авторизацію буде додано в ЛР 3–4).
   - На рівні конвеєра Minimal API невалідний синтаксис JSON викликає `BadHttpRequestException` (що перехоплюється глобальним обробником як безпечний `500 Problem Details` без витоку стека).

## Таблиця перевірок

| ID | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| T-01 | Коректне створення | Відновлений seed, унікальний `title`, валідний DTO | `POST /api/incidents` із `"severity": "medium"` та датою `+03:00` | `201 Created`, `CreatedIncidentResponse`, `Title` обрізано, час нормалізовано в UTC | `201 Created`, `Location: /api/incidents/{id}`, `status: "New"`, `severity: "Medium"`, час у UTC (`+00:00`), зайві поля відсутні | `evidence/t01-response.txt`, `Lab02RegressionTests` |
| T-02 | Некоректний DTO | Працюючий API | `POST /api/incidents` з порожнім `title`, `"severity": "7"` та датою у 2099 році | `400`, `application/problem+json`, ключі `title`, `severity`, `occurredAtUtc` | `400 Bad Request`, `application/problem+json`, об'єкт `errors` містить ключі `title`, `severity`, `occurredAtUtc`; стек і SQL відсутні | `evidence/t02-response.txt`, тест `Post_WithInvalidDto_Returns400ValidationProblemWithoutInternalDetails` |
| T-03 | Предметний конфлікт (добрий рівень) | Існує активний інцидент у статусі `New` з тим самим `title` після `Trim()` | Повторний `POST /api/incidents` із тим самим заголовком | `409 Conflict` у форматі `Problem Details` | `409 Conflict`, `application/problem+json`, `title: "Конфлікт створення інциденту"`, без внутрішніх деталей | `evidence/t03-response.txt`, тест `Post_WithDuplicateActiveTitle_Returns409ConflictProblemDetails` |
| S-01 | SQLi до виправлення | `vulnerable commit` (`<VULNERABLE_SHA>`), штатний seed (5 записів) | `GET /api/incidents/search` із контрольним вводом C | Небажано розширена вибірка | `200 OK`, повернено всі 5 інцидентів із БД (`0004`, `0005`, `0003`, `0002`, `0001`), у логах `Parameters=[]` | `evidence/s01-response.txt` |
| S-02 | Retest SQLi | `fixed commit` (`<FIXED_SHA>`), штатний seed | Той самий контрольний запит C | `200 OK`, порожній результат `[]` | `200 OK`, повернено `[]`, у логах значення передано через параметр `@pattern` | `evidence/s02-response.txt`, тест `Search_AfterFix_BlocksSqliAndSupportsLiteralSubstringAndApostrophe` |
| T-04 | Позитивна регресія | `fixed commit` (`<FIXED_SHA>`), штатний seed | Запити `?q=USB`, `?q=O%27Brien`, `?q=комп'ютерного`, `?q=%25` | `200 OK`, знайдено відповідні записи без помилки 500 | `200 OK`: `USB` -> 1 запис (`0005`), `O'Brien` -> 1 запис (`0004`), `комп'ютерного` -> 1 запис (`0003`), `%25` -> `[]` | `evidence/t04-response.txt`, тест `Search_AfterFix_BlocksSqliAndSupportsLiteralSubstringAndApostrophe` |
| T-05 | Невідоме сортування | `fixed commit` (`<FIXED_SHA>`) | `GET /api/incidents/search?sortBy=price` | `400 Bad Request` із ключем `sortBy` | `400 Bad Request`, `application/problem+json`, `errors.sortBy` містить перелік `createdAtUtc, severity, status` | `evidence/t05-response.txt`, тест `Search_WithUnknownSortBy_Returns400WithSortByKey` |
| T-06 | Ресурс не знайдено (добрий рівень) | Працюючий API, неіснуючий UUID | `GET /api/incidents/99999999-9999-9999-9999-999999999999` | `404 Not Found` у форматі `Problem Details` | `404 Not Found`, `application/problem+json`, `title: "Інцидент не знайдено"`, без витоку деталей | `evidence/t06-response.txt` |
| T-09 | Cross-field перевірка 2-A (добрий рівень) | Унікальні `title`, `severity: "High"` | Два `POST /api/incidents`: `description` після `Trim()` має 39 та 40 символів | 39 символів -> `400` (ключ `description`); 40 символів -> `201 Created` | Перший запит повернув `400 Bad Request` із `errors.description`; другий запит повернув `201 Created` | `evidence/t09-response.txt`, тест `Post_HighSeverityCrossFieldBoundary_Rejects39CharsAndAccepts40Chars` |
| A-01 | Огляд data-access points (добрий рівень) | `fixed commit` (`<FIXED_SHA>`) | Виконано пошук `git grep` за `FromSqlRaw`, `ExecuteSqlRaw`, `ORDER BY`, `$"SELECT`, `+ query` | Класифіковано кожен збіг у кодовій базі | Залишився лише 1 безпечний статичний виклик `ExecuteSqlRawAsync` у `DatabaseBootstrap.cs:43`; таблицю наведено нижче | Таблиця `A-01` у звіті, `evidence/test-run.txt` |

### Деталізація A-01 (Огляд raw-SQL місць)

| Файл : рядок / метод | Категорія | Висновок |
| :--- | :--- | :--- |
| `src/SecureLab.Api/Data/DatabaseBootstrap.cs:43` (`ResetAndSeedAsync`) | `ExecuteSqlRawAsync` (Trusted Static SQL) | Безпечно: статична команда `TRUNCATE TABLE ... RESTART IDENTITY CASCADE;` для локального скидання стенда без конкатенації зовнішніх даних. |
| `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs` (`MapLab02Endpoints`) | LINQ (`EF.Functions.ILike` + allowlist `switch`) | Безпечно: колишній `FromSqlRaw` та динамічний `ORDER BY` замінено на параметризований LINQ та серверний allowlist. |
| `src/`, `tests/` (пошук `$"SELECT`, `+ query`, `FromSqlRaw`) | `0 matches` | Безпечно: інших входжень сирого SQL або конкатенації запитів у проєкті немає. |

## Декларація використання генеративного ШІ

- **Сервіс:** Google Gemini
- **Задача:** структурування перевірок контракту 2-A, побудова шаблону `EscapeLike` та оформлення інтеграційних тестів xUnit.
- **Власна адаптація та фактична перевірка:** код інтегровано до власного репозиторію `SecureLab`, перевірено збірку з `TreatWarningsAsErrors`, виконано ручні запити у `lab-02-checks.http` на локальному контейнері PostgreSQL до та після виправлення, перевірено журнали EF Core (`Executed DbCommand`) та успішне проходження всіх автоматичних тестів `dotnet test -c Release`.

## Висновок

1. **Чому змішування даних і структури запиту є першопричиною SQLi:** Коли застосунок склеює недовірений рядок користувача безпосередньо з текстом SQL-запиту до відправлення в СУБД, парсер PostgreSQL не може відрізнити дані від команд і трактує керівні символи даних (зокрема апостроф `'`, оператори `OR`, коментарі `--`) як частину синтаксичного дерева запиту. Параметризація (через LINQ і `EF.Functions.ILike`) передає структуру SQL-команди та значення параметра окремими потоками протоколу БД, унеможливлюючи зміну логіки запиту, а серверний allowlist для `sortBy` гарантує, що структура `ORDER BY` визначається лише фіксованими серверними виразами.
2. **Яку інженерну межу створює серверний контракт:** Відокремлення `CreateIncidentRequest` та `CreatedIncidentResponse` від доменної сутності `Incident` разом із комплексною серверною валідацією унеможливлює підміну службових полів (Overposting), відсікає некоректні формати та порушення міжпольових правил (`400 Bad Request`) ще до звернення до бази даних, чітко відокремлює предметні конфлікти стану (`409 Conflict`) та гарантує повернення уніфікованих `Problem Details` без витоку внутрішньої інформації про систему.