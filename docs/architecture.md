# Карта архітектури

Це початкова карта. Під час ЛР 1 доповніть її власним трасуванням запиту,
конкретними файлами та спостереженнями з DevTools і журналу PostgreSQL.

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | Надсилає HTTP-запити, безпечно показує відповідь через DOM API |
| Presentation | `Presentation/` | Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь |
| Application | `Application/` | Виконує сценарій отримання списку або деталей інциденту |
| Data | `Data/` | Відображає C#-сутності на PostgreSQL через EF Core/Npgsql |
| PostgreSQL | `infra/compose.yaml` | Зберігає навчальні дані у локальному контейнері |

## Підготовлений наскрізний маршрут

```text
кнопка summary у Client/index.html
  → handler у Client/app.js
  → GET /api/incidents/severity-summary
  → Presentation/Endpoints/IncidentEndpoints.cs
  → Application/Incidents/IncidentQueries.cs
  → Data/SecureLabDbContext.cs / таблиця incidents
  → PostgreSQL
  → IncidentSeveritySummaryResponse як JSON
  → textContent у списку підсумку в Client/app.js

## Межі довіри

Межа, Чому даним ще не можна довіряти, Де перевіряємо або обмежуємо

Користувач → Browser client,Користувач контролює введення,Валідація HTML-форми є лише елементом інтерфейсу; реальний контроль має бути на сервері.
Browser client → API,Клієнт і HTTP-запит можна змінити поза UI,"Маршрутне обмеження (наприклад, :guid) та серверна перевірка параметрів і наявності ресурсу."
PostgreSQL → API → DOM,У БД може зберігатися раніше введений недовірений текст,Проєкція у спеціальний DTO-контракт та безпечний DOM sink (використання textContent замість HTML).

## Конфігураційні входи

global.json — версія .NET SDK;
src/SecureLab.Api/appsettings*.json — режим міграцій і локальний connection string;
infra/compose.yaml — версія PostgreSQL, порт і локальні навчальні облікові дані;
змінна середовища ConnectionStrings__SecureLab — безпечний спосіб перевизначити connection string поза репозиторієм.


