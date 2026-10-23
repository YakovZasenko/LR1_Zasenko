# Security review SecureLab, ЛР 6
Рівень: достатній («Задовільно»)

## 1. Executive summary
## 2. Scope та exclusions
## 3. System overview і trust boundaries
## 4. Methodology та test environment
## 5. Findings summary
## 6. Detailed findings
## 7. Regression results
## 8. Hardening controls
## 9. Dependency and secret audit
| Path | Безпечний контекст | Рішення | Причина й межа |
|---|---|---|---|
| `infra/compose.yaml` | пароль локального контейнера PostgreSQL, порт прив'язано до 127.0.0.1 | accepted, study-only | відкрите навчальне значення, README забороняє повторне використання; не поширюється на інші БД і середовища |
| `src/SecureLab.Api/appsettings.Development.json` | локальний навчальний connection string | accepted, study-only | відкрите навчальне значення; використовується лише в Development оточенні |
| `src/SecureLab.Api/Data/SecureLabDesignTimeDbContextFactory.cs` | connection string для міграцій EF Core | accepted, study-only | містить той самий навчальний пароль `local-study-password` для локального стенда |
| `tests/http/lab3requests.http` | тестові змінні для HTTP-клієнта | не секрет | це фіктивні дані для локальних ручних перевірок, не дають доступу до реальних систем |
| `src/SecureLab.Api/Scaffolding/Lab03Identity.cs`, `Client/*.js`, `Client/*.html` | назви полів DTO, змінних у коді та HTML-елементів | не секрет | це імена властивостей, а не самі значення |
| `tests/SecureLab.Api.Tests/packages.lock.json` | ідентифікатор пакета | не секрет | це назва залежності, а не секретне значення |
| `docs/git-workflow.md`, `.gitignore`, `README.md` | згадки в документації та правилах ігнорування | не секрет | звичайний текст і коментарі |
| `src/SecureLab.Api/Data/DbSeeder.cs`, `tests/*.cs` | код, що читає змінну `SeedUsers__Password` | не секрет | значення передається через змінні середовища поза Git, у коді лише логіка |
## 10. Residual risks
## 11. Conclusion
## 12. Evidence appendix
