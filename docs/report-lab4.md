# ЗВІТ
**з лабораторної роботи № 4**
**з дисципліни:** «Прикладні технології програмування в інформаційній безпеці»
**на тему:** «Авторизація, ролі, володіння ресурсом та IDOR/BOLA»

---

## 1. Параметри відтворення та середовище

* **Виконав:** студент групи [Ваша група], Корбут Данило Андрійович
* **Предметний профіль:** Спільний навчальний Baseline 2-A «Трекер інцидентів»
* **Обраний рівень виконання:** Добрий («Добре»)
* **Початковий тег (ЛР 3):** `v0.3.0` (`217120083bfa1b5b5a6400bb585b33f3651510f9`)
* **Робоча гілка:** `lab/4-authorization`
* **Vulnerable commit hash (стан «до» з PoC):** `42cf0c074409e53feb71497186db967046d8ddd3`
* **Fixed commit hash (виправлений стан):** `93abd7f2f979236d4dcc510c8b2c223b96d6abc7`
* **Підсумковий тег:** `v0.4.0`
* **ОС та SDK:** Windows 11 / .NET SDK 10.0 (`net10.0`)
* **Команди підготовки та перевірки:**
  ```powershell
  docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
  dotnet run --project src/SecureLab.Api -- --reset-database
  dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj -c Release