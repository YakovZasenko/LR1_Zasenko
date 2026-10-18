# Матриця контролю доступу (Baseline 2-A «Трекер інцидентів»)

## Політика HTTP-відмов для чужих і недоступних ресурсів
* **Неавтентифікований запит (Анонім):** повертає `401 Unauthorized` (без HTML redirect).
* **Чужий головний або дочірній ресурс (Горизонтальне розмежування):** застосовується послідовна **політика 404 Not Found** (`IncidentNotFound()` з `title: "Інцидент не знайдено"`). Сервер не розкриває факт існування чужого інциденту чи коментаря: відповіді для чужого і неіснуючого UUID є нерозрізнюваними за статусом, `Content-Type` та тілом (крім `traceId`).
* **Привілейована дія (`POST /api/incidents/{id}/triage`):** при спробі виконання користувачем без ролі `Analyst` (наприклад, `Reporter` або `Administrator`) повертається **`403 Forbidden`** та записується безпечна аудиторська подія `authorization.denied` зі спільним `traceId`. Якщо `Analyst` викликає `triage` для інциденту не в статусі `New`, повертається `409 Conflict`.

## Таблиця прав доступу

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---|---|---|---|---|---|
| Перегляд списку `GET /api/incidents` | добрий | deny, `401` | allow: лише власні (`OwnerUserId == principal`) | allow: усі інциденти для аналізу | deny (порожній список за правилом найменших привілеїв) | Так для Reporter | `IncidentQueries.GetListAsync`; тест `A05_List_AsAlice_ReturnsOnlyOwnIncidents` |
| Перегляд деталей `GET /api/incidents/{id}` | достатній (entry-контракт ЛР 5) | deny, `401` | owner: allow `200`; non-owner: deny `404` | allow `200` для аналізу інциденту (включно з internal comments) | deny `404` | Так для Reporter | `IncidentQueries.GetDetailsAsync`; тести `A02`, `A03`, `A03R`, `A10` |
| Створення інциденту `POST /api/incidents` | успадкований baseline | deny, `401` | allow `201` (сервер встановлює `OwnerUserId` з principal та статус `New`) | allow `201` for self | allow `201` for self | Сервер призначає власника з principal | `Lab02Endpoints.cs` (перевірено у ЛР 3) |
| Update content `PUT /api/incidents/{id}` | добрий | deny, `401` | owner: allow `204` (лише `Title`, `Description`, `Severity`); non-owner: deny `404` | deny `404` (читання для аналізу не дає права змінювати чужий контент) | deny `404` | Так (лише Reporter-власник) | `IncidentEndpoints.UpdateAsync`, `IncidentOperations.Update`; тести `A02`, `A04`, `A08a` |
| Delete `DELETE /api/incidents/{id}` | добрий | deny, `401` | owner: allow `204`; non-owner: deny `404` | deny `404` | deny `404` | Так (лише Reporter-власник) | `IncidentEndpoints.DeleteAsync`, `IncidentOperations.Delete`; тест `A04` |
| Зміна статусу (Triage) `POST /api/incidents/{id}/triage` | добрий | deny, `401` | deny `403` + audit event `authorization.denied` | allow `204` лише для переходу `New -> Triaged` (інакше `409 Conflict`) | deny `403` + audit event `authorization.denied` | Ні (визначається роллю `Analyst` та поточним статусом `New`) | `IncidentEndpoints.TriageAsync`, `IncidentOperations.Triage`; тести `A06`, `A07`, `A09` |
| Перегляд коментаря `GET /api/incident-comments/{id}` та internal comment | добрий | deny, `401` | allow `200` лише для публічного коментаря (`IsInternal == false`) до власного інциденту; для чужого або `IsInternal == true` — deny `404` | allow `200` для публічних та внутрішніх коментарів (`IsInternal == true`) | deny `404` | Так для Reporter (перевірка власника батьківського `Incident`) | `IncidentEndpoints.GetCommentAsync`, `IncidentQueries.GetDetailsAsync`; тест `A12` |
