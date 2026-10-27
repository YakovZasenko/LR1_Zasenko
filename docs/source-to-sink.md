# Карта source-to-sink для ЛР 5

## 1. Досліджуваний потік

- Варіант: `02-A` — Інциденти безпеки та журнал реагування (`Incident`, `IncidentComment`)
- Сторінка або клієнтський маршрут: `http://localhost:5080/browser-lab.html` (`src/SecureLab.Api/Client/browser-lab.html`, `src/SecureLab.Api/Client/browser-lab.js`)
- Користувацька дія: створення інциденту через форму `#edit` («Створити й прочитати») або читання інциденту за `Guid` («Прочитати»)
- API endpoint: `POST /api/incidents`, `GET /api/incidents/{id:guid}`

## 2. Таблиця руху даних

| Поле / значення | Source | Request | Server transformation / validation | Storage | Response field | Client transformation | DOM sink | Контекст | Статус довіри | Поточне рішення |
|---|---|---|---|---|---|---|---|---|---|---|
| `Incident.Description` | `<textarea name="description">` у формі `#edit` (`Client/browser-lab.html`) | JSON-поле `description` у `POST /api/incidents` (`CreateIncidentRequest` у `Scaffolding/Lab02Endpoints.cs`) | `request.Description?.Trim()`; перевірка обов'язковості, довжини `<= 4000`, для `High`/`Critical` `>= 40` символів; без HTML-очищення | Таблиця `incidents`, колонка `description` (`varchar(4000)`, `Data/Entities/Incident.cs`) | `IncidentDetailsResponse.Description` (`description` у `GET /api/incidents/{id}`) | `current = await response.json()` у `load()` (`Client/browser-lab.js`) | Було: `#description.innerHTML`; стало: `setSafeText(#description, current.description)` (`textContent`) | Було: HTML-контекст; стало: текстовий вузол | Контрольоване користувачем / збережене значення користувача (недовірене) | Заміна `innerHTML` на `textContent` через `setSafeText` |
| `IncidentComment.Text` | Seed-дані у `Data/DbSeeder.cs` (`SeedAsync`, коментар `30000000-0000-0000-0000-000000000005`, `Lab05Marker`) або введення автора коментаря | Коментар створюється під час ініціалізації стенда (або через сервіс коментарів) | Зберігається як звичайний текст (`varchar(2000)`) без HTML-трансформації | Таблиця `incident_comments`, колонка `text` (`Data/Entities/IncidentComment.cs`) | `IncidentCommentResponse.Text` (`comments[].text` у `GET /api/incidents/{id}`) | Цикл `for (const comment of current.comments ?? [])` у `load()` (`Client/browser-lab.js`) | Було: `paragraph.innerHTML`; стало: `setSafeText(paragraph, comment.text)` (`textContent`) | Було: HTML-контекст; стало: текстовий вузол | Збережене значення користувача (недовірене) | Заміна `innerHTML` на `textContent` через `setSafeText` |
| `Incident.Title` | `<input name="title">` у формі `#edit` (`Client/browser-lab.html`) | JSON-поле `title` у `POST /api/incidents` | `request.Title?.Trim()`, довжина `5..200` символів | Таблиця `incidents`, колонка `title` (`varchar(200)`) | `IncidentDetailsResponse.Title` (`title` у `GET /api/incidents/{id}`) | `current.title` у `load()` (`Client/browser-lab.js`) | `setSafeText(document.querySelector("#title"), current.title)` (`textContent`) | Текстовий вузол | Збережене значення користувача (недовірене) | Безпечно (`textContent`) |

## 3. Інвентаризація DOM sinks

| Файл і функція | Вираз запису у DOM | Які дані туди потрапляють | Контекст | Безпечно чи небезпечно | Що змінено |
|---|---|---|---|---|---|
| `Client/browser-lab.js`, `load()` | `document.querySelector("#title").textContent` | `current.title` | Текстовий вузол | Безпечно | Уніфіковано виклик через `setSafeText(document.querySelector("#title"), current.title)` |
| `Client/browser-lab.js`, `load()` | `document.querySelector("#description").innerHTML = current.description` | `current.description` | HTML-контекст (парсер DOM) | Небезпечно (Stored / DOM XSS) | Замінено на `setSafeText(document.querySelector("#description"), current.description)` |
| `Client/browser-lab.js`, `load()` | `paragraph.innerHTML = comment.text` | `comment.text` із масиву `current.comments` | HTML-контекст (парсер DOM) | Небезпечно (Stored / DOM XSS) | Замінено на `setSafeText(paragraph, comment.text)` |
| `Client/browser-lab.js`, `load()` | `status.textContent = ...` | Числовий HTTP-статус відповіді (`response.status`) | Текстовий вузол | Безпечно | Без змін |
| `Client/browser-lab.js`, `load()` | `form.elements.title.value = ...`, `form.elements.description.value = ...` | `current.title`, `current.description` | Властивість `.value` елементів форми | Безпечно (не запускає HTML-парсер) | Без змін |
| `Client/browser-lab.js`, `id()` | `encodeURIComponent(document.querySelector("#incident-id").value.trim())` | Ідентифікатор інциденту з поля вводу | URL-сегмент шляху того самого origin | Безпечно (`encodeURIComponent`) | Без змін |
| `Client/app.js`, `createTextElement()`, `renderIncidentDetails()` | `element.textContent = text ?? ""` | Поля інциденту та коментарів у штатному клієнті | Текстовий вузол | Безпечно | Без змін |

## 4. Гіпотеза перед PoC

Значення з `<textarea name="description">` форми `#edit` (`Client/browser-lab.html`) зберігається в PostgreSQL (`incidents.description`), повертається через поле `description` відповіді `GET /api/incidents/{id}` (`IncidentDetailsResponse.Description`) і передається у sink `document.querySelector("#description").innerHTML` (`Client/browser-lab.js`, `load()`) як HTML-контекст; тому за умов наявності в описі або коментарі HTML-подібного рядка браузер інтерпретує дані не як звичайний текст, а будує DOM-елементи (зокрема `<img onerror="...">`) і виконує JavaScript-обробник у контексті сесії поточного глядача (наприклад, аналітика Morgan).