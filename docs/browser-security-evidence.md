# Докази безпеки браузера (ЛР 5)

## 1. Стенд і Git-стан

- Гілка: `lab/5-browser-xss`
- Початковий тег перед роботою: `v0.4.0` (`c0b1a33`)
- Vulnerable state commit: `440110c5f1fe5049dce8aee137edd272eb4e9963`
- Fixed state commit: `[FIXED_HASH]`
- Фінальний тег: `v0.5.0`
- Клієнтський origin: `http://localhost:5080`
- API origin: `http://localhost:5080`
- Додаткова тестова origin для CORS: `http://localhost:4173` (дозволена в `Development`), `http://localhost:4174` (недозволена, негативний контроль)

Команди запуску навчальних серверів для перевірки CORS з кореня проєкту:
- `python3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe`
- `python3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe`

## 2. Позитивна перевірка звичайного тексту

| Набір даних | Очікування | Результат до виправлення | Результат після виправлення | Доказ |
|---|---|---|---|---|
| Лапки (`O'Brien написав "терміново"`) | Відображається без змін і без помилок | Текст відображено коректно | Текст відображено коректно | `GET /api/incidents/{id}` JSON + Elements `#description` |
| Кутові дужки (`5 < 7 і 9 > 3`, `<b>жирний</b> текст`) | Символи видно буквально як текст, теги не парсяться | Для `<b>жирний</b>` створено HTML-елемент `<b>` | Рядок `<b>жирний</b> текст` показано буквально як один текстовий вузол | Elements `#description`: текстовий вузол замість `<b>` |
| Unicode (`Київ — Ω`) | Кирилиця, тире та спецсимволи не пошкоджуються | Відображено без спотворень | Відображено без спотворень | Response JSON та DOM `#description` |
| Довгий дозволений текст (`3900` символів `А`) | Зберігається (межа `<= 4000`) і рендериться без помилок | Відображено повністю | Відображено повністю без помилок у Console | Status `201`/`200`, DOM `#description` |
| Seed-інцидент `20000000-0000-0000-0000-000000000003` (містить `<script>`) | Усе речення видно повністю як текст | Видно лише слово «Текст», решту поглинув тег `<script>` | Повністю видно рядок `Текст <script> має відображатися як текст, а не змінювати DOM.` | Elements `#description` |

## 3. XSS PoC, виправлення і retest

### Стан до виправлення

- Поле: `Incident.Description` та `IncidentComment.Text`
- Sink: `document.querySelector("#description").innerHTML = current.description` та `paragraph.innerHTML = comment.text` у `src/SecureLab.Api/Client/browser-lab.js` (`load()`)
- Тип XSS: Stored XSS + DOM-based XSS (збережені в БД дані користувача доставляються через JSON API і записуються клієнтським скриптом у небезпечний HTML-sink `innerHTML`)
- Канонічний нешкідливий маркер: `<img src="x" onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')">`
- Спостереження у `Network`: `POST /api/incidents` повертає `201 Created`; `GET /api/incidents/{id}` повертає `200 OK` із незміненим рядком маркера в JSON; браузер додатково робить запит `GET http://localhost:5080/x` (`404 Not Found`)
- Спостереження в `Elements`: всередині `<div id="description">` (та `<div id="comments"><p>` для seed-коментаря `30000000-0000-0000-0000-000000000005`) створено елемент `<img src="x" onerror="...">`, а на `<span id="lab05-marker-target">` встановлено атрибут `data-lab05-marker="executed"`
- Перевірка у двох сесіях: маркер, збережений користувачем `alice` (`Reporter`), автоматично виконується у браузері користувача `morgan` (`Analyst`) під час перегляду цього інциденту (`document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")` повертає `'executed'`). Для користувача `bob` (`Reporter`) сервер повертає `404 Not Found` згідно з правилами авторизації ЛР 4, тому маркер не завантажується і залишається `null`

### Виправлення

- Файл і функція: `src/SecureLab.Api/Client/browser-lab.js`, функція `load()` та допоміжна функція `setSafeText(element, text)`
- На який безпечний API замінено небезпечний запис: `innerHTML` замінено на `element.textContent = text ?? ""` через єдиний helper `setSafeText` для `#title`, `#description` та елементів `<p>` у `#comments`
- Чи дозволено форматований HTML за правилами варіанта: ні, поля `Incident.Description` та `IncidentComment.Text` за вимогами варіанта `02-A` містять виключно звичайний текст

### Стан після виправлення

- Повторна перевірка того самого маркера: інцидент із маркером в описі та seed-інцидент `20000000-0000-0000-0000-000000000001` із маркером у коментарі відкрито в сесіях `alice` та `morgan`
- Підтвердження, що значення в БД і JSON-відповіді не було змінено: у вкладці `Network` та в автоматизованому тесті `B02` поле `description` і `comments[].text` у JSON точно дорівнюють початковому рядку `<img src="x" onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')">`
- Спостереження в `Elements`: усередині `#description` та `<p>` коментаря міститься лише один текстовий вузол, жодного тегу `<img>` не створено
- Спостереження в `Console`: `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")` повертає `null`
- Залишковий ризик: потенційна поява нових клієнтських шаблонів або сторонніх віджетів у майбутніх версіях, де розробник може використати `innerHTML` або динамічні `href`/`src` без перевірки схеми URL

## 4. CORS-дослідження

### Прогноз перед налаштуванням

| Сценарій | Чи дійде запит до API | Чи прочитає браузерний JS відповідь | Пояснення |
|---|---|---|---|
| Same-origin клієнт (`5080` → `5080`) | Так | Так | Однаковий origin (`http://localhost:5080`), діє Same-Origin Policy без потреби в CORS |
| Дозволена друга origin (`4173` → `5080`) | Так | Ні — до додавання policy; Так — після додавання policy | Без заголовка `Access-Control-Allow-Origin: http://localhost:4173` браузер блокує читання відповіді скриптом |
| Недозволена origin (`4174` → `5080`) | Так (для простого GET) / лише OPTIONS (для preflight) | Ні | Origin `http://localhost:4174` не входить до allowlist, тому браузер не віддає відповідь коду сторінки |
| Прямий HTTP-клієнт (`curl` / `.http`) | Так | Так (читає напряму) | SOP і CORS — це механізми безпеки браузера; на прямі HTTP-клієнти вони не поширюються |

### Фактичний результат

| Сценарій | Request headers | Preflight (`OPTIONS`) | Response headers | Що бачить клієнт |
|---|---|---|---|---|
| Same-origin (`5080` → `5080`) | Немає крос-доменного блокування | Не виконується | Стандартні заголовки API + CSP, `nosniff`, `no-referrer` | Статус `200`, повний доступ до JSON |
| Allowed origin (`http://localhost:4173`, простий `GET /health`) | `Origin: http://localhost:4173` | Не виконується | `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true`, `Vary: Origin` | JS отримує `{ status: 200, body: '{"status":"ok"}' }` |
| Allowed origin (`http://localhost:4173`, із заголовком `X-Lab-Cors-Probe`) | `Origin: http://localhost:4173`, у preflight: `Access-Control-Request-Method: GET`, `Access-Control-Request-Headers: x-lab-cors-probe` | `OPTIONS /health` → `204 No Content` | У preflight: `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Methods: GET`, `Access-Control-Allow-Headers: X-Lab-Cors-Probe`, `Access-Control-Allow-Credentials: true` | Після успішного `OPTIONS` виконується `GET /health` (`200`), JS читає тіло відповіді |
| Allowed origin (`http://localhost:4173`, `GET /api/incidents` з `credentials: "include"`) | `Origin: http://localhost:4173`, `Cookie: .AspNetCore.Identity.Application=...` | Не виконується | `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true` | Зі сесією Alice: `200` і JSON-список інцидентів; без сесії: `401` (JS бачить статус `401`) |
| Disallowed origin (`http://localhost:4174`) | `Origin: http://localhost:4174` | Для запиту з `X-Lab-Cors-Probe` виконується `OPTIONS /health` (`204` без CORS-заголовків), основний `GET` не надсилається | Заголовки `Access-Control-Allow-*` відсутні | У Console — `blocked by CORS policy` (`TypeError: Failed to fetch`), хоча простий `GET` на сервері виконався зі статусом `200` |
| Direct HTTP (`curl`) | `Origin: http://localhost:4173` та `Origin: http://localhost:4174` | Не виконується | Для `4173` є `Access-Control-Allow-Origin`, для `4174` — немає; обидва повертають `HTTP/1.1 200 OK` | `curl` читає повне тіло відповіді в обох випадках |

### Висновок щодо меж CORS

- Чому CORS не замінює authentication і authorization: CORS лише вказує браузеру, чи можна передати отриману HTTP-відповідь JavaScript-коду іншого origin. Зловмисник або скрипт поза браузером (`curl`, Postman, серверний скрипт) ігнорує правила CORS і читає відповідь напряму, тому без серверної перевірки сесії та прав доступу дані були б відкриті.
- Чому CORS не є повним захистом від CSRF: під час простого cross-origin запиту (або відправлення HTML-форми) браузер спочатку надсилає запит на сервер разом із cookie (якщо дозволяє `SameSite`), сервер виконує дію, і лише після цього браузер блокує читання відповіді скриптом. Тобто побічна зміна стану без CSRF-токена вже відбудеться.
- Який фінальний стан CORS залишено у коді та чому: у `Program.cs` залишено політику `Lab05BrowserProbe`, яка реєструється й підключається виключно за умови `Environment.IsDevelopment()`, дозволяє лише точний origin `http://localhost:4173`, метод `GET`, заголовок `X-Lab-Cors-Probe` та `AllowCredentials()`. У `Production` ця політика повністю вимкнена, а штатний клієнт працює в режимі same-origin на `http://localhost:5080`.

## 5. CSP і захисні заголовки

- Заголовок: `Content-Security-Policy`
- Значення policy: `default-src 'self'; frame-ancestors 'none'`
- Які ресурси потрібні клієнту: документи HTML (`/`, `/browser-lab.html`, `/auth-lab.html`), стилі (`/styles.css`), скрипти (`/app.js`, `/browser-lab.js`, `/auth-lab.js`) та `fetch`-запити до API (`/api/...`, `/health`) — усі завантажуються виключно з власного origin `'self'` (`http://localhost:5080`). Вбудованих скриптів, inline-стилів чи фреймів клієнт не використовує.
- Що перевірено в `Network` і `Console`: на всіх клієнтських маршрутах повертається рівно один заголовок `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff` та `Referrer-Policy: no-referrer`. Під час штатної роботи клієнта порушень у `Console` немає. Під час тестового виклику `new Image().src = "http://localhost:4173/x.png"` браузер блокує завантаження зображення із записом про порушення директиви `default-src 'self'`.
- Чому CSP є defense in depth, а не заміною виправлення DOM sink: CSP `default-src 'self'` блокує виконання inline-обробника `onerror`, але без заміни `innerHTML` на `textContent` зловмисна розмітка все одно вбудовується в DOM дерева сторінки (створюючи сторонні елементи, змінюючи структуру інтерфейсу — HTML injection / defacement або готуючи ґрунт для обходу CSP через скриптові гаджети).

## 6. Регресійна перевірка

- `REG-XSS-01`: виконано ручний retest у браузері (сесії `alice` та `morgan` для `Incident.Description` і seed-коментаря `IncidentComment.Text`) та автоматизовані тести `B01`, `B02` у `tests/SecureLab.Api.Tests/Lab05BrowserSecurityTests.cs`. Маркер зберігається без змін у JSON, рендериться як текстовий вузол, атрибут `data-lab05-marker` залишається `null`.
- `REG-CORS-01`: виконано перевірку в браузері з origins `4173` і `4174`, перевірку через `curl -sS -D - -o /dev/null` для обох origins та автоматизовані тести `B03`, `B04` у `tests/SecureLab.Api.Tests/Lab05BrowserSecurityTests.cs`. Усі 17 автоматизованих тестів проєкту (`13` базових + `4` нових для ЛР 5) проходять успішно (`Passed: 17, Failed: 0`).