const result = document.querySelector("#result");
const stateEl = document.querySelector("#state");
const profile = document.querySelector("#profile");

function apiFetch(path, options = {}) {
  return fetch(path, { ...options, credentials: "same-origin" });
}

function postJson(path, data) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

function clearProfile() {
  profile.hidden = true;
  for (const id of ["#p-id", "#p-name", "#p-role"])
    document.querySelector(id).textContent = "";
}

function showProfile(data) {
  document.querySelector("#p-id").textContent = data.userId ?? "";
  document.querySelector("#p-name").textContent = data.userName ?? "";
  document.querySelector("#p-role").textContent = data.role ?? "";
  profile.hidden = false;
}

async function refreshState() {
  const response = await apiFetch("/api/auth/session-check");
  if (response.status === 204) stateEl.textContent = "Сеанс активний";
  else if (response.status === 401) {
    stateEl.textContent = "Не ввійшли";
    clearProfile();
  } else stateEl.textContent = "Невідомо (" + response.status + ")";
}

async function loadProfile() {
  const response = await apiFetch("/api/me");
  const isJson = (response.headers.get("Content-Type") ?? "").includes("json");
  if (response.status === 401) {
    clearProfile();
    result.textContent = "Profile: 401";
    return;
  }
  if (!response.ok || !isJson) {
    clearProfile();
    result.textContent = "Profile: " + response.status;
    return;
  }
  showProfile(await response.json());
  result.textContent = "Profile: 200";
}

document
  .querySelector("#register")
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const response = await postJson(
      "/api/auth/register",
      Object.fromEntries(new FormData(form)),
    );
    form.elements.password.value = "";
    result.textContent = "Register: " + response.status + " (тепер увійдіть)"; // автологіну немає
  });

document.querySelector("#login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const response = await postJson(
    "/api/auth/login",
    Object.fromEntries(new FormData(form)),
  );
  form.elements.password.value = "";
  result.textContent = "Login: " + response.status;
  await refreshState();
  if (response.ok) await loadProfile();
});

document.querySelector("#me").addEventListener("click", loadProfile);

document.querySelector("#logout").addEventListener("click", async () => {
  const response = await apiFetch("/api/auth/logout", { method: "POST" });
  clearProfile();
  document.querySelector("#incident").reset();
  result.textContent = "Logout: " + response.status;
  await refreshState();
});

document
  .querySelector("#incident")
  .addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const body = {
      title: data.get("title"),
      description: data.get("description"),
      severity: data.get("severity"),
      occurredAtUtc: new Date(data.get("occurredAt")).toISOString(),
    };
    const response = await postJson("/api/incidents", body);
    result.textContent = "Create: " + response.status;
    if (response.status === 401) {
      await refreshState();
    }
  });

refreshState();
