const status = document.querySelector("#status");
const form = document.querySelector("#edit");
let current = null;

function id() {
  return encodeURIComponent(
    document.querySelector("#incident-id").value.trim(),
  );
}

function setSafeText(element, text) {
  element.textContent = text ?? "";
}

async function load() {
  const response = await fetch(`/api/incidents/${id()}`);
  setSafeText(status, `GET: ${response.status}`);
  if (!response.ok) return;

  current = await response.json();
  setSafeText(document.querySelector("#title"), current.title);
  form.elements.title.value = current.title ?? "";
  form.elements.description.value = current.description ?? "";

  setSafeText(document.querySelector("#description"), current.description);

  const comments = document.querySelector("#comments");
  comments.replaceChildren();
  for (const comment of current.comments ?? []) {
    const paragraph = document.createElement("p");
    setSafeText(paragraph, comment.text);
    comments.append(paragraph);
  }
}

document.querySelector("#load").addEventListener("click", load);

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(form));
  const createResponse = await fetch("/api/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      title: data.title,
      description: data.description,
      severity: current?.severity ?? "Low",
      occurredAtUtc: current?.occurredAtUtc ?? new Date().toISOString(),
    }),
  });
  setSafeText(status, `POST: ${createResponse.status}`);
  if (!createResponse.ok) return;

  const created = await createResponse.json();
  document.querySelector("#incident-id").value = created.id;
  await load();
});
