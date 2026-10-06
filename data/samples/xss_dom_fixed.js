function renderGreeting() {
  const name = decodeURIComponent(window.location.hash.slice(1));
  const el = document.getElementById("greeting");
  el.textContent = "Hello, " + name;
}

window.addEventListener("hashchange", renderGreeting);
