window.addEventListener("message", (event) => {
  const box = document.querySelector("#notice");
  box.insertAdjacentHTML("beforeend", event.data.html);
});
