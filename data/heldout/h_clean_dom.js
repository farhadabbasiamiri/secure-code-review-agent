function renderComments(list, comments) {
  list.replaceChildren();
  for (const c of comments) {
    const li = document.createElement("li");
    li.textContent = c.body;
    list.appendChild(li);
  }
  document.getElementById("count").innerHTML = "<b>" + comments.length + "</b> comments";
}
