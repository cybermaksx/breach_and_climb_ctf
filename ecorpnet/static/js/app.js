// Small UI helpers (no inline JS so the Content-Security-Policy can forbid it).
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});
document.addEventListener("click", function (e) {
  if (e.target.closest("[data-print]")) window.print();
});
