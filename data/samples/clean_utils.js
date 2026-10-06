function slugify(title) {
  return String(title)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function formatPrice(cents, currency = "INR") {
  return new Intl.NumberFormat("en-IN", { style: "currency", currency }).format(cents / 100);
}

module.exports = { slugify, formatPrice };
