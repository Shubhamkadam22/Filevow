// Small progressive enhancements; every page works without JavaScript.
(() => {
  const nav = document.querySelector(".nav");
  const toggle = document.querySelector(".nav-toggle");
  toggle?.addEventListener("click", () => {
    const open = nav.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
  });

  // Download page: show the published SHA-256 of the installer so people can check it.
  const checksum = document.querySelector("[data-checksum]");
  if (checksum) {
    fetch(checksum.dataset.checksum, { cache: "no-store" })
      .then((response) => (response.ok ? response.text() : Promise.reject()))
      .then((text) => {
        const hash = text.trim().split(/\s+/)[0];
        if (/^[0-9a-f]{64}$/i.test(hash)) {
          checksum.textContent = hash.toLowerCase();
          checksum.classList.add("ready");
        }
      })
      .catch(() => undefined);
  }

  const year = document.querySelector("[data-year]");
  if (year) year.textContent = String(new Date().getFullYear());
})();
