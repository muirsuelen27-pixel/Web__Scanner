(() => {
  "use strict";

  const root = document.documentElement;
  root.classList.add("js-ready");

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  const menuToggle = document.querySelector(".menu-toggle");
  const navigation = document.querySelector(".primary-navigation");

  if (menuToggle && navigation) {
    const setMenuOpen = (open) => {
      menuToggle.setAttribute("aria-expanded", String(open));
      menuToggle.setAttribute(
        "aria-label",
        open ? "Cerrar menú de navegación" : "Abrir menú de navegación"
      );
      navigation.classList.toggle("is-open", open);
    };

    menuToggle.addEventListener("click", () => {
      const open = menuToggle.getAttribute("aria-expanded") !== "true";
      setMenuOpen(open);
      if (open) {
        navigation.querySelector("a")?.focus();
      }
    });

    navigation.addEventListener("click", (event) => {
      if (event.target.closest("a")) {
        setMenuOpen(false);
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && menuToggle.getAttribute("aria-expanded") === "true") {
        setMenuOpen(false);
        menuToggle.focus();
      }
    });

    document.addEventListener("click", (event) => {
      if (
        menuToggle.getAttribute("aria-expanded") === "true" &&
        !navigation.contains(event.target) &&
        !menuToggle.contains(event.target)
      ) {
        setMenuOpen(false);
      }
    });

    const mobileBreakpoint = window.matchMedia("(min-width: 821px)");
    mobileBreakpoint.addEventListener("change", (event) => {
      if (event.matches) {
        setMenuOpen(false);
      }
    });
  }

  const samePageLinks = [...document.querySelectorAll('a[href^="#"]')];
  const observedSections = samePageLinks
    .map((link) => {
      const id = decodeURIComponent(link.hash.slice(1));
      return id ? document.getElementById(id) : null;
    })
    .filter((section, index, sections) => section && sections.indexOf(section) === index);

  const setCurrentLocation = (section) => {
    if (!section?.id) {
      return;
    }

    samePageLinks.forEach((link) => {
      if (link.hash !== `#${section.id}`) {
        if (link.getAttribute("aria-current") === "location") {
          link.removeAttribute("aria-current");
        }
        return;
      }

      link.setAttribute("aria-current", "location");
    });
  };

  if ("IntersectionObserver" in window && observedSections.length > 0) {
    const sectionObserver = new IntersectionObserver(
      (entries) => {
        const visibleSections = entries
          .filter((entry) => entry.isIntersecting)
          .sort((first, second) => first.boundingClientRect.top - second.boundingClientRect.top);

        if (visibleSections[0]) {
          setCurrentLocation(visibleSections[0].target);
        }
      },
      {
        rootMargin: "-18% 0px -68% 0px",
        threshold: 0,
      }
    );

    observedSections.forEach((section) => sectionObserver.observe(section));
  }

  const revealItems = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const revealObserver = new IntersectionObserver(
      (entries, observer) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -48px 0px", threshold: 0.08 }
    );

    revealItems.forEach((item) => revealObserver.observe(item));
  } else {
    revealItems.forEach((item) => item.classList.add("is-visible"));
  }

  document.querySelectorAll("[data-image-frame] img").forEach((image) => {
    const frame = image.closest("[data-image-frame]");
    const imageButton = image.closest("[data-image-dialog]");
    const setImageState = () => {
      const missing = image.naturalWidth === 0;
      frame?.classList.toggle("is-missing", missing);
      if (imageButton) {
        imageButton.disabled = missing;
        imageButton.setAttribute("aria-disabled", String(missing));
      }
    };

    image.addEventListener("load", setImageState);
    image.addEventListener("error", setImageState);
    if (image.complete) {
      setImageState();
    }
  });

  const imageDialog = document.querySelector("#image-dialog");
  const dialogImage = imageDialog?.querySelector(".dialog-image");
  const dialogTitle = imageDialog?.querySelector("#image-dialog-title");
  const closeDialogButton = imageDialog?.querySelector("[data-dialog-close]");
  let dialogOpener = null;

  if (
    imageDialog instanceof HTMLDialogElement &&
    dialogImage instanceof HTMLImageElement &&
    dialogTitle instanceof HTMLElement &&
    closeDialogButton instanceof HTMLButtonElement
  ) {
    document.querySelectorAll("[data-image-dialog]").forEach((button) => {
      button.addEventListener("click", () => {
        if (button.disabled || !button.dataset.imageSrc) {
          return;
        }

        const image = button.querySelector("img");
        if (!(image instanceof HTMLImageElement) || image.naturalWidth === 0) {
          return;
        }

        dialogOpener = button;
        dialogImage.src = button.dataset.imageSrc;
        dialogImage.alt = button.dataset.imageAlt || image.alt;
        dialogTitle.textContent =
          button.querySelector(".shot-copy strong")?.textContent || "Captura de Web Scanner";
        imageDialog.showModal();
        closeDialogButton.focus();
      });
    });

    closeDialogButton.addEventListener("click", () => imageDialog.close());

    imageDialog.addEventListener("click", (event) => {
      if (event.target === imageDialog) {
        imageDialog.close();
      }
    });

    imageDialog.addEventListener("close", () => {
      dialogOpener?.focus();
      dialogOpener = null;
    });
  }

  const copyText = async (text) => {
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        // Continue with the local clipboard fallback when browser permissions deny access.
      }
    }

    const temporaryField = document.createElement("textarea");
    temporaryField.value = text;
    temporaryField.setAttribute("readonly", "");
    temporaryField.className = "clipboard-fallback";
    document.body.append(temporaryField);
    temporaryField.select();

    let copied = false;
    try {
      copied = document.execCommand("copy");
    } finally {
      temporaryField.remove();
    }
    return copied;
  };

  document.querySelectorAll("[data-copy-command]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget || "");
      const status = button.closest(".code-card")?.querySelector(".copy-status");
      if (!(target instanceof HTMLElement) || !(status instanceof HTMLElement)) {
        return;
      }

      const copied = await copyText(target.textContent.trim());
      status.textContent = copied
        ? "Comando copiado al portapapeles."
        : "No se pudo copiar. Selecciona y copia el comando manualmente.";
      button.classList.toggle("is-copied", copied);
      button.setAttribute("aria-label", copied ? "Comando copiado" : "No se pudo copiar el comando");

      window.setTimeout(() => {
        button.classList.remove("is-copied");
        button.removeAttribute("aria-label");
        status.textContent = "";
      }, 2600);
    });
  });

  document.querySelectorAll("[data-current-year]").forEach((year) => {
    year.textContent = String(new Date().getFullYear());
  });

  const backToTop = document.querySelector("[data-back-to-top]");
  if (backToTop instanceof HTMLButtonElement) {
    const updateBackToTop = () => {
      backToTop.classList.toggle("is-visible", window.scrollY > 560);
    };

    window.addEventListener("scroll", updateBackToTop, { passive: true });
    updateBackToTop();
    backToTop.addEventListener("click", () => {
      window.scrollTo({
        top: 0,
        behavior: reduceMotion.matches ? "auto" : "smooth",
      });
    });
  }
})();
