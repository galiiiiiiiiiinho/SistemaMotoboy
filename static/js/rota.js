// /static/js/rota.js
(function () {
  "use strict";

  // ===== helpers =====
  const $ = (sel, ctx = document) => ctx.querySelector(sel);

  // Data ISO atual (YYYY-MM-DD) com fallback a URL /moto/YYYY-MM-DD
  function getCurrentISO() {
    const inp = $("#data-dia");
    if (inp && inp.value) return inp.value.trim();
    const m = location.pathname.match(/\/moto\/(\d{4}-\d{2}-\d{2})/);
    return m ? m[1] : new Date().toISOString().slice(0, 10);
  }

  // Atualiza KPIs e contador do período ao remover/adicionar 1 card
  function updateCounters(delta, card) {
    const kpis = Array.from(document.querySelectorAll(".stats .kpi"));
    const kTotal = kpis[0], kManha = kpis[1], kTarde = kpis[2];

    const grid = card.closest(".grid");
    const head = grid ? grid.previousElementSibling : null; // .section-head
    const isMorning = head?.querySelector("h2")?.textContent?.toLowerCase().includes("manhã");

    const getN = (el) => (parseInt(el?.textContent || "0", 10) || 0);
    const setN = (el, v) => { if (el) el.textContent = Math.max(0, v); };

    setN(kTotal, getN(kTotal) + delta);
    if (isMorning) setN(kManha, getN(kManha) + delta);
    else setN(kTarde, getN(kTarde) + delta);

    const pill = head?.querySelector(".pill");
    setN(pill, getN(pill) + delta);
  }

  // Remoção visual do cartão
  function animateRemoveCard(card) {
    card.style.transition = "opacity .18s ease, transform .18s ease";
    card.style.opacity = "0";
    card.style.transform = "translateY(-4px)";
    setTimeout(() => {
      const grid = card.parentElement;
      card.remove();
      if (!grid.querySelector(".cartao")) {
        const head = grid.previousElementSibling; // .section-head
        const secName = head?.querySelector("h2")?.textContent?.split("–")[1]?.trim() || "período";
        const empty = document.createElement("div");
        empty.className = "card muted";
        empty.textContent = `Sem itens para ${secName}.`;
        grid.replaceWith(empty);
      }
    }, 180);
  }

  // ===== navegação por data =====
  function setupDateForm() {
    const form = $("#date-form");
    const input = $("#data-dia");
    if (!form || !input) return;

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const iso = (input.value || "").trim();
      if (iso) window.location.href = `/moto/${iso}`;
    });

    input.addEventListener("change", () => {
      form.requestSubmit ? form.requestSubmit() : form.submit();
    });
  }

  // ===== Botão "Marcar como feito" =====
  function setupDoneButtons() {
    const iso = getCurrentISO();
    document.querySelectorAll(".btn-done").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const card = btn.closest(".cartao");
        const empresa = card?.querySelector(".empresa")?.textContent?.trim() || "o item";
        if (!confirm(`Confirmar que "${empresa}" foi concluído?`)) return;

        btn.disabled = true;
        try {
          const id = btn.dataset.id;
          const res = await fetch("/moto/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ date: iso, id, done: true })
          });
          if (!res.ok) throw new Error("Falha ao salvar");

          updateCounters(-1, card);
          animateRemoveCard(card);
        } catch (err) {
          alert("Não consegui salvar. Tenta de novo.");
          btn.disabled = false;
        }
      });
    });
  }

  // ===== init =====
  document.addEventListener("DOMContentLoaded", () => {
    setupDateForm();
    setupDoneButtons();

    // Reagendamento desativado. Se reativar no HTML, reimporte aqui:
    // setupRescheduleButtons();
  });
})();
