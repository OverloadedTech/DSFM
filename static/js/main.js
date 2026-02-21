(function () {
  const autoScroll = document.querySelector("[data-chat-scroll='true']");
  if (autoScroll) {
    autoScroll.scrollTop = autoScroll.scrollHeight;
  }

  const replyTargetInput = document.querySelector("[data-reply-target-input]");
  const replyTargetBox = document.querySelector("[data-reply-target-box]");
  const replyTargetText = document.querySelector("[data-reply-target-text]");
  const replyClear = document.querySelector("[data-reply-clear]");

  const trimPreview = (text) => {
    const val = (text || "").replace(/\s+/g, " ").trim();
    if (!val) {
      return "(messaggio vuoto)";
    }
    if (val.length <= 180) {
      return val;
    }
    return `${val.slice(0, 180)}...`;
  };

  const setReplyTarget = (msgId, previewText) => {
    if (!replyTargetInput || !replyTargetBox || !replyTargetText) {
      return;
    }
    replyTargetInput.value = String(msgId || "");
    replyTargetText.textContent = `Stai rispondendo a #${msgId}: ${trimPreview(previewText)}`;
    replyTargetBox.style.display = "block";
  };

  const clearReplyTarget = () => {
    if (!replyTargetInput || !replyTargetBox || !replyTargetText) {
      return;
    }
    replyTargetInput.value = "";
    replyTargetText.textContent = "";
    replyTargetBox.style.display = "none";
  };

  if (replyClear) {
    replyClear.addEventListener("click", clearReplyTarget);
  }

  document.querySelectorAll(".reply-link").forEach((button) => {
    button.addEventListener("click", () => {
      const msgId = Number.parseInt(button.dataset.replyTo || "0", 10) || 0;
      const previewText = button.dataset.replyPreview || "";
      if (msgId > 0) {
        setReplyTarget(msgId, previewText);
      }
    });
  });

  const liveChat = document.querySelector("[data-chat-live='true']");
  if (liveChat) {
    let lastId = Number.parseInt(liveChat.dataset.lastId || "0", 10) || 0;
    const apiUrl = liveChat.dataset.chatApi || "";

    const rowClassForSender = (senderType) => {
      if (senderType === "admin") {
        return "admin";
      }
      if (senderType === "admin_note") {
        return "note";
      }
      return "user";
    };

    const shouldAutoScroll = () => {
      const distance = liveChat.scrollHeight - liveChat.scrollTop - liveChat.clientHeight;
      return distance < 120;
    };

    const appendMessage = (msg) => {
      const box = document.createElement("div");
      box.className = `msg ${rowClassForSender(msg.sender_type || "")}`;
      box.dataset.msgId = String(msg.id || "");

      if (msg.reply_to_content) {
        const replyRef = document.createElement("div");
        replyRef.className = "msg-reply-ref";
        replyRef.textContent = `Risposta a #${msg.reply_to_message_id || "-"}: ${msg.reply_to_content}`;
        box.appendChild(replyRef);
      }

      const content = document.createElement("div");
      content.textContent = msg.content || "";
      box.appendChild(content);

      const meta = document.createElement("div");
      meta.className = "msg-meta";
      meta.textContent = `${msg.sender_type || "user"} · ${msg.content_type || "text"} · ${msg.created_at || ""}`;
      box.appendChild(meta);

      if (msg.sender_type === "user" && msg.direction === "in") {
        const replyBtn = document.createElement("button");
        replyBtn.type = "button";
        replyBtn.className = "btn reply-link";
        replyBtn.textContent = "Rispondi a questo";
        replyBtn.addEventListener("click", () => {
          const msgId = Number.parseInt(String(msg.id || 0), 10) || 0;
          if (msgId > 0) {
            setReplyTarget(msgId, msg.content || "");
          }
        });
        box.appendChild(replyBtn);
      }

      const empty = liveChat.querySelector(".empty");
      if (empty) {
        empty.remove();
      }
      liveChat.appendChild(box);
    };

    let fetching = false;
    const poll = async () => {
      if (fetching || !apiUrl) {
        return;
      }
      fetching = true;
      const stickToBottom = shouldAutoScroll();
      try {
        const resp = await fetch(`${apiUrl}?after_id=${lastId}`, {
          headers: {
            Accept: "application/json",
          },
          credentials: "same-origin",
          cache: "no-store",
        });
        if (!resp.ok) {
          return;
        }
        const data = await resp.json();
        const messages = Array.isArray(data.messages) ? data.messages : [];
        messages.forEach((msg) => {
          const msgId = Number.parseInt(String(msg.id || 0), 10) || 0;
          if (msgId > lastId) {
            appendMessage(msg);
            lastId = msgId;
          }
        });
        if (messages.length > 0 && stickToBottom) {
          liveChat.scrollTop = liveChat.scrollHeight;
        }
      } catch (_err) {
        // Polling best-effort: ignore transient network errors.
      } finally {
        fetching = false;
      }
    };

    window.setTimeout(poll, 1200);
    window.setInterval(poll, 2500);
  }

  const dangerForms = document.querySelectorAll("form[data-confirm]");
  dangerForms.forEach((form) => {
    form.addEventListener("submit", (ev) => {
      const msg = form.getAttribute("data-confirm") || "Confermi questa azione?";
      if (!window.confirm(msg)) {
        ev.preventDefault();
      }
    });
  });

  const hourlyCanvas = document.getElementById("hourlyChart");
  if (hourlyCanvas && window.Chart) {
    const labels = JSON.parse(hourlyCanvas.dataset.labels || "[]");
    const values = JSON.parse(hourlyCanvas.dataset.values || "[]");
    // eslint-disable-next-line no-new
    new Chart(hourlyCanvas, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Richieste",
            data: values,
            borderColor: "#3b82f6",
            backgroundColor: "rgba(59,130,246,0.12)",
            borderWidth: 2,
            pointRadius: 2,
            tension: 0.3,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: "#d4d4d8" } },
        },
        scales: {
          x: { ticks: { color: "#71717a" }, grid: { color: "rgba(255,255,255,0.05)" } },
          y: {
            ticks: { color: "#71717a" },
            grid: { color: "rgba(255,255,255,0.05)" },
            beginAtZero: true,
          },
        },
      },
    });
  }

  const sectionCanvas = document.getElementById("sectionsChart");
  if (sectionCanvas && window.Chart) {
    const labels = JSON.parse(sectionCanvas.dataset.labels || "[]");
    const values = JSON.parse(sectionCanvas.dataset.values || "[]");
    // eslint-disable-next-line no-new
    new Chart(sectionCanvas, {
      type: "bar",
      data: {
        labels,
        datasets: [
          {
            label: "Visualizzazioni",
            data: values,
            borderWidth: 1,
            borderColor: "#3b82f6",
            backgroundColor: "rgba(59,130,246,0.5)",
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: "#d4d4d8" } },
        },
        scales: {
          x: { ticks: { color: "#71717a" }, grid: { color: "rgba(255,255,255,0.05)" } },
          y: {
            ticks: { color: "#71717a" },
            grid: { color: "rgba(255,255,255,0.05)" },
            beginAtZero: true,
          },
        },
      },
    });
  }
})();
