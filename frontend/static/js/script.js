/* ModelTrust – Interactive Frontend Controls & Scan Progress */

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("analyzeForm");
  const urlInput = document.getElementById("repoUrlInput");
  const validationMsg = document.getElementById("urlValidationMsg");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const progressBox = document.getElementById("scanProgressBox");
  const progressBar = document.getElementById("scanProgressBar");
  const stageTitle = document.getElementById("scanStageTitle");
  const scanPercent = document.getElementById("scanPercent");
  const errorAlert = document.getElementById("scanErrorAlert");

  // Quick example URL buttons
  document.querySelectorAll(".example-url-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (urlInput) {
        urlInput.value = btn.getAttribute("data-url") || "";
        validateClientUrl(urlInput.value);
      }
    });
  });

  // Copy-to-clipboard buttons (SHA-256 hashes)
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const value = btn.getAttribute("data-copy") || "";
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        const orig = btn.innerHTML;
        btn.innerHTML = '<i class="bi bi-check2 text-success"></i>';
        setTimeout(() => {
          btn.innerHTML = orig;
        }, 1500);
      } catch (_) {}
    });
  });

  function validateClientUrl(raw) {
    const val = (raw || "").trim();
    const ghPattern = /^https:\/\/(www\.)?github\.com\/[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+(\/.*)?$/i;
    const hfPattern = /^https:\/\/(www\.)?huggingface\.co\/(models\/|datasets\/|spaces\/)?[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)?(\/.*)?$/i;

    if (!val) {
      return { valid: false, message: "Please enter a GitHub or Hugging Face repository URL." };
    }
    if (ghPattern.test(val)) {
      return { valid: true, platform: "GitHub", message: "Valid GitHub repository URL detected." };
    }
    if (hfPattern.test(val)) {
      return { valid: true, platform: "Hugging Face", message: "Valid Hugging Face repository URL detected." };
    }
    return {
      valid: false,
      message: "Invalid URL. Only HTTPS GitHub (github.com/owner/repo) and Hugging Face (huggingface.co/owner/model) URLs are allowed.",
    };
  }

  if (urlInput && validationMsg) {
    urlInput.addEventListener("input", () => {
      const check = validateClientUrl(urlInput.value);
      if (!urlInput.value.trim()) {
        urlInput.classList.remove("is-valid", "is-invalid");
        validationMsg.className = "small mb-3 text-secondary";
        validationMsg.innerHTML =
          '<i class="bi bi-github me-1"></i>GitHub (<code>https://github.com/&lt;owner&gt;/&lt;repo&gt;</code>) &bull; <i class="bi bi-cpu me-1"></i>Hugging Face (<code>https://huggingface.co/&lt;owner&gt;/&lt;model&gt;</code>)';
        return;
      }
      if (check.valid) {
        urlInput.classList.remove("is-invalid");
        urlInput.classList.add("is-valid");
        validationMsg.className = "small mb-3 text-success";
        validationMsg.innerHTML = `<i class="bi bi-check-circle me-1"></i>${check.message}`;
      } else {
        urlInput.classList.remove("is-valid");
        urlInput.classList.add("is-invalid");
        validationMsg.className = "small mb-3 text-danger";
        validationMsg.innerHTML = `<i class="bi bi-exclamation-triangle me-1"></i>${check.message}`;
      }
    });
  }

  if (form && urlInput) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const rawUrl = urlInput.value.trim();
      const check = validateClientUrl(rawUrl);

      if (errorAlert) {
        errorAlert.classList.add("d-none");
        errorAlert.textContent = "";
      }

      if (!check.valid) {
        urlInput.classList.add("is-invalid");
        if (errorAlert) {
          errorAlert.textContent = check.message;
          errorAlert.classList.remove("d-none");
        }
        return;
      }

      // Show animated pipeline progress while backend executes real scanners
      const stages = [
        { pct: 15, text: "Acquiring repository metadata and bounded snapshot..." },
        { pct: 32, text: "Running Repository Provenance Analysis..." },
        { pct: 50, text: "Running Bandit Static Code Security Analysis..." },
        { pct: 68, text: "Checking Dependencies via pip-audit & OSV API..." },
        { pct: 84, text: "Scanning Serialization Safety (PickleScan) & Computing SHA-256..." },
        { pct: 95, text: "Generating Syft SBOM, Policy Evaluation & PDF Report..." },
      ];

      let currentStage = 0;
      if (progressBox) progressBox.classList.remove("d-none");
      if (analyzeBtn) {
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Analyzing...';
      }

      function updateStageUI(idx) {
        const st = stages[Math.min(idx, stages.length - 1)];
        if (progressBar) progressBar.style.width = `${st.pct}%`;
        if (scanPercent) scanPercent.textContent = `${st.pct}%`;
        if (stageTitle) stageTitle.textContent = st.text;

        document.querySelectorAll("#scanStagesList [data-stage]").forEach((el) => {
          const sIdx = Number(el.getAttribute("data-stage"));
          const icon = el.querySelector("i");
          if (sIdx < idx) {
            el.classList.remove("text-secondary", "text-primary");
            el.classList.add("text-success");
            if (icon) icon.className = "bi bi-check-circle-fill me-1";
          } else if (sIdx === idx) {
            el.classList.remove("text-secondary", "text-success");
            el.classList.add("text-primary");
            if (icon) icon.className = "bi bi-arrow-right-circle-fill me-1";
          }
        });
      }

      updateStageUI(0);
      const timer = setInterval(() => {
        if (currentStage < stages.length - 1) {
          currentStage += 1;
          updateStageUI(currentStage);
        }
      }, 2500);

      try {
        const resp = await fetch(form.action, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-CSRFToken": form.querySelector('[name="csrf_token"]')?.value || "",
          },
          body: JSON.stringify({ repository_url: rawUrl }),
        });

        clearInterval(timer);
        const data = await resp.json();

        if (!resp.ok || !data.ok) {
          throw new Error(data.error || "Security assessment failed.");
        }

        if (progressBar) progressBar.style.width = "100%";
        if (scanPercent) scanPercent.textContent = "100%";
        if (stageTitle) stageTitle.textContent = `Completed (${data.decision}) — Opening Security Analysis...`;
        window.location.href = data.redirect_url;
      } catch (err) {
        clearInterval(timer);
        if (progressBox) progressBox.classList.add("d-none");
        if (errorAlert) {
          errorAlert.textContent = err.message || "Unexpected error occurred.";
          errorAlert.classList.remove("d-none");
        }
        if (analyzeBtn) {
          analyzeBtn.disabled = false;
          analyzeBtn.innerHTML = '<i class="bi bi-search me-1"></i>Analyze Repository';
        }
      }
    });
  }
});
