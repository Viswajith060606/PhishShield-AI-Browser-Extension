// Options JS controller script

document.addEventListener("DOMContentLoaded", () => {
  const geminiKeyInput = document.getElementById("gemini-key");
  const phishtankToggle = document.getElementById("phishtank-toggle");
  const customWhitelistInput = document.getElementById("custom-whitelist");
  const customBlacklistInput = document.getElementById("custom-blacklist");
  const saveBtn = document.getElementById("save-btn");
  const testBtn = document.getElementById("test-btn");
  const toast = document.getElementById("toast");
  const testStatus = document.getElementById("test-status");

  // Load existing settings
  chrome.storage.local.get(
    ["geminiApiKey", "enablePhishTank", "customWhitelist", "customBlacklist"],
    (res) => {
      if (res.geminiApiKey) geminiKeyInput.value = res.geminiApiKey;
      if (res.enablePhishTank !== undefined) phishtankToggle.checked = res.enablePhishTank;
      if (res.customWhitelist) customWhitelistInput.value = res.customWhitelist.join(", ");
      if (res.customBlacklist) customBlacklistInput.value = res.customBlacklist.join(", ");
    }
  );

  saveBtn.addEventListener("click", () => {
    const key = geminiKeyInput.value.trim();
    const enablePT = phishtankToggle.checked;

    const whitelist = customWhitelistInput.value
      .split(/[\n,]+/)
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);

    const blacklist = customBlacklistInput.value
      .split(/[\n,]+/)
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);

    chrome.storage.local.set(
      {
        geminiApiKey: key,
        enablePhishTank: enablePT,
        customWhitelist: whitelist,
        customBlacklist: blacklist
      },
      () => {
        showToast(toast, "All settings & custom domain rules saved!", "success");
      }
    );
  });

  testBtn.addEventListener("click", async () => {
    const key = geminiKeyInput.value.trim();
    if (!key) {
      showToast(testStatus, "Please enter a Gemini API Key first.", "error");
      return;
    }

    testBtn.disabled = true;
    testBtn.textContent = "Testing...";
    showToast(testStatus, "Testing Gemini API key connection...", "success");

    try {
      const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key=${key}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: "Hello" }] }]
        })
      });

      if (res.ok) {
        showToast(testStatus, "Gemini API connection verified successfully!", "success");
      } else {
        const errJson = await res.json().catch(() => ({}));
        const msg = errJson.error ? errJson.error.message : `API returned HTTP ${res.status}`;
        showToast(testStatus, `Connection error: ${msg}`, "error");
      }
    } catch (e) {
      showToast(testStatus, `Connection failed: ${e.message}`, "error");
    } finally {
      testBtn.disabled = false;
      testBtn.textContent = "Test Connection";
    }
  });

  function showToast(targetEl, msg, type) {
    if (!targetEl) return;
    targetEl.textContent = msg;
    targetEl.className = `toast ${type}`;
    targetEl.style.display = "block";
    setTimeout(() => {
      targetEl.style.display = "none";
    }, 5000);
  }
});

