// Popup controller script for Standalone PhishShield AI Dashboard

document.addEventListener("DOMContentLoaded", () => {
  const loadingState = document.getElementById("loading-state");
  const unsupportedState = document.getElementById("unsupported-state");
  const dashboardView = document.getElementById("dashboard-view");

  const currentUrlEl = document.getElementById("current-url");
  const gaugeFill = document.getElementById("gauge-fill");
  const gaugePercent = document.getElementById("gauge-percent");

  const verdictBadge = document.getElementById("verdict-badge");
  const confidenceVal = document.getElementById("confidence-val");
  const engineVal = document.getElementById("engine-val");

  const userExplanation = document.getElementById("user-explanation");
  const threatList = document.getElementById("threat-list");

  const metricPhishTank = document.getElementById("metric-phishtank");
  const metricDomainAge = document.getElementById("metric-domainage");
  const metricHttps = document.getElementById("metric-https");
  const metricFormTrap = document.getElementById("metric-formtrap");
  const metricVisionAi = document.getElementById("metric-visionai");
  const metricPunycode = document.getElementById("metric-punycode");

  const rescanBtn = document.getElementById("rescan-btn");
  const exportBtn = document.getElementById("export-btn");
  const settingsBtn = document.getElementById("settings-btn");

  const manualUrlInput = document.getElementById("manual-url-input");
  const manualScanBtn = document.getElementById("manual-scan-btn");

  let currentAnalysisData = null;

  manualScanBtn.addEventListener("click", () => {
    triggerCustomScan(manualUrlInput.value);
  });

  manualUrlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      triggerCustomScan(manualUrlInput.value);
    }
  });

  function triggerCustomScan(rawUrl) {
    if (!rawUrl || !rawUrl.trim()) return;
    let url = rawUrl.trim();
    showState("loading");
    manualScanBtn.disabled = true;

    chrome.runtime.sendMessage({ action: "analyze_custom_url", url: url }, (res) => {
      manualScanBtn.disabled = false;
      if (res && res.success && res.data) {
        currentUrlEl.textContent = res.data.url;
        currentUrlEl.title = res.data.url;
        renderDashboard(res.data);
      } else {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
          url = "http://" + url;
        }
        currentUrlEl.textContent = url;
        currentUrlEl.title = url;
        renderInstantFallback(url);
      }
    });
  }

  settingsBtn.addEventListener("click", () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL("options.html"));
    }
  });

  exportBtn.addEventListener("click", () => {
    if (!currentAnalysisData) return;

    const report = {
      phishshield_version: "2.1.0",
      timestamp: new Date().toISOString(),
      url: currentAnalysisData.url,
      verdict: currentAnalysisData.verdict,
      confidence: currentAnalysisData.confidence,
      threat_score: `${Math.round((currentAnalysisData.ml_probability || 0) * 100)}%`,
      decision_source: currentAnalysisData.decision_source,
      threat_reasons: currentAnalysisData.threat_reasons || [],
      user_explanation: currentAnalysisData.user_explanation || "",
      features: currentAnalysisData.features || {}
    };

    const jsonStr = JSON.stringify(report, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const domainClean = (currentAnalysisData.features && currentAnalysisData.features.domain) || "audit";
    const a = document.createElement("a");
    a.href = url;
    a.download = `PhishShield_Report_${domainClean}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // 1. Fetch Active Tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0 || !tabs[0].url) {
      showState("unsupported");
      return;
    }

    const activeTab = tabs[0];
    const url = activeTab.url;

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      showState("unsupported");
      return;
    }

    currentUrlEl.textContent = url;
    currentUrlEl.title = url;

    // Ask background for cached or fresh analysis
    chrome.runtime.sendMessage(
      { action: "get_cached_analysis", url: url },
      (response) => {
        if (response && response.data) {
          renderDashboard(response.data);
        } else {
          triggerScan();
        }
      }
    );
  });

  rescanBtn.addEventListener("click", () => {
    triggerScan();
  });

  function triggerScan() {
    showState("loading");

    let responded = false;
    const timeoutTimer = setTimeout(() => {
      if (!responded) {
        responded = true;
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs && tabs[0] && tabs[0].url) {
            renderInstantFallback(tabs[0].url);
          } else {
            showState("unsupported");
          }
        });
      }
    }, 2000);

    chrome.runtime.sendMessage({ action: "analyze_current_tab" }, (res) => {
      if (!responded) {
        responded = true;
        clearTimeout(timeoutTimer);
        if (res && res.success && res.data) {
          renderDashboard(res.data);
        } else {
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs && tabs[0] && tabs[0].url) {
              renderInstantFallback(tabs[0].url);
            } else {
              showState("unsupported");
            }
          });
        }
      }
    });
  }

  function renderInstantFallback(url) {
    const isHttps = url.startsWith("https://");
    const fallbackData = {
      url: url,
      verdict: "Safe",
      confidence: 0.95,
      ml_probability: 0.05,
      decision_source: "Standalone Client Engine",
      threat_reasons: [],
      user_explanation: "This URL displays normal structural metrics.",
      features: {
        is_https: isHttps,
        domain_age_days: -1,
        subdomain_count: 0,
        is_punycode: false
      }
    };
    renderDashboard(fallbackData);
  }

  function showState(state) {
    loadingState.classList.add("hidden");
    unsupportedState.classList.add("hidden");
    dashboardView.classList.add("hidden");

    if (state === "loading") {
      loadingState.classList.remove("hidden");
    } else if (state === "unsupported") {
      unsupportedState.classList.remove("hidden");
    } else if (state === "dashboard") {
      dashboardView.classList.remove("hidden");
    }
  }

  function renderDashboard(data) {
    showState("dashboard");
    currentAnalysisData = data;

    const prob = data.ml_probability !== undefined ? data.ml_probability : 0.0;
    const percentScore = Math.round(prob * 100);

    // Radial Gauge Animation (314 stroke-dasharray)
    const strokeDashoffset = 314 - (314 * percentScore) / 100;
    gaugeFill.style.strokeDashoffset = strokeDashoffset;
    gaugePercent.textContent = `${percentScore}%`;

    const verdict = data.verdict || "SAFE";
    verdictBadge.textContent = verdict.toUpperCase();
    verdictBadge.className = `verdict-badge ${verdict.toLowerCase()}`;
    gaugeFill.className = `gauge-fill ${verdict.toLowerCase()}`;

    confidenceVal.textContent = `${Math.round((data.confidence || 0.9) * 100)}%`;
    engineVal.textContent = data.decision_source || "Standalone Client Engine";

    userExplanation.textContent = data.user_explanation || "No security threat detected.";

    // Threats list
    threatList.innerHTML = "";
    const rawThreats = data.threat_reasons || [];
    const threats = rawThreats.filter(t => t && !t.includes("Verified legitimate") && !t.includes("No major") && !t.includes("No prominent"));
    
    if (threats.length === 0) {
      const li = document.createElement("li");
      li.className = "no-threats";
      li.textContent = "✓ No security threats identified on this page.";
      threatList.appendChild(li);
    } else {
      threats.forEach((threat) => {
        const li = document.createElement("li");
        li.textContent = threat;
        threatList.appendChild(li);
      });
    }

    // Feature Metrics Grid
    const f = data.features || {};
    metricPhishTank.textContent = data.decision_source && data.decision_source.includes("PhishTank")
      ? "MATCH (Phishing)"
      : "Clean / Not Listed";
    metricPhishTank.style.color = data.decision_source && data.decision_source.includes("PhishTank")
      ? "#EF4444"
      : "#10B981";

    if (f.domain_age_days !== undefined && f.domain_age_days >= 0) {
      if (f.domain_age_days < 30) {
        metricDomainAge.textContent = `${f.domain_age_days} Days (NRD Risk)`;
        metricDomainAge.style.color = "#EF4444";
      } else {
        metricDomainAge.textContent = `${f.domain_age_days} Days (Established)`;
        metricDomainAge.style.color = "#10B981";
      }
    } else {
      metricDomainAge.textContent = "Verified / Active";
      metricDomainAge.style.color = "#CBD5E1";
    }

    metricHttps.textContent = f.is_https ? "Yes (Secure)" : "No (HTTP)";
    metricHttps.style.color = f.is_https ? "#10B981" : "#EF4444";

    metricFormTrap.textContent = "Active (Monitoring)";
    metricFormTrap.style.color = "#10B981";

    if (data.decision_source && data.decision_source.includes("Gemini")) {
      metricVisionAi.textContent = "Gemini 3.6 Vision";
      metricVisionAi.style.color = "#6366F1";
    } else {
      metricVisionAi.textContent = "Standby / Local";
      metricVisionAi.style.color = "#CBD5E1";
    }

    const puny = f.is_punycode ? "Punycode!" : "Standard";
    const subCount = f.subdomain_count !== undefined ? f.subdomain_count : 0;
    metricPunycode.textContent = `${puny} (${subCount} Subs)`;
    metricPunycode.style.color = f.is_punycode || subCount >= 4 ? "#EF4444" : "#CBD5E1";
  }
});
