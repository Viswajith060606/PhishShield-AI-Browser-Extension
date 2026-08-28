// Content script for DOM security scraping, input interception, & security banners

(function () {
  let isPageMalicious = false;

  // Extract security-relevant DOM metrics
  function getDomContext() {
    const title = document.title || "";
    
    const forms = Array.from(document.querySelectorAll("form"));
    const formActions = forms.map((f) => {
      try {
        return new URL(f.action || "", window.location.href).href;
      } catch (e) {
        return f.action || "";
      }
    });

    const passwordFields = document.querySelectorAll('input[type="password"]');

    const scripts = Array.from(document.querySelectorAll("script[src]"));
    const externalScripts = scripts.filter((s) => {
      try {
        const srcUrl = new URL(s.src, window.location.href);
        return srcUrl.hostname !== window.location.hostname;
      } catch (e) {
        return false;
      }
    });

    const inputElements = Array.from(document.querySelectorAll("input"));
    let sensitiveInputsCount = 0;
    const sensitiveRegex = /user|login|email|pass|ssn|card|credit|bank|account|pin|verify/i;
    
    inputElements.forEach((input) => {
      const name = input.name || "";
      const id = input.id || "";
      const placeholder = input.placeholder || "";
      if (sensitiveRegex.test(name) || sensitiveRegex.test(id) || sensitiveRegex.test(placeholder)) {
        sensitiveInputsCount++;
      }
    });

    const iframes = document.querySelectorAll("iframe");

    return {
      title: title,
      forms_count: forms.length,
      form_actions: formActions.slice(0, 5),
      password_fields_count: passwordFields.length,
      external_scripts_count: externalScripts.length,
      sensitive_inputs_count: sensitiveInputsCount,
      iframe_count: iframes.length,
      protocol: window.location.protocol,
      hostname: window.location.hostname
    };
  }

  // Real-Time Password Field & Form Target Interceptor
  function initPasswordFieldInterceptor() {
    document.addEventListener("focusin", (event) => {
      const target = event.target;
      if (!target || target.tagName !== "INPUT") return;

      const isPassword = target.type === "password";
      const isInsecureHttp = window.location.protocol === "http:";

      if ((isPassword || isInsecureHttp) && (isInsecureHttp || isPageMalicious)) {
        showInlineInputWarning(target);
      }
    });
  }

  function showInlineInputWarning(inputEl) {
    if (inputEl.dataset.phishshieldWarningInjected) return;
    inputEl.dataset.phishshieldWarningInjected = "true";

    inputEl.style.border = "2px solid #EF4444 !important";
    inputEl.style.boxShadow = "0 0 10px rgba(239, 68, 68, 0.5) !important";

    const badge = document.createElement("div");
    badge.className = "phishshield-input-warning";
    badge.style.cssText = `
      display: inline-flex !important;
      align-items: center !important;
      gap: 6px !important;
      background: #7F1D1D !important;
      color: #FECACA !important;
      border: 1px solid #EF4444 !important;
      border-radius: 6px !important;
      padding: 4px 8px !important;
      font-size: 11px !important;
      font-weight: 600 !important;
      font-family: -apple-system, sans-serif !important;
      margin-top: 4px !important;
      margin-bottom: 4px !important;
      box-shadow: 0 4px 10px rgba(0,0,0,0.3) !important;
      z-index: 2147483646 !important;
    `;
    badge.innerHTML = `⚠️ <span>PhishShield Alert: Unverified Login Field</span>`;

    if (inputEl.parentNode) {
      inputEl.parentNode.insertBefore(badge, inputEl.nextSibling);
    }
  }

  // Inject security warning banner overlay for malicious pages
  function injectSecurityBanner(alertData) {
    isPageMalicious = true;

    if (document.getElementById("phishshield-security-banner")) return;

    const banner = document.createElement("div");
    banner.id = "phishshield-security-banner";
    banner.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      z-index: 2147483647 !important;
      background: linear-gradient(135deg, #1E1B4B 0%, #0F172A 100%) !important;
      border-bottom: 3px solid #EF4444 !important;
      color: #F8FAFC !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      box-shadow: 0 10px 25px -5px rgba(239, 68, 68, 0.5) !important;
      padding: 16px 24px !important;
      box-sizing: border-box !important;
      animation: phishShieldSlideDown 0.4s ease-out !important;
    `;

    const reasonsList = (alertData.threat_reasons || [])
      .map((r) => `<li style="margin-bottom: 4px;">⚠️ ${escapeHtml(r)}</li>`)
      .join("");

    banner.innerHTML = `
      <style>
        @keyframes phishShieldSlideDown {
          from { transform: translateY(-100%); }
          to { transform: translateY(0); }
        }
        .ps-banner-container {
          max-width: 1200px;
          margin: 0 auto;
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          gap: 20px;
        }
        .ps-banner-content {
          display: flex;
          align-items: flex-start;
          gap: 16px;
        }
        .ps-banner-icon {
          background: rgba(239, 68, 68, 0.2);
          border: 1px solid rgba(239, 68, 68, 0.4);
          border-radius: 50%;
          width: 44px;
          height: 44px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 24px;
          flex-shrink: 0;
        }
        .ps-banner-title {
          font-size: 16px;
          font-weight: 700;
          color: #EF4444;
          letter-spacing: 0.5px;
          margin: 0 0 4px 0;
          text-transform: uppercase;
        }
        .ps-banner-desc {
          font-size: 13px;
          color: #CBD5E1;
          margin: 0 0 8px 0;
          line-height: 1.4;
        }
        .ps-banner-reasons {
          margin: 0;
          padding-left: 18px;
          font-size: 12px;
          color: #F87171;
        }
        .ps-banner-actions {
          display: flex;
          gap: 10px;
          align-items: center;
          flex-shrink: 0;
        }
        .ps-btn-leave {
          background: #EF4444;
          color: white;
          border: none;
          padding: 8px 16px;
          border-radius: 6px;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s;
        }
        .ps-btn-leave:hover {
          background: #DC2626;
        }
        .ps-btn-dismiss {
          background: rgba(255, 255, 255, 0.1);
          color: #94A3B8;
          border: 1px solid rgba(255, 255, 255, 0.2);
          padding: 8px 14px;
          border-radius: 6px;
          font-size: 13px;
          cursor: pointer;
        }
        .ps-btn-dismiss:hover {
          background: rgba(255, 255, 255, 0.2);
          color: white;
        }
      </style>
      <div class="ps-banner-container">
        <div class="ps-banner-content">
          <div class="ps-banner-icon">🛡️</div>
          <div>
            <div class="ps-banner-title">PhishShield Alert: High-Risk Phishing Website</div>
            <div class="ps-banner-desc">${escapeHtml(alertData.user_explanation || "This website shows critical indicators of phishing.")}</div>
            <ul class="ps-banner-reasons">${reasonsList}</ul>
          </div>
        </div>
        <div class="ps-banner-actions">
          <button id="ps-leave-btn" class="ps-btn-leave">Get Me Out of Here</button>
          <button id="ps-dismiss-btn" class="ps-btn-dismiss">Ignore Warning</button>
        </div>
      </div>
    `;

    document.body.prepend(banner);

    document.getElementById("ps-leave-btn").addEventListener("click", () => {
      window.location.href = "about:blank";
    });

    document.getElementById("ps-dismiss-btn").addEventListener("click", () => {
      banner.remove();
    });
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Dynamic Form Submission Interceptor & Trap Engine
  function initFormSubmissionTrap() {
    document.addEventListener("submit", (event) => {
      const form = event.target;
      if (!form || form.tagName !== "FORM") return;

      let targetUrl;
      try {
        targetUrl = new URL(form.action || "", window.location.href);
      } catch (e) {
        return;
      }

      const currentHost = window.location.hostname.toLowerCase();
      const targetHost = targetUrl.hostname.toLowerCase();
      const isCrossDomain = targetHost && currentHost && !targetHost.endsWith(currentHost) && !currentHost.endsWith(targetHost);
      const isInsecureTarget = targetUrl.protocol === "http:";

      // Check if form contains sensitive credentials
      const hasPassword = form.querySelector('input[type="password"]') !== null;
      const inputs = Array.from(form.querySelectorAll("input"));
      const sensitiveRegex = /user|login|email|pass|ssn|card|credit|bank|account|pin|verify/i;
      const hasSensitiveInput = inputs.some((input) => sensitiveRegex.test(input.name || "") || sensitiveRegex.test(input.id || ""));

      if ((hasPassword || hasSensitiveInput) && (isCrossDomain || isInsecureTarget || isPageMalicious)) {
        event.preventDefault();
        event.stopPropagation();
        showFormTrapModal(form, targetUrl.href, isCrossDomain, isInsecureTarget);
      }
    }, true);
  }

  function showFormTrapModal(form, targetHref, isCrossDomain, isInsecureTarget) {
    if (document.getElementById("phishshield-form-trap-modal")) return;

    const modal = document.createElement("div");
    modal.id = "phishshield-form-trap-modal";
    modal.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100vw !important;
      height: 100vh !important;
      background: rgba(11, 15, 25, 0.85) !important;
      backdrop-filter: blur(8px) !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    `;

    modal.innerHTML = `
      <div style="
        background: #1E1B4B;
        border: 2px solid #EF4444;
        border-radius: 12px;
        padding: 24px;
        max-width: 480px;
        width: 90%;
        color: #F8FAFC;
        box-shadow: 0 20px 40px rgba(0,0,0,0.6);
      ">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
          <span style="font-size: 28px;">🚨</span>
          <h2 style="font-size: 18px; font-weight: 700; color: #EF4444; margin: 0;">PhishShield Trap Alert</h2>
        </div>
        <p style="font-size: 13px; color: #CBD5E1; line-height: 1.5; margin-bottom: 14px;">
          <strong>Warning:</strong> You are submitting sensitive login credentials!
        </p>
        <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(255,255,255,0.1); padding: 10px; border-radius: 8px; font-size: 12px; margin-bottom: 16px;">
          <div><strong>Current Host:</strong> ${escapeHtml(window.location.hostname)}</div>
          <div style="color: #F87171;"><strong>Target Action Host:</strong> ${escapeHtml(targetHref)}</div>
          ${isCrossDomain ? `<div style="color: #F87171; margin-top: 4px;">⚠️ Target domain does not match current site!</div>` : ""}
          ${isInsecureTarget ? `<div style="color: #F87171; margin-top: 4px;">⚠️ Action endpoint is unencrypted HTTP!</div>` : ""}
        </div>
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
          <button id="ps-trap-cancel" style="background: #EF4444; color: white; border: none; padding: 10px 16px; border-radius: 6px; font-weight: 600; cursor: pointer;">
            Block Submission (Recommended)
          </button>
          <button id="ps-trap-proceed" style="background: rgba(255,255,255,0.1); color: #CBD5E1; border: 1px solid rgba(255,255,255,0.2); padding: 10px 14px; border-radius: 6px; cursor: pointer;">
            Proceed Anyway
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    document.getElementById("ps-trap-cancel").addEventListener("click", () => {
      modal.remove();
    });

    document.getElementById("ps-trap-proceed").addEventListener("click", () => {
      modal.remove();
      form.submit();
    });
  }

  initPasswordFieldInterceptor();
  initFormSubmissionTrap();

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "get_dom_context") {
      sendResponse(getDomContext());
      return true;
    }

    if (request.action === "show_security_alert") {
      injectSecurityBanner(request.data);
      sendResponse({ status: "alert_displayed" });
      return true;
    }
  });
})();
