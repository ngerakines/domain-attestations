"use strict";
(() => {
  // src/popup.ts
  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }
  function renderStep(step) {
    const iconMap = {
      success: "\u2713",
      failed: "\u2717",
      pending: "\u22EF"
    };
    const icon = iconMap[step.status] ?? "\u2022";
    let detailsHtml = "";
    if (step.details && Object.keys(step.details).length > 0) {
      detailsHtml = '<div class="step-details">';
      detailsHtml += Object.entries(step.details).map(
        ([key, value]) => typeof value === "object" ? `${key}: ${JSON.stringify(value)}` : `${key}: ${escapeHtml(String(value))}`
      ).join("<br>");
      detailsHtml += "</div>";
    }
    return `
    <div class="step ${step.status}">
      <div class="step-icon">${icon}</div>
      <div class="step-content">
        <div class="step-name">${escapeHtml(step.name)}</div>
        ${detailsHtml}
      </div>
      <div class="step-time">+${step.timestamp}ms</div>
    </div>
  `;
  }
  function renderHistoryDetails(item) {
    let html = "";
    if (item.steps && item.steps.length > 0) {
      html += '<div class="detail-section"><h3>Verification Steps</h3>';
      html += '<div class="step-list">';
      html += item.steps.map(renderStep).join("");
      html += "</div></div>";
    }
    if (item.errors && item.errors.length > 0) {
      html += `
      <div class="detail-section">
        <h3>Errors</h3>
        <ul class="error-list">
          ${item.errors.map((err) => `<li>${escapeHtml(err)}</li>`).join("")}
        </ul>
      </div>
    `;
    }
    if (item.details && Object.keys(item.details).length > 0) {
      html += '<div class="detail-section"><h3>Details</h3>';
      for (const [key, value] of Object.entries(item.details)) {
        html += `
        <div class="detail-item">
          <div class="detail-label">${escapeHtml(key)}</div>
          <div class="detail-value">${escapeHtml(String(value))}</div>
        </div>
      `;
      }
      html += "</div>";
    }
    html += renderLinkedDidChecks(item.linkedDidChecks ?? []);
    return html;
  }
  function renderLinkedDidChecks(checks) {
    if (!checks || checks.length === 0)
      return "";
    let html = '<div class="detail-section"><h3>Linked DID Checks</h3>';
    html += '<div class="step-list">';
    for (const check of checks) {
      const iconMap = {
        success: "\u2713",
        failed: "\u2717",
        skipped: "\u22EF"
      };
      const icon = iconMap[check.status] ?? "\u2022";
      const statusClass = check.status === "skipped" ? "pending" : check.status;
      const label = check.relationship === "controller" ? "Controller" : "alsoKnownAs";
      let detailsHtml = "";
      if (check.keyFound !== void 0) {
        detailsHtml += `Key found: ${check.keyFound}<br>`;
      }
      if (check.error) {
        detailsHtml += escapeHtml(check.error);
      }
      html += `
      <div class="step ${statusClass}">
        <div class="step-icon">${icon}</div>
        <div class="step-content">
          <div class="step-name">${escapeHtml(label)}: ${escapeHtml(check.did)}</div>
          ${detailsHtml ? `<div class="step-details">${detailsHtml}</div>` : ""}
        </div>
      </div>
    `;
    }
    html += "</div></div>";
    return html;
  }
  async function displayCurrentResult() {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tabs || tabs.length === 0)
      return;
    const tabId = tabs[0].id;
    const url = tabs[0].url ?? "";
    const statusEl = document.getElementById("status");
    const detailsEl = document.getElementById("details");
    let result;
    try {
      const storage = await browser.storage.local.get(`verification_${tabId}`);
      result = storage[`verification_${tabId}`];
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      statusEl.className = "status failed";
      statusEl.innerHTML = `
      <div class="status-icon">&#x274C;</div>
      <div>
        <div>Error loading verification data</div>
        <div class="url">${escapeHtml(message)}</div>
      </div>
    `;
      detailsEl.innerHTML = "";
      return;
    }
    if (!result) {
      statusEl.className = "status pending";
      statusEl.innerHTML = `
      <div class="status-icon">&#x23F3;</div>
      <div>
        <div>No verification data available</div>
        <div class="url">${escapeHtml(url)}</div>
      </div>
    `;
      detailsEl.innerHTML = "";
      return;
    }
    if (result.verified) {
      statusEl.className = "status verified";
      statusEl.innerHTML = `
      <div class="status-icon">&#x2705;</div>
      <div>
        <div>Signature Verified</div>
        <div class="url">${escapeHtml(result.url)}</div>
      </div>
    `;
    } else {
      statusEl.className = "status failed";
      statusEl.innerHTML = `
      <div class="status-icon">&#x274C;</div>
      <div>
        <div>Verification Failed</div>
        <div class="url">${escapeHtml(result.url)}</div>
      </div>
    `;
    }
    let detailsHtml = "";
    if (result.steps && result.steps.length > 0) {
      detailsHtml += '<div class="detail-section"><h3>Verification Steps</h3>';
      detailsHtml += '<div class="step-list">';
      detailsHtml += result.steps.map(renderStep).join("");
      detailsHtml += "</div></div>";
    }
    if (result.errors && result.errors.length > 0) {
      detailsHtml += `
      <div class="detail-section">
        <h3>Errors</h3>
        <ul class="error-list">
          ${result.errors.map((err) => `<li>${escapeHtml(err)}</li>`).join("")}
        </ul>
      </div>
    `;
    }
    if (result.details && Object.keys(result.details).length > 0) {
      detailsHtml += '<div class="detail-section"><h3>Details</h3>';
      for (const [key, value] of Object.entries(result.details)) {
        detailsHtml += `
        <div class="detail-item">
          <div class="detail-label">${escapeHtml(key)}</div>
          <div class="detail-value">${escapeHtml(String(value))}</div>
        </div>
      `;
      }
      detailsHtml += "</div>";
    }
    detailsHtml += renderLinkedDidChecks(result.linkedDidChecks ?? []);
    if (result.duration) {
      detailsHtml += `
      <div class="detail-section">
        <h3>Performance</h3>
        <div class="detail-item">
          <div class="detail-label">Duration</div>
          <div class="detail-value">${result.duration}ms</div>
        </div>
      </div>
    `;
    }
    detailsEl.innerHTML = detailsHtml;
  }
  async function loadHistory() {
    const historyEl = document.getElementById("history-list");
    let history = [];
    try {
      const storage = await browser.storage.local.get("verification_history");
      history = storage.verification_history ?? [];
    } catch {
      historyEl.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">&#x274C;</div>
        <div>Error loading history</div>
      </div>
    `;
      return;
    }
    if (history.length === 0) {
      historyEl.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">&#x1F4DD;</div>
        <div>No verification history yet</div>
        <div style="margin-top: 8px; font-size: 11px;">
          Navigate to a site with HTTP signatures to see verification details here
        </div>
      </div>
    `;
      return;
    }
    historyEl.innerHTML = history.map((item, index) => {
      const timeStr = new Date(item.timestamp).toLocaleTimeString();
      return `
        <div class="history-item" data-index="${index}">
          <div class="history-header">
            <div class="history-url" title="${escapeHtml(item.url)}">
              ${escapeHtml(item.url)}
            </div>
            <div class="history-meta">
              <span class="history-status ${item.verified ? "verified" : "failed"}">
                ${item.verified ? "&#x2705; Verified" : "&#x274C; Failed"}
              </span>
              <span>${timeStr}</span>
              <span>${item.duration}ms</span>
              <span class="expand-icon">&#x25B6;</span>
            </div>
          </div>
          <div class="history-details">
            ${renderHistoryDetails(item)}
          </div>
        </div>
      `;
    }).join("");
    document.querySelectorAll(".history-header").forEach((header) => {
      header.addEventListener("click", () => {
        header.parentElement.classList.toggle("expanded");
      });
    });
  }
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const tabName = tab.dataset.tab;
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById("current-tab").style.display = tabName === "current" ? "block" : "none";
      document.getElementById("history-tab").style.display = tabName === "history" ? "block" : "none";
      if (tabName === "history") {
        loadHistory();
      }
    });
  });
  document.getElementById("clear-history").addEventListener("click", async () => {
    try {
      await browser.storage.local.set({ verification_history: [] });
      loadHistory();
    } catch (error) {
      console.error("[Popup] Error clearing history:", error);
    }
  });
  var BUILD_ID = typeof __BUILD_ID__ !== "undefined" ? __BUILD_ID__ : "dev";
  document.addEventListener("DOMContentLoaded", () => {
    displayCurrentResult();
    const buildEl = document.getElementById("build-id");
    if (buildEl) {
      buildEl.textContent = `Build: ${BUILD_ID}`;
    }
  });
  browser.runtime.onMessage.addListener((message) => {
    if (message.type === "verification-updated") {
      displayCurrentResult();
    }
  });
})();
