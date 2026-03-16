"use strict";
(() => {
  // src/background.ts
  var verificationResults = /* @__PURE__ */ new Map();
  var verificationHistory = [];
  var MAX_HISTORY_ITEMS = 50;
  var activeTabId = null;
  var ICONS = {
    default: {
      16: "icons/default-16.png",
      32: "icons/default-32.png",
      48: "icons/default-48.png"
    },
    verified: {
      16: "icons/verified-16.png",
      32: "icons/verified-32.png",
      48: "icons/verified-48.png"
    },
    error: {
      16: "icons/error-16.png",
      32: "icons/error-32.png",
      48: "icons/error-48.png"
    }
  };
  console.log("[HTTP Sig] Extension initialized");
  function parseSignatureInput(signatureInput) {
    const eqIndex = signatureInput.indexOf("=");
    if (eqIndex === -1) {
      throw new Error("Invalid Signature-Input format");
    }
    const signatureName = signatureInput.slice(0, eqIndex);
    const rest = signatureInput.slice(eqIndex + 1);
    let coveredComponents = [];
    const listMatch = rest.match(/^\(([^)]*)\)/);
    if (listMatch) {
      coveredComponents = listMatch[1].split(" ").map((c) => c.replace(/^"|"$/g, "")).filter((c) => c.length > 0);
    }
    const params = { signatureName, coveredComponents };
    const parts = rest.split(";");
    for (let i = 1; i < parts.length; i++) {
      const part = parts[i].trim();
      const sepIndex = part.indexOf("=");
      if (sepIndex === -1)
        continue;
      const key = part.slice(0, sepIndex).trim();
      const value = part.slice(sepIndex + 1).trim().replace(/^"|"$/g, "");
      params[key] = value;
    }
    return params;
  }
  function parseSignature(signature, signatureName) {
    const regex = new RegExp(`${signatureName}=:([^:]+):`);
    const match = signature.match(regex);
    if (!match) {
      throw new Error("Invalid signature format");
    }
    const binaryString = atob(match[1]);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
  function derToRaw(derSig, byteLength = 32) {
    if (derSig[0] !== 48) {
      throw new Error("Invalid DER signature: expected SEQUENCE");
    }
    let offset = 2;
    if (derSig[offset] !== 2) {
      throw new Error("Invalid DER signature: expected INTEGER for r");
    }
    offset++;
    const rLen = derSig[offset];
    offset++;
    let r = derSig.slice(offset, offset + rLen);
    offset += rLen;
    if (derSig[offset] !== 2) {
      throw new Error("Invalid DER signature: expected INTEGER for s");
    }
    offset++;
    const sLen = derSig[offset];
    offset++;
    let s = derSig.slice(offset, offset + sLen);
    if (r.length > byteLength) {
      r = r.slice(r.length - byteLength);
    }
    if (s.length > byteLength) {
      s = s.slice(s.length - byteLength);
    }
    const raw = new Uint8Array(byteLength * 2);
    raw.set(r, byteLength - r.length);
    raw.set(s, byteLength * 2 - s.length);
    return raw;
  }
  function resolveComponent(component, status, headers, requestInfo) {
    switch (component) {
      case "@status":
        return String(status);
      case "@method":
        return requestInfo.method;
      case "@path":
        return requestInfo.path;
      case "@authority":
        return requestInfo.authority;
      default: {
        const value = headers[component.toLowerCase()];
        if (value === void 0) {
          throw new Error(`Header "${component}" not present in response`);
        }
        return value;
      }
    }
  }
  function buildSignatureBase(coveredComponents, componentValues, sigParams) {
    const lines = [];
    for (const component of coveredComponents) {
      const value = componentValues[component];
      if (value === void 0) {
        throw new Error(`Missing value for covered component: ${component}`);
      }
      lines.push(`"${component}": ${value}`);
    }
    lines.push(`"@signature-params": ${sigParams}`);
    return lines.join("\n");
  }
  async function verifyEcdsaSignature(jwk, derSignature, message) {
    try {
      const rawSignature = derToRaw(derSignature, 32);
      const publicKey = await crypto.subtle.importKey(
        "jwk",
        { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
      );
      const messageBytes = new TextEncoder().encode(message);
      return await crypto.subtle.verify(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        publicKey,
        rawSignature.buffer,
        messageBytes
      );
    } catch (error) {
      console.error("[HTTP Sig] ECDSA verification error:", error);
      return false;
    }
  }
  async function fetchDidDocument(origin) {
    const url = `${origin}/.well-known/did.json`;
    console.log("[HTTP Sig] Fetching DID document from:", url);
    const response = await fetch(url, {
      headers: { Accept: "application/json" }
    });
    if (!response.ok) {
      throw new Error(`Failed to fetch DID document: ${response.status}`);
    }
    const didDoc = await response.json();
    console.log("[HTTP Sig] DID document:", didDoc);
    return didDoc;
  }
  function findVerificationMethod(didDoc, keyid) {
    return didDoc.verificationMethod?.find(
      (vm) => vm.id === keyid || vm.id.endsWith(keyid)
    );
  }
  function extractPublicKey(vm) {
    if (vm.publicKeyJwk) {
      return vm.publicKeyJwk;
    }
    throw new Error(
      `Unsupported key format in verification method: ${Object.keys(vm).join(", ")}`
    );
  }
  async function verifyHttpSignature(details) {
    const startTime = Date.now();
    const steps = [];
    const result = {
      url: details.url,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      verified: false,
      errors: [],
      details: {},
      steps
    };
    const addStep = (name, status, info = {}) => {
      steps.push({ name, status, details: info, timestamp: Date.now() - startTime });
    };
    try {
      addStep("Extract Headers", "pending");
      const headers = {};
      for (const header of details.responseHeaders || []) {
        if (header.name && header.value) {
          headers[header.name.toLowerCase()] = header.value;
        }
      }
      addStep("Extract Headers", "success", {
        headerCount: details.responseHeaders?.length ?? 0
      });
      addStep("Check Signature Headers", "pending");
      if (!headers["signature-input"] || !headers["signature"]) {
        addStep("Check Signature Headers", "failed", {
          hasSignatureInput: !!headers["signature-input"],
          hasSignature: !!headers["signature"]
        });
        result.errors.push("Missing Signature or Signature-Input header");
        return result;
      }
      addStep("Check Signature Headers", "success");
      addStep("Parse Signature-Input", "pending");
      const sigParams = parseSignatureInput(headers["signature-input"]);
      result.details.keyid = sigParams.keyid;
      result.details.created = sigParams.created;
      result.details.algorithm = sigParams.alg;
      result.details.coveredComponents = sigParams.coveredComponents.join(", ");
      addStep("Parse Signature-Input", "success", {
        keyid: sigParams.keyid,
        algorithm: sigParams.alg,
        coveredComponents: sigParams.coveredComponents,
        created: sigParams.created ? new Date(parseInt(sigParams.created, 10) * 1e3).toISOString() : "unknown"
      });
      addStep("Validate Algorithm", "pending");
      if (sigParams.alg !== "ecdsa-p256-sha256") {
        addStep("Validate Algorithm", "failed", {
          algorithm: sigParams.alg,
          expected: "ecdsa-p256-sha256"
        });
        result.errors.push(`Unsupported algorithm: ${sigParams.alg}`);
        return result;
      }
      addStep("Validate Algorithm", "success", { algorithm: "ecdsa-p256-sha256" });
      addStep("Parse Signature", "pending");
      const signatureName = sigParams.signatureName || "sig";
      const signature = parseSignature(headers["signature"], signatureName);
      addStep("Parse Signature", "success", {
        signatureLength: signature.length,
        format: "DER/ASN.1"
      });
      addStep("Parse URL Components", "pending");
      const url = new URL(details.url);
      const requestInfo = {
        method: details.method,
        path: url.pathname + url.search,
        authority: url.host,
        origin: url.origin
      };
      addStep("Parse URL Components", "success", {
        method: requestInfo.method,
        path: requestInfo.path,
        authority: requestInfo.authority,
        origin: requestInfo.origin
      });
      addStep("Fetch DID Document", "pending", {
        url: `${requestInfo.origin}/.well-known/did.json`
      });
      const didDoc = await fetchDidDocument(requestInfo.origin);
      result.details.did = didDoc.id;
      addStep("Fetch DID Document", "success", {
        did: didDoc.id,
        verificationMethods: didDoc.verificationMethod?.length ?? 0
      });
      addStep("Find Verification Method", "pending", {
        searchingFor: sigParams.keyid
      });
      const vm = findVerificationMethod(didDoc, sigParams.keyid ?? "");
      if (!vm) {
        addStep("Find Verification Method", "failed", {
          keyid: sigParams.keyid,
          availableMethods: didDoc.verificationMethod?.map((v) => v.id) ?? []
        });
        result.errors.push(`Verification method not found: ${sigParams.keyid}`);
        return result;
      }
      addStep("Find Verification Method", "success", {
        methodId: vm.id,
        type: vm.type
      });
      addStep("Extract Public Key", "pending");
      const jwk = extractPublicKey(vm);
      addStep("Extract Public Key", "success", {
        keyType: jwk.kty,
        curve: jwk.crv
      });
      addStep("Build Signature Base", "pending");
      const componentValues = {};
      for (const component of sigParams.coveredComponents) {
        componentValues[component] = resolveComponent(
          component,
          details.statusCode,
          headers,
          requestInfo
        );
      }
      const sigParamsValue = headers["signature-input"].slice(
        headers["signature-input"].indexOf("=") + 1
      );
      const signatureBase = buildSignatureBase(
        sigParams.coveredComponents,
        componentValues,
        sigParamsValue
      );
      addStep("Build Signature Base", "success", {
        baseLength: signatureBase.length,
        components: sigParams.coveredComponents
      });
      addStep("Verify ECDSA P-256 Signature", "pending");
      const isValid = await verifyEcdsaSignature(jwk, signature, signatureBase);
      if (isValid) {
        addStep("Verify ECDSA P-256 Signature", "success");
        result.verified = true;
        console.log("[HTTP Sig] Signature verified successfully");
      } else {
        addStep("Verify ECDSA P-256 Signature", "failed");
        result.errors.push("Signature verification failed");
        console.log("[HTTP Sig] Signature verification failed");
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const stack = error instanceof Error ? error.stack : void 0;
      addStep("Error", "failed", { message, stack });
      result.errors.push(message);
      console.error("[HTTP Sig] Verification error:", error);
    }
    result.duration = Date.now() - startTime;
    return result;
  }
  function updateIcon(tabId, result) {
    const icon = result.verified ? ICONS.verified : ICONS.error;
    browser.browserAction.setIcon({ tabId, path: icon });
    const title = result.verified ? `Verified: ${result.details.did ?? "Unknown DID"}` : `Failed: ${result.errors.join(", ")}`;
    browser.browserAction.setTitle({ tabId, title });
  }
  browser.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (details.type !== "main_frame")
        return;
      console.log("[HTTP Sig] Processing:", details.url);
      void (async () => {
        const result = await verifyHttpSignature(details);
        verificationResults.set(details.tabId, result);
        verificationHistory.unshift(result);
        if (verificationHistory.length > MAX_HISTORY_ITEMS) {
          verificationHistory.pop();
        }
        try {
          await browser.storage.local.set({
            [`verification_${details.tabId}`]: result,
            verification_history: verificationHistory
          });
        } catch (error) {
          console.error("[HTTP Sig] Error storing to browser.storage:", error);
        }
        updateIcon(details.tabId, result);
      })();
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
  );
  browser.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
      browser.browserAction.setIcon({ tabId: details.tabId, path: ICONS.default });
      browser.browserAction.setTitle({
        tabId: details.tabId,
        title: "DID HTTP Signature Verifier"
      });
    }
  });
  browser.tabs.onActivated.addListener((activeInfo) => {
    activeTabId = activeInfo.tabId;
  });
  browser.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === "get-verification-result") {
      sendResponse(verificationResults.get(message.tabId));
    } else if (message.type === "get-verification-history") {
      sendResponse({ history: verificationHistory });
    } else if (message.type === "clear-history") {
      verificationHistory.length = 0;
      browser.storage.local.set({ verification_history: [] }).catch(
        (err) => console.error("[HTTP Sig] Error clearing storage:", err)
      );
      sendResponse({ success: true });
    }
    return true;
  });
  console.log("[HTTP Sig] Extension ready");
})();
