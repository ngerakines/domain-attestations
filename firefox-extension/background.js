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
  function uint8ArrayToBase64url(bytes) {
    let binary = "";
    for (const b of bytes) {
      binary += String.fromCharCode(b);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  function base58btcDecode(input) {
    const alphabetMap = /* @__PURE__ */ new Map();
    for (let i = 0; i < BASE58_ALPHABET.length; i++) {
      alphabetMap.set(BASE58_ALPHABET[i], i);
    }
    let value = 0n;
    for (const char of input) {
      const digit = alphabetMap.get(char);
      if (digit === void 0) {
        throw new Error(`Invalid base58 character: ${char}`);
      }
      value = value * 58n + BigInt(digit);
    }
    const bytes = [];
    while (value > 0n) {
      bytes.unshift(Number(value & 0xffn));
      value >>= 8n;
    }
    for (const char of input) {
      if (char !== "1")
        break;
      bytes.unshift(0);
    }
    return new Uint8Array(bytes);
  }
  function decompressP256Point(compressed) {
    if (compressed.length !== 33) {
      throw new Error(`Expected 33-byte compressed key, got ${compressed.length}`);
    }
    const prefix = compressed[0];
    if (prefix !== 2 && prefix !== 3) {
      throw new Error(`Invalid compression prefix: 0x${prefix.toString(16)}`);
    }
    const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
    const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
    const a = p - 3n;
    let xBig = 0n;
    for (let i = 1; i < 33; i++) {
      xBig = xBig << 8n | BigInt(compressed[i]);
    }
    const x3 = modPow(xBig, 3n, p);
    const ySquared = ((x3 + a * xBig + b) % p + p) % p;
    const yCandidate = modPow(ySquared, (p + 1n) / 4n, p);
    const isEven = (yCandidate & 1n) === 0n;
    const wantEven = prefix === 2;
    const yBig = isEven === wantEven ? yCandidate : p - yCandidate;
    return {
      x: bigIntToUint8Array(xBig, 32),
      y: bigIntToUint8Array(yBig, 32)
    };
  }
  function modPow(base, exp, m) {
    let result = 1n;
    base = (base % m + m) % m;
    while (exp > 0n) {
      if (exp & 1n) {
        result = result * base % m;
      }
      exp >>= 1n;
      base = base * base % m;
    }
    return result;
  }
  function bigIntToUint8Array(value, length) {
    const result = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
      result[i] = Number(value & 0xffn);
      value >>= 8n;
    }
    return result;
  }
  function resolveDidKey(didKey) {
    const multibaseValue = didKey.startsWith("did:key:") ? didKey.slice("did:key:".length) : didKey;
    if (multibaseValue[0] !== "z") {
      throw new Error("Expected base58btc multibase prefix 'z'");
    }
    const decoded = base58btcDecode(multibaseValue.slice(1));
    if (decoded.length < 3) {
      throw new Error("Decoded key data too short");
    }
    if (decoded[0] !== 128 || decoded[1] !== 36) {
      throw new Error(
        `Unsupported multicodec prefix: 0x${decoded[0].toString(16)}${decoded[1].toString(16)}`
      );
    }
    const compressedKey = decoded.slice(2);
    const { x, y } = decompressP256Point(compressedKey);
    return {
      kty: "EC",
      crv: "P-256",
      x: uint8ArrayToBase64url(x),
      y: uint8ArrayToBase64url(y)
    };
  }
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
  async function verifyEcdsaSignature(jwk, signatureBytes, message) {
    try {
      let rawSignature;
      if (signatureBytes[0] === 48) {
        rawSignature = derToRaw(signatureBytes, 32);
      } else if (signatureBytes.length === 64) {
        rawSignature = signatureBytes;
      } else {
        throw new Error(
          `Unknown signature format: length=${signatureBytes.length}, first byte=0x${signatureBytes[0].toString(16)}`
        );
      }
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
  async function computeJwkThumbprint(jwk) {
    const canonical = JSON.stringify({
      crv: jwk.crv,
      kty: jwk.kty,
      x: jwk.x,
      y: jwk.y
    });
    const data = new TextEncoder().encode(canonical);
    const hash = await crypto.subtle.digest("SHA-256", data);
    const bytes = new Uint8Array(hash);
    let binary = "";
    for (const b of bytes) {
      binary += String.fromCharCode(b);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  async function findVerificationMethodByThumbprint(didDoc, referenceJwk) {
    if (!didDoc.verificationMethod)
      return void 0;
    const targetThumbprint = await computeJwkThumbprint(referenceJwk);
    for (const vm of didDoc.verificationMethod) {
      if (!vm.publicKeyJwk)
        continue;
      const vmThumbprint = await computeJwkThumbprint(vm.publicKeyJwk);
      if (vmThumbprint === targetThumbprint) {
        return vm;
      }
    }
    return void 0;
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
    if (vm.publicKeyMultibase) {
      const value = vm.publicKeyMultibase;
      if (value.startsWith("did:key:")) {
        return resolveDidKey(value);
      }
      return resolveDidKey(`did:key:${value}`);
    }
    throw new Error(
      `Unsupported key format in verification method: ${Object.keys(vm).join(", ")}`
    );
  }
  function resolveDidToUrl(did) {
    if (did.startsWith("did:web:")) {
      const rest = did.slice("did:web:".length);
      const parts = rest.split(":");
      const host = decodeURIComponent(parts[0]);
      if (parts.length === 1) {
        return `https://${host}/.well-known/did.json`;
      }
      const path = parts.slice(1).join("/");
      return `https://${host}/${path}/did.json`;
    }
    if (did.startsWith("did:plc:")) {
      return `https://plc.directory/${did}`;
    }
    if (did.startsWith("did:key:")) {
      return null;
    }
    return null;
  }
  async function resolveDidDocument(did) {
    const url = resolveDidToUrl(did);
    if (!url) {
      throw new Error(`Cannot resolve DID: ${did}`);
    }
    console.log("[HTTP Sig] Resolving DID document:", did, "\u2192", url);
    const response = await fetch(url, {
      headers: { Accept: "application/json" }
    });
    if (!response.ok) {
      throw new Error(`Failed to resolve ${did}: HTTP ${response.status}`);
    }
    return await response.json();
  }
  async function checkLinkedDid(did, referenceJwk, relationship, addStep) {
    const label = relationship === "controller" ? "Controller" : "alsoKnownAs";
    const stepName = `Resolve ${label}: ${did}`;
    if (resolveDidToUrl(did) === null) {
      addStep(stepName, "success", { skipped: true, reason: "Self-describing DID method" });
      return { did, relationship, status: "skipped", error: "Self-describing DID method (no document to fetch)" };
    }
    addStep(stepName, "pending", { did });
    try {
      const linkedDoc = await resolveDidDocument(did);
      const vm = await findVerificationMethodByThumbprint(linkedDoc, referenceJwk);
      if (vm) {
        addStep(stepName, "success", {
          did,
          resolvedId: linkedDoc.id,
          matchingMethod: vm.id
        });
        return { did, relationship, status: "success", keyFound: true };
      } else {
        addStep(stepName, "failed", {
          did,
          resolvedId: linkedDoc.id,
          availableMethods: linkedDoc.verificationMethod?.map((v) => v.id) ?? []
        });
        return { did, relationship, status: "failed", keyFound: false, error: "Key not found in linked document" };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      addStep(stepName, "failed", { did, error: message });
      return { did, relationship, status: "failed", error: message };
    }
  }
  async function performLinkedDidChecks(didDoc, referenceJwk, addStep) {
    const checks = [];
    if (didDoc.controller) {
      const controllers = Array.isArray(didDoc.controller) ? didDoc.controller : [didDoc.controller];
      for (const controller of controllers) {
        if (controller === didDoc.id)
          continue;
        checks.push(await checkLinkedDid(controller, referenceJwk, "controller", addStep));
      }
    }
    if (didDoc.alsoKnownAs) {
      for (const aka of didDoc.alsoKnownAs) {
        if (!aka.startsWith("did:"))
          continue;
        checks.push(await checkLinkedDid(aka, referenceJwk, "alsoKnownAs", addStep));
      }
    }
    return checks;
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
      result.details.coveredComponents = sigParams.coveredComponents.join(", ");
      addStep("Parse Signature-Input", "success", {
        keyid: sigParams.keyid,
        algorithm: sigParams.alg,
        coveredComponents: sigParams.coveredComponents,
        created: sigParams.created ? new Date(parseInt(sigParams.created, 10) * 1e3).toISOString() : "unknown"
      });
      addStep("Validate Algorithm", "pending");
      let effectiveAlg = sigParams.alg;
      if (!effectiveAlg && sigParams.keyid?.startsWith("did:key:")) {
        try {
          const keyJwk = resolveDidKey(sigParams.keyid);
          if (keyJwk.crv === "P-256") {
            effectiveAlg = "ecdsa-p256-sha256";
          }
        } catch {
        }
      }
      if (effectiveAlg !== "ecdsa-p256-sha256") {
        addStep("Validate Algorithm", "failed", {
          algorithm: effectiveAlg ?? sigParams.alg,
          expected: "ecdsa-p256-sha256"
        });
        result.errors.push(`Unsupported algorithm: ${effectiveAlg ?? sigParams.alg}`);
        return result;
      }
      result.details.algorithm = effectiveAlg;
      addStep("Validate Algorithm", "success", {
        algorithm: "ecdsa-p256-sha256",
        inferred: !sigParams.alg
      });
      addStep("Parse Signature", "pending");
      const signatureName = sigParams.signatureName || "sig";
      const signature = parseSignature(headers["signature"], signatureName);
      const sigFormat = signature[0] === 48 ? "DER/ASN.1" : signature.length === 64 ? "IEEE P1363" : "unknown";
      addStep("Parse Signature", "success", {
        signatureLength: signature.length,
        format: sigFormat
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
      addStep("Resolve Signing Key", "pending", { keyid: sigParams.keyid });
      let jwk;
      if (sigParams.keyid?.startsWith("did:key:")) {
        jwk = resolveDidKey(sigParams.keyid);
        addStep("Resolve Signing Key", "success", {
          source: "did:key",
          keyType: jwk.kty,
          curve: jwk.crv
        });
        addStep("Match Key in DID Document", "pending");
        let matchedVm = await findVerificationMethodByThumbprint(didDoc, jwk);
        if (!matchedVm) {
          for (const vm of didDoc.verificationMethod ?? []) {
            if (!vm.publicKeyMultibase)
              continue;
            try {
              const vmJwk = extractPublicKey(vm);
              const vmThumb = await computeJwkThumbprint(vmJwk);
              const keyThumb = await computeJwkThumbprint(jwk);
              if (vmThumb === keyThumb) {
                matchedVm = vm;
                break;
              }
            } catch {
              continue;
            }
          }
        }
        if (matchedVm) {
          addStep("Match Key in DID Document", "success", { methodId: matchedVm.id });
        } else {
          addStep("Match Key in DID Document", "success", {
            keyid: sigParams.keyid,
            note: "Signing key not in DID document (did:key is self-authenticating)",
            availableMethods: didDoc.verificationMethod?.map((v) => v.id) ?? []
          });
        }
      } else {
        const vm = findVerificationMethod(didDoc, sigParams.keyid ?? "");
        if (!vm) {
          addStep("Resolve Signing Key", "failed", {
            keyid: sigParams.keyid,
            availableMethods: didDoc.verificationMethod?.map((v) => v.id) ?? []
          });
          result.errors.push(`Verification method not found: ${sigParams.keyid}`);
          return result;
        }
        jwk = extractPublicKey(vm);
        addStep("Resolve Signing Key", "success", {
          methodId: vm.id,
          type: vm.type,
          keyType: jwk.kty,
          curve: jwk.crv
        });
      }
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
        try {
          const linkedChecks = await performLinkedDidChecks(
            didDoc,
            jwk,
            addStep
          );
          if (linkedChecks.length > 0) {
            result.linkedDidChecks = linkedChecks;
          }
        } catch (error) {
          const msg = error instanceof Error ? error.message : String(error);
          addStep("Linked DID Checks", "failed", { error: msg });
        }
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
