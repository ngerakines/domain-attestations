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
  var BUILD_ID = typeof __BUILD_ID__ !== "undefined" ? __BUILD_ID__ : "dev";
  console.log(`[HTTP Sig] Extension initialized (build: ${BUILD_ID})`);
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
      console.log("[HTTP Sig] JWK for verification:", JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }));
      console.log("[HTTP Sig] Raw signature (P1363, hex):", Array.from(rawSignature).map((b) => b.toString(16).padStart(2, "0")).join(""));
      console.log("[HTTP Sig] Raw signature length:", rawSignature.length);
      const publicKey = await crypto.subtle.importKey(
        "jwk",
        { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
      );
      const messageBytes = new TextEncoder().encode(message);
      console.log("[HTTP Sig] Message to verify length:", messageBytes.length);
      const result = await crypto.subtle.verify(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        publicKey,
        rawSignature.buffer,
        messageBytes
      );
      console.log("[HTTP Sig] crypto.subtle.verify result:", result);
      return result;
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
      try {
        const vmJwk = extractPublicKey(vm);
        const vmThumbprint = await computeJwkThumbprint(vmJwk);
        if (vmThumbprint === targetThumbprint) {
          return vm;
        }
      } catch {
        continue;
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
  async function findKeyInControllers(didDoc, referenceJwk, keyid, addStep) {
    if (!didDoc.controller)
      return null;
    const controllers = Array.isArray(didDoc.controller) ? didDoc.controller : [didDoc.controller];
    for (const controller of controllers) {
      if (controller === didDoc.id)
        continue;
      if (resolveDidToUrl(controller) === null)
        continue;
      try {
        const controllerDoc = await resolveDidDocument(controller);
        if (referenceJwk) {
          const vm = await findVerificationMethodByThumbprint(controllerDoc, referenceJwk);
          if (vm) {
            return { jwk: referenceJwk, controllerDid: controller, methodId: vm.id };
          }
        }
        if (keyid) {
          const vm = findVerificationMethod(controllerDoc, keyid);
          if (vm) {
            return { jwk: extractPublicKey(vm), controllerDid: controller, methodId: vm.id };
          }
        }
      } catch (error) {
        console.log(`[HTTP Sig] Failed to resolve controller ${controller}:`, error);
        continue;
      }
    }
    return null;
  }
  async function checkLinkedDid(did, originDid, referenceJwk, relationship, addStep) {
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
      const keyFound = vm !== void 0;
      if (relationship === "controller") {
        if (keyFound) {
          addStep(stepName, "success", {
            did,
            resolvedId: linkedDoc.id,
            matchingMethod: vm.id
          });
          return { did, relationship, status: "success", keyFound: true };
        }
        addStep(stepName, "failed", {
          did,
          resolvedId: linkedDoc.id,
          availableMethods: linkedDoc.verificationMethod?.map((v) => v.id) ?? []
        });
        return { did, relationship, status: "failed", keyFound: false, error: "Key not found in linked document" };
      }
      const reciprocal = Array.isArray(linkedDoc.alsoKnownAs) && linkedDoc.alsoKnownAs.includes(originDid);
      if (keyFound && reciprocal) {
        addStep(stepName, "success", {
          did,
          resolvedId: linkedDoc.id,
          matchingMethod: vm.id,
          reciprocal: true
        });
        return { did, relationship, status: "success", keyFound: true, reciprocal: true };
      }
      let error;
      if (!keyFound && !reciprocal) {
        error = "Key not found in linked document and linked DID does not claim this DID in alsoKnownAs";
      } else if (!keyFound) {
        error = "Key not found in linked document";
      } else {
        error = "Key found but linked DID does not claim this DID in alsoKnownAs";
      }
      addStep(stepName, "failed", {
        did,
        resolvedId: linkedDoc.id,
        keyFound,
        reciprocal,
        availableMethods: linkedDoc.verificationMethod?.map((v) => v.id) ?? []
      });
      return { did, relationship, status: "failed", keyFound, reciprocal, error };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      addStep(stepName, "failed", { did, error: message });
      return { did, relationship, status: "failed", error: message };
    }
  }
  async function performLinkedDidChecks(didDoc, referenceJwk, addStep, extraDids = []) {
    const checks = [];
    if (didDoc.controller) {
      const controllers = Array.isArray(didDoc.controller) ? didDoc.controller : [didDoc.controller];
      for (const controller of controllers) {
        if (controller === didDoc.id)
          continue;
        checks.push(await checkLinkedDid(controller, didDoc.id, referenceJwk, "controller", addStep));
      }
    }
    if (didDoc.alsoKnownAs) {
      for (const aka of didDoc.alsoKnownAs) {
        if (!aka.startsWith("did:"))
          continue;
        checks.push(await checkLinkedDid(aka, didDoc.id, referenceJwk, "alsoKnownAs", addStep));
      }
    }
    if (didDoc.alsoKnownAs) {
      for (const aka of didDoc.alsoKnownAs) {
        const handle = parseAtHandle(aka);
        if (!handle)
          continue;
        checks.push(await checkLinkedHandle(handle, didDoc.id, addStep));
        break;
      }
    }
    for (const did of extraDids) {
      if (!did.startsWith("did:"))
        continue;
      if (did === didDoc.id)
        continue;
      checks.push(await checkLinkedDid(did, didDoc.id, referenceJwk, "alsoKnownAs", addStep));
    }
    return checks;
  }
  var RESERVED_HANDLE_TLDS = /* @__PURE__ */ new Set([
    "local",
    "arpa",
    "internal",
    "invalid",
    "localhost",
    "onion",
    "example",
    "alt",
    "test"
  ]);
  function parseAtHandle(aka) {
    if (!aka.startsWith("at://"))
      return null;
    const rest = aka.slice("at://".length);
    if (/[/?#@]/.test(rest))
      return null;
    const handle = rest.toLowerCase();
    if (handle.length === 0 || handle.length > 253)
      return null;
    const labels = handle.split(".");
    if (labels.length < 2)
      return null;
    const labelRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
    for (const label of labels) {
      if (label.length < 1 || label.length > 63)
        return null;
      if (!labelRe.test(label))
        return null;
    }
    const tld = labels[labels.length - 1];
    if (RESERVED_HANDLE_TLDS.has(tld))
      return null;
    if (/^[0-9]+$/.test(tld))
      return null;
    return handle;
  }
  async function resolveHandleToDid(handle) {
    const url = `https://${handle}/.well-known/atproto-did`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5e3);
    try {
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} from ${url}`);
      }
      const body = (await response.text()).trim().split(/\s+/)[0] ?? "";
      if (!body.startsWith("did:")) {
        throw new Error(`Response is not a DID: ${body.slice(0, 64)}`);
      }
      return body;
    } finally {
      clearTimeout(timeout);
    }
  }
  async function checkLinkedHandle(handle, originDid, addStep) {
    const stepName = `Resolve handle: at://${handle}`;
    addStep(stepName, "pending", { handle });
    try {
      const resolvedDid = await resolveHandleToDid(handle);
      const matchesOrigin = resolvedDid === originDid;
      if (matchesOrigin) {
        addStep(stepName, "success", { handle, resolvedDid });
        return {
          did: originDid,
          relationship: "handle",
          status: "success",
          handle,
          resolvedDid,
          resolvedVia: "http",
          matchesOrigin: true
        };
      }
      const error = `Handle resolves to ${resolvedDid}, not the origin DID ${originDid}`;
      addStep(stepName, "failed", { handle, resolvedDid, error });
      return {
        did: originDid,
        relationship: "handle",
        status: "failed",
        handle,
        resolvedDid,
        resolvedVia: "http",
        matchesOrigin: false,
        error
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      addStep(stepName, "failed", { handle, error: message });
      return {
        did: originDid,
        relationship: "handle",
        status: "failed",
        handle,
        matchesOrigin: false,
        error: message
      };
    }
  }
  var MAX_CHAIN_DEPTH = 5;
  function didWebHost(did) {
    if (!did.startsWith("did:web:"))
      return null;
    const rest = did.slice("did:web:".length);
    const firstSegment = rest.split(":")[0];
    return decodeURIComponent(firstSegment);
  }
  async function docHoldsKey(doc, jwk) {
    return await findVerificationMethodByThumbprint(doc, jwk) !== void 0;
  }
  async function verifyDomainAnchoring(originHost, keyDid, jwk, originDoc, addStep) {
    const chain = [];
    const startDid = keyDid && keyDid.startsWith("did:web:") ? keyDid : originDoc.id;
    if (didWebHost(startDid) === originHost) {
      const holdsKey = keyDid ? true : await docHoldsKey(originDoc, jwk);
      if (holdsKey) {
        addStep("Domain Anchoring", "success", { via: "direct", originHost, keyDid: startDid });
        return {
          originHost,
          keyDid,
          anchored: true,
          via: "direct",
          chain: [{ did: startDid, host: originHost, holdsKey: true, reciprocal: true }]
        };
      }
    }
    addStep("Domain Anchoring", "pending", { originHost, keyDid: startDid });
    let frontier;
    try {
      const startDoc = startDid === originDoc.id ? originDoc : await resolveDidDocument(startDid);
      frontier = [{ did: startDid, doc: startDoc }];
    } catch (error2) {
      const message = error2 instanceof Error ? error2.message : String(error2);
      const failure = `Cannot resolve key DID ${startDid}: ${message}`;
      addStep("Domain Anchoring", "failed", { error: failure });
      return { originHost, keyDid, anchored: false, via: "none", chain, error: failure };
    }
    const visited = /* @__PURE__ */ new Set([startDid]);
    for (let depth = 0; depth < MAX_CHAIN_DEPTH && frontier.length > 0; depth++) {
      const next = [];
      for (const node of frontier) {
        const akas = Array.isArray(node.doc.alsoKnownAs) ? node.doc.alsoKnownAs : [];
        for (const aka of akas) {
          if (!aka.startsWith("did:web:"))
            continue;
          if (visited.has(aka))
            continue;
          visited.add(aka);
          try {
            const linkedDoc = aka === originDoc.id ? originDoc : await resolveDidDocument(aka);
            const reciprocal = Array.isArray(linkedDoc.alsoKnownAs) && linkedDoc.alsoKnownAs.includes(node.did);
            const holdsKey = await docHoldsKey(linkedDoc, jwk);
            const host = didWebHost(aka);
            chain.push({ did: aka, host, holdsKey, reciprocal });
            if (reciprocal && holdsKey) {
              if (host === originHost) {
                addStep("Domain Anchoring", "success", {
                  via: "chain",
                  originHost,
                  anchorDid: aka,
                  hops: depth + 1
                });
                return { originHost, keyDid, anchored: true, via: "chain", chain };
              }
              next.push({ did: aka, doc: linkedDoc });
            }
          } catch (error2) {
            const message = error2 instanceof Error ? error2.message : String(error2);
            console.log(`[HTTP Sig] Failed to resolve chain member ${aka}:`, message);
            chain.push({ did: aka, host: didWebHost(aka), holdsKey: false, reciprocal: false });
          }
        }
      }
      frontier = next;
    }
    const error = `No bidirectional did:web identity in the chain matches the request origin ${originHost}`;
    addStep("Domain Anchoring", "failed", { originHost, keyDid: startDid, error });
    return { originHost, keyDid, anchored: false, via: "none", chain, error };
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
      console.log("[HTTP Sig] URL:", details.url);
      console.log("[HTTP Sig] Response headers:", JSON.stringify(headers, null, 2));
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
        path: url.pathname,
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
          const controllerResult = await findKeyInControllers(didDoc, jwk, sigParams.keyid, addStep);
          if (controllerResult) {
            addStep("Match Key in DID Document", "success", {
              source: "controller",
              controllerDid: controllerResult.controllerDid,
              methodId: controllerResult.methodId
            });
          } else {
            addStep("Match Key in DID Document", "failed", {
              keyid: sigParams.keyid,
              note: "Signing key not found in DID document or controller documents",
              availableMethods: didDoc.verificationMethod?.map((v) => v.id) ?? []
            });
            result.errors.push(`Signing key ${sigParams.keyid} not found in DID document or controller documents`);
            return result;
          }
        }
      } else {
        let vm = findVerificationMethod(didDoc, sigParams.keyid ?? "");
        let keySource = "origin document";
        if (!vm && sigParams.keyid?.startsWith("did:web:")) {
          const keyDid = sigParams.keyid.split("#")[0];
          try {
            const keyDoc = await resolveDidDocument(keyDid);
            vm = findVerificationMethod(keyDoc, sigParams.keyid);
            if (vm)
              keySource = keyDid;
          } catch (error) {
            console.log(`[HTTP Sig] Failed to resolve key DID ${keyDid}:`, error);
          }
        }
        if (vm) {
          jwk = extractPublicKey(vm);
          addStep("Resolve Signing Key", "success", {
            source: keySource,
            methodId: vm.id,
            type: vm.type,
            keyType: jwk.kty,
            curve: jwk.crv
          });
        } else {
          const controllerResult = await findKeyInControllers(didDoc, null, sigParams.keyid, addStep);
          if (controllerResult) {
            jwk = controllerResult.jwk;
            addStep("Resolve Signing Key", "success", {
              source: "controller",
              controllerDid: controllerResult.controllerDid,
              methodId: controllerResult.methodId,
              keyType: jwk.kty,
              curve: jwk.crv
            });
          } else {
            addStep("Resolve Signing Key", "failed", {
              keyid: sigParams.keyid,
              availableMethods: didDoc.verificationMethod?.map((v) => v.id) ?? []
            });
            result.errors.push(`Verification method not found: ${sigParams.keyid}`);
            return result;
          }
        }
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
      console.log("[HTTP Sig] Signature base:\n" + signatureBase);
      console.log("[HTTP Sig] Component values:", JSON.stringify(componentValues, null, 2));
      console.log("[HTTP Sig] sigParamsValue:", sigParamsValue);
      console.log("[HTTP Sig] Signature base (hex):", Array.from(new TextEncoder().encode(signatureBase)).map((b) => b.toString(16).padStart(2, "0")).join(" "));
      addStep("Build Signature Base", "success", {
        baseLength: signatureBase.length,
        components: sigParams.coveredComponents,
        signatureBase
      });
      addStep("Verify ECDSA P-256 Signature", "pending");
      console.log("[HTTP Sig] Signature bytes (hex):", Array.from(signature).map((b) => b.toString(16).padStart(2, "0")).join(""));
      console.log("[HTTP Sig] Signature length:", signature.length, "first byte:", signature[0]?.toString(16));
      const isValid = await verifyEcdsaSignature(jwk, signature, signatureBase);
      if (isValid) {
        addStep("Verify ECDSA P-256 Signature", "success");
        console.log("[HTTP Sig] Signature verified successfully");
        const keyDid = sigParams.keyid && !sigParams.keyid.startsWith("did:key:") ? sigParams.keyid.split("#")[0] : null;
        const anchoring = await verifyDomainAnchoring(
          requestInfo.authority,
          keyDid,
          jwk,
          didDoc,
          addStep
        );
        result.domainAnchoring = anchoring;
        if (anchoring.anchored) {
          result.verified = true;
          console.log("[HTTP Sig] Signature verified and domain-anchored");
        } else {
          result.verified = false;
          result.errors.push(
            anchoring.error ?? "Signing key identity is not anchored to the request origin domain"
          );
          console.log("[HTTP Sig] Signature valid but not domain-anchored:", anchoring.error);
        }
        try {
          const checkDids = url.searchParams.getAll("check");
          const linkedChecks = await performLinkedDidChecks(
            didDoc,
            jwk,
            addStep,
            checkDids
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
