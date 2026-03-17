/**
 * DID HTTP Signature Verifier - Firefox Extension
 *
 * Verifies RFC 9421 HTTP Message Signatures on did:web DID documents
 * using ECDSA P-256 with SHA-256.
 *
 * Compatible with signatures produced by server-py and caddy-httpsig
 * from the domain-attestations project.
 */

// ── Types ──────────────────────────────────────────────────────────

interface IconPaths {
  [size: number]: string;
}

/** Parsed fields from a Signature-Input header. */
interface SignatureParams {
  signatureName: string;
  coveredComponents: string[];
  keyid?: string;
  created?: string;
  alg?: string;
  [key: string]: string | string[] | undefined;
}

/** Request metadata needed to resolve derived components. */
interface HttpRequestInfo {
  method: string;
  path: string;
  authority: string;
  origin: string;
}

/** A single step recorded during signature verification. */
interface VerificationStep {
  name: string;
  status: "pending" | "success" | "failed";
  details: Record<string, unknown>;
  timestamp: number;
}

/** The full result of verifying an HTTP signature. */
interface VerificationResult {
  url: string;
  timestamp: string;
  verified: boolean;
  errors: string[];
  details: Record<string, string | undefined>;
  steps: VerificationStep[];
  duration?: number;
  linkedDidChecks?: LinkedDidCheck[];
}

/** Subset of a JWK representing an EC public key. */
interface EcPublicJwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
}

/** A verification method entry in a DID document. */
interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: EcPublicJwk;
}

/** Minimal shape of a DID document we need for verification. */
interface DidDocument {
  id: string;
  controller?: string | string[];
  alsoKnownAs?: string[];
  verificationMethod?: VerificationMethod[];
}

/** Result of resolving and checking a linked DID (controller or alsoKnownAs). */
interface LinkedDidCheck {
  did: string;
  relationship: "controller" | "alsoKnownAs";
  status: "success" | "failed" | "skipped";
  error?: string;
  keyFound?: boolean;
}

// ── State ──────────────────────────────────────────────────────────

const verificationResults = new Map<number, VerificationResult>();
const verificationHistory: VerificationResult[] = [];
const MAX_HISTORY_ITEMS = 50;
let activeTabId: number | null = null;

const ICONS: Record<string, IconPaths> = {
  default: {
    16: "icons/default-16.png",
    32: "icons/default-32.png",
    48: "icons/default-48.png",
  },
  verified: {
    16: "icons/verified-16.png",
    32: "icons/verified-32.png",
    48: "icons/verified-48.png",
  },
  error: {
    16: "icons/error-16.png",
    32: "icons/error-32.png",
    48: "icons/error-48.png",
  },
};

console.log("[HTTP Sig] Extension initialized");

// ── RFC 9421 Parsing ───────────────────────────────────────────────

/**
 * Parse a Signature-Input header value per RFC 9421.
 *
 * Example input:
 *   sig=("@status" "content-type");created=1700000000;keyid="default";alg="ecdsa-p256-sha256"
 */
function parseSignatureInput(signatureInput: string): SignatureParams {
  const eqIndex = signatureInput.indexOf("=");
  if (eqIndex === -1) {
    throw new Error("Invalid Signature-Input format");
  }

  const signatureName = signatureInput.slice(0, eqIndex);
  const rest = signatureInput.slice(eqIndex + 1);

  // Extract covered components from the inner list (...)
  let coveredComponents: string[] = [];
  const listMatch = rest.match(/^\(([^)]*)\)/);
  if (listMatch) {
    coveredComponents = listMatch[1]
      .split(" ")
      .map((c) => c.replace(/^"|"$/g, ""))
      .filter((c) => c.length > 0);
  }

  // Extract semicolon-delimited parameters
  const params: SignatureParams = { signatureName, coveredComponents };
  const parts = rest.split(";");
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i].trim();
    const sepIndex = part.indexOf("=");
    if (sepIndex === -1) continue;
    const key = part.slice(0, sepIndex).trim();
    const value = part.slice(sepIndex + 1).trim().replace(/^"|"$/g, "");
    params[key] = value;
  }

  return params;
}

/**
 * Parse a Signature header value per RFC 9421.
 *
 * Example input:  sig=:<base64>:
 *
 * Returns the raw DER-encoded signature bytes.
 */
function parseSignature(
  signature: string,
  signatureName: string,
): Uint8Array {
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

// ── DER / ASN.1 ────────────────────────────────────────────────────

/**
 * Convert a DER/ASN.1 encoded ECDSA signature to raw IEEE P1363 format
 * (r || s, each `byteLength` bytes, zero-padded).
 *
 * Web Crypto API expects P1363, but Go's `ecdsa.SignASN1` and Python's
 * `cryptography` library produce DER-encoded signatures.
 */
function derToRaw(derSig: Uint8Array, byteLength: number = 32): Uint8Array {
  if (derSig[0] !== 0x30) {
    throw new Error("Invalid DER signature: expected SEQUENCE");
  }

  let offset = 2; // skip SEQUENCE tag + length byte

  // Parse r INTEGER
  if (derSig[offset] !== 0x02) {
    throw new Error("Invalid DER signature: expected INTEGER for r");
  }
  offset++;
  const rLen = derSig[offset];
  offset++;
  let r = derSig.slice(offset, offset + rLen);
  offset += rLen;

  // Parse s INTEGER
  if (derSig[offset] !== 0x02) {
    throw new Error("Invalid DER signature: expected INTEGER for s");
  }
  offset++;
  const sLen = derSig[offset];
  offset++;
  let s = derSig.slice(offset, offset + sLen);

  // Strip leading zero padding added by ASN.1 for negative-looking integers
  if (r.length > byteLength) {
    r = r.slice(r.length - byteLength);
  }
  if (s.length > byteLength) {
    s = s.slice(s.length - byteLength);
  }

  // Zero-pad shorter values and concatenate
  const raw = new Uint8Array(byteLength * 2);
  raw.set(r, byteLength - r.length);
  raw.set(s, byteLength * 2 - s.length);
  return raw;
}

// ── Signature Base Construction ────────────────────────────────────

/**
 * Resolve a single covered component to its string value.
 *
 * Derived components (`@status`, `@method`, `@path`, `@authority`) are
 * resolved from the response status and request metadata.  Everything
 * else is treated as a response header name.
 */
function resolveComponent(
  component: string,
  status: number,
  headers: Record<string, string>,
  requestInfo: HttpRequestInfo,
): string {
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
      if (value === undefined) {
        throw new Error(`Header "${component}" not present in response`);
      }
      return value;
    }
  }
}

/**
 * Build the RFC 9421 signature base string.
 *
 * The output matches the format produced by server-py and caddy-httpsig:
 *
 *     "@status": 200
 *     "content-type": application/json
 *     "@signature-params": ("@status" "content-type");created=...;keyid="...";alg="..."
 */
function buildSignatureBase(
  coveredComponents: string[],
  componentValues: Record<string, string>,
  sigParams: string,
): string {
  const lines: string[] = [];
  for (const component of coveredComponents) {
    const value = componentValues[component];
    if (value === undefined) {
      throw new Error(`Missing value for covered component: ${component}`);
    }
    lines.push(`"${component}": ${value}`);
  }
  lines.push(`"@signature-params": ${sigParams}`);
  return lines.join("\n");
}

// ── Cryptographic Verification ─────────────────────────────────────

/**
 * Verify an ECDSA P-256 signature using the Web Crypto API.
 *
 * Accepts a JWK public key and a DER-encoded signature.  The DER
 * signature is converted to IEEE P1363 format before being passed to
 * `crypto.subtle.verify`, which internally hashes the message with
 * SHA-256 — matching the hash-then-sign approach of server-py and
 * caddy-httpsig.
 */
async function verifyEcdsaSignature(
  jwk: EcPublicJwk,
  derSignature: Uint8Array,
  message: string,
): Promise<boolean> {
  try {
    const rawSignature = derToRaw(derSignature, 32);

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );

    const messageBytes = new TextEncoder().encode(message);

    return await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      publicKey,
      rawSignature.buffer as ArrayBuffer,
      messageBytes,
    );
  } catch (error) {
    console.error("[HTTP Sig] ECDSA verification error:", error);
    return false;
  }
}

// ── DID Document Helpers ───────────────────────────────────────────

/** Fetch the DID document at `{origin}/.well-known/did.json`. */
async function fetchDidDocument(origin: string): Promise<DidDocument> {
  const url = `${origin}/.well-known/did.json`;
  console.log("[HTTP Sig] Fetching DID document from:", url);

  const response = await fetch(url, {
    headers: { Accept: "application/json" },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch DID document: ${response.status}`);
  }

  const didDoc: DidDocument = await response.json();
  console.log("[HTTP Sig] DID document:", didDoc);
  return didDoc;
}

/** Find the verification method whose `id` matches `keyid`. */
function findVerificationMethod(
  didDoc: DidDocument,
  keyid: string,
): VerificationMethod | undefined {
  return didDoc.verificationMethod?.find(
    (vm) => vm.id === keyid || vm.id.endsWith(keyid),
  );
}

/**
 * Extract a JWK public key from a DID verification method.
 *
 * Currently only `publicKeyJwk` is supported (used by server-py and
 * caddy-httpsig).
 */
function extractPublicKey(vm: VerificationMethod): EcPublicJwk {
  if (vm.publicKeyJwk) {
    return vm.publicKeyJwk;
  }
  throw new Error(
    `Unsupported key format in verification method: ${Object.keys(vm).join(", ")}`,
  );
}

// ── DID Resolution ─────────────────────────────────────────────────

/**
 * Convert a DID to its resolution URL.
 *
 * - did:web:example.com          → https://example.com/.well-known/did.json
 * - did:web:example.com:path:doc → https://example.com/path/doc/did.json
 * - did:plc:abc123               → https://plc.directory/did:plc:abc123
 * - did:key:*                    → null (self-describing)
 */
function resolveDidToUrl(did: string): string | null {
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

  // did:key is self-describing, no document to fetch
  if (did.startsWith("did:key:")) {
    return null;
  }

  return null;
}

/** Fetch and parse a DID document from any supported DID method. */
async function resolveDidDocument(did: string): Promise<DidDocument> {
  const url = resolveDidToUrl(did);
  if (!url) {
    throw new Error(`Cannot resolve DID: ${did}`);
  }

  console.log("[HTTP Sig] Resolving DID document:", did, "→", url);

  const response = await fetch(url, {
    headers: { Accept: "application/json" },
  });

  if (!response.ok) {
    throw new Error(`Failed to resolve ${did}: HTTP ${response.status}`);
  }

  return await response.json() as DidDocument;
}

// ── Linked DID Checks ──────────────────────────────────────────────

/**
 * Resolve a single linked DID and check whether it contains a
 * verification method matching the given keyid.
 */
async function checkLinkedDid(
  did: string,
  keyid: string,
  relationship: "controller" | "alsoKnownAs",
  addStep: (name: string, status: VerificationStep["status"], info?: Record<string, unknown>) => void,
): Promise<LinkedDidCheck> {
  const label = relationship === "controller" ? "Controller" : "alsoKnownAs";
  const stepName = `Resolve ${label}: ${did}`;

  // Skip self-describing DIDs
  if (resolveDidToUrl(did) === null) {
    addStep(stepName, "success", { skipped: true, reason: "Self-describing DID method" });
    return { did, relationship, status: "skipped", error: "Self-describing DID method (no document to fetch)" };
  }

  addStep(stepName, "pending", { did });

  try {
    const linkedDoc = await resolveDidDocument(did);
    const vm = findVerificationMethod(linkedDoc, keyid);

    if (vm) {
      addStep(stepName, "success", {
        did,
        resolvedId: linkedDoc.id,
        matchingMethod: vm.id,
      });
      return { did, relationship, status: "success", keyFound: true };
    } else {
      addStep(stepName, "failed", {
        did,
        resolvedId: linkedDoc.id,
        keyid,
        availableMethods: linkedDoc.verificationMethod?.map((v) => v.id) ?? [],
      });
      return { did, relationship, status: "failed", keyFound: false, error: "Key not found in linked document" };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    addStep(stepName, "failed", { did, error: message });
    return { did, relationship, status: "failed", error: message };
  }
}

/**
 * Check all linked DIDs referenced by a DID document's `controller`
 * and `alsoKnownAs` fields.
 */
async function performLinkedDidChecks(
  didDoc: DidDocument,
  keyid: string,
  addStep: (name: string, status: VerificationStep["status"], info?: Record<string, unknown>) => void,
): Promise<LinkedDidCheck[]> {
  const checks: LinkedDidCheck[] = [];

  // Normalize controller to array, skip self-references
  if (didDoc.controller) {
    const controllers = Array.isArray(didDoc.controller)
      ? didDoc.controller
      : [didDoc.controller];

    for (const controller of controllers) {
      if (controller === didDoc.id) continue;
      checks.push(await checkLinkedDid(controller, keyid, "controller", addStep));
    }
  }

  // Check alsoKnownAs entries that are DIDs
  if (didDoc.alsoKnownAs) {
    for (const aka of didDoc.alsoKnownAs) {
      if (!aka.startsWith("did:")) continue;
      checks.push(await checkLinkedDid(aka, keyid, "alsoKnownAs", addStep));
    }
  }

  return checks;
}

// ── Main Verification Flow ─────────────────────────────────────────

/**
 * Verify the HTTP signature on a response intercepted by the
 * `webRequest.onHeadersReceived` listener.
 *
 * Returns a detailed {@link VerificationResult} with per-step timing
 * and diagnostics regardless of whether verification succeeds.
 */
async function verifyHttpSignature(
  details: browser.webRequest._OnHeadersReceivedDetails,
): Promise<VerificationResult> {
  const startTime = Date.now();
  const steps: VerificationStep[] = [];

  const result: VerificationResult = {
    url: details.url,
    timestamp: new Date().toISOString(),
    verified: false,
    errors: [],
    details: {},
    steps,
  };

  const addStep = (
    name: string,
    status: VerificationStep["status"],
    info: Record<string, unknown> = {},
  ) => {
    steps.push({ name, status, details: info, timestamp: Date.now() - startTime });
  };

  try {
    // Step 1: Extract headers into a lowercase-keyed map
    addStep("Extract Headers", "pending");
    const headers: Record<string, string> = {};
    for (const header of details.responseHeaders || []) {
      if (header.name && header.value) {
        headers[header.name.toLowerCase()] = header.value;
      }
    }
    addStep("Extract Headers", "success", {
      headerCount: details.responseHeaders?.length ?? 0,
    });

    // Step 2: Check for required signature headers
    addStep("Check Signature Headers", "pending");
    if (!headers["signature-input"] || !headers["signature"]) {
      addStep("Check Signature Headers", "failed", {
        hasSignatureInput: !!headers["signature-input"],
        hasSignature: !!headers["signature"],
      });
      result.errors.push("Missing Signature or Signature-Input header");
      return result;
    }
    addStep("Check Signature Headers", "success");

    // Step 3: Parse Signature-Input
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
      created: sigParams.created
        ? new Date(parseInt(sigParams.created, 10) * 1000).toISOString()
        : "unknown",
    });

    // Step 4: Validate algorithm
    addStep("Validate Algorithm", "pending");
    if (sigParams.alg !== "ecdsa-p256-sha256") {
      addStep("Validate Algorithm", "failed", {
        algorithm: sigParams.alg,
        expected: "ecdsa-p256-sha256",
      });
      result.errors.push(`Unsupported algorithm: ${sigParams.alg}`);
      return result;
    }
    addStep("Validate Algorithm", "success", { algorithm: "ecdsa-p256-sha256" });

    // Step 5: Parse Signature bytes (DER-encoded)
    addStep("Parse Signature", "pending");
    const signatureName = sigParams.signatureName || "sig";
    const signature = parseSignature(headers["signature"], signatureName);
    addStep("Parse Signature", "success", {
      signatureLength: signature.length,
      format: "DER/ASN.1",
    });

    // Step 6: Parse URL components for derived-component resolution
    addStep("Parse URL Components", "pending");
    const url = new URL(details.url);
    const requestInfo: HttpRequestInfo = {
      method: details.method,
      path: url.pathname + url.search,
      authority: url.host,
      origin: url.origin,
    };
    addStep("Parse URL Components", "success", {
      method: requestInfo.method,
      path: requestInfo.path,
      authority: requestInfo.authority,
      origin: requestInfo.origin,
    });

    // Step 7: Fetch the site's DID document
    addStep("Fetch DID Document", "pending", {
      url: `${requestInfo.origin}/.well-known/did.json`,
    });
    const didDoc = await fetchDidDocument(requestInfo.origin);
    result.details.did = didDoc.id;
    addStep("Fetch DID Document", "success", {
      did: didDoc.id,
      verificationMethods: didDoc.verificationMethod?.length ?? 0,
    });

    // Step 8: Find the matching verification method
    addStep("Find Verification Method", "pending", {
      searchingFor: sigParams.keyid,
    });
    const vm = findVerificationMethod(didDoc, sigParams.keyid ?? "");
    if (!vm) {
      addStep("Find Verification Method", "failed", {
        keyid: sigParams.keyid,
        availableMethods: didDoc.verificationMethod?.map((v) => v.id) ?? [],
      });
      result.errors.push(`Verification method not found: ${sigParams.keyid}`);
      return result;
    }
    addStep("Find Verification Method", "success", {
      methodId: vm.id,
      type: vm.type,
    });

    // Step 9: Extract the JWK public key
    addStep("Extract Public Key", "pending");
    const jwk = extractPublicKey(vm);
    addStep("Extract Public Key", "success", {
      keyType: jwk.kty,
      curve: jwk.crv,
    });

    // Step 10: Build the signature base string
    addStep("Build Signature Base", "pending");
    const componentValues: Record<string, string> = {};
    for (const component of sigParams.coveredComponents) {
      componentValues[component] = resolveComponent(
        component,
        details.statusCode,
        headers,
        requestInfo,
      );
    }
    const sigParamsValue = headers["signature-input"].slice(
      headers["signature-input"].indexOf("=") + 1,
    );
    const signatureBase = buildSignatureBase(
      sigParams.coveredComponents,
      componentValues,
      sigParamsValue,
    );
    addStep("Build Signature Base", "success", {
      baseLength: signatureBase.length,
      components: sigParams.coveredComponents,
    });

    // Step 11: Verify the ECDSA P-256 signature
    addStep("Verify ECDSA P-256 Signature", "pending");
    const isValid = await verifyEcdsaSignature(jwk, signature, signatureBase);

    if (isValid) {
      addStep("Verify ECDSA P-256 Signature", "success");
      result.verified = true;
      console.log("[HTTP Sig] Signature verified successfully");

      // Resolve and validate linked DIDs (controller, alsoKnownAs)
      try {
        const linkedChecks = await performLinkedDidChecks(
          didDoc,
          sigParams.keyid ?? "",
          addStep,
        );
        if (linkedChecks.length > 0) {
          result.linkedDidChecks = linkedChecks;
        }
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        addStep("Linked DID Checks", "failed", { error: msg });
        // Do NOT change result.verified — the HTTP signature is still valid
      }
    } else {
      addStep("Verify ECDSA P-256 Signature", "failed");
      result.errors.push("Signature verification failed");
      console.log("[HTTP Sig] Signature verification failed");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const stack = error instanceof Error ? error.stack : undefined;
    addStep("Error", "failed", { message, stack });
    result.errors.push(message);
    console.error("[HTTP Sig] Verification error:", error);
  }

  result.duration = Date.now() - startTime;
  return result;
}

// ── Icon Management ────────────────────────────────────────────────

function updateIcon(tabId: number, result: VerificationResult): void {
  const icon = result.verified ? ICONS.verified : ICONS.error;
  browser.browserAction.setIcon({ tabId, path: icon });

  const title = result.verified
    ? `Verified: ${result.details.did ?? "Unknown DID"}`
    : `Failed: ${result.errors.join(", ")}`;
  browser.browserAction.setTitle({ tabId, title });
}

// ── Event Listeners ────────────────────────────────────────────────

browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== "main_frame") return;

    console.log("[HTTP Sig] Processing:", details.url);

    // Fire-and-forget — the listener doesn't need to block on the result.
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
          verification_history: verificationHistory,
        });
      } catch (error) {
        console.error("[HTTP Sig] Error storing to browser.storage:", error);
      }

      updateIcon(details.tabId, result);
    })();
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"],
);

browser.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) {
    browser.browserAction.setIcon({ tabId: details.tabId, path: ICONS.default });
    browser.browserAction.setTitle({
      tabId: details.tabId,
      title: "DID HTTP Signature Verifier",
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
    browser.storage.local
      .set({ verification_history: [] })
      .catch((err: unknown) =>
        console.error("[HTTP Sig] Error clearing storage:", err),
      );
    sendResponse({ success: true });
  }
  return true;
});

console.log("[HTTP Sig] Extension ready");
