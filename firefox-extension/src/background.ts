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
  domainAnchoring?: DomainAnchorResult;
}

/** Convenience signature for the per-step recorder threaded through helpers. */
type AddStep = (
  name: string,
  status: VerificationStep["status"],
  info?: Record<string, unknown>,
) => void;

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
  publicKeyMultibase?: string;
}

/** Minimal shape of a DID document we need for verification. */
interface DidDocument {
  id: string;
  controller?: string | string[];
  alsoKnownAs?: string[];
  verificationMethod?: VerificationMethod[];
}

/** Result of resolving and checking a linked DID (controller or alsoKnownAs) or handle. */
interface LinkedDidCheck {
  did: string;
  relationship: "controller" | "alsoKnownAs" | "handle";
  status: "success" | "failed" | "skipped";
  error?: string;
  keyFound?: boolean;
  // Only populated for alsoKnownAs: whether the linked DID document lists
  // the origin DID in its own alsoKnownAs (mutual-identity assertion).
  reciprocal?: boolean;
  // Only populated for handle relationships: the at:// handle, the DID it
  // resolved to, the method used, and whether it points back to the origin DID.
  handle?: string;
  resolvedDid?: string;
  resolvedVia?: "http";
  matchesOrigin?: boolean;
}

/** A single member of a verified did:web anchoring chain. */
interface DomainAnchorChainMember {
  did: string;
  host: string | null;
  holdsKey: boolean;
  reciprocal: boolean;
}

/**
 * Result of checking whether the signing key's identity is bidirectionally
 * anchored to the request origin domain — either directly (the key's
 * did:web domain is the origin) or through a chain of mutually-linked,
 * key-bearing did:web identities.
 */
interface DomainAnchorResult {
  originHost: string;
  keyDid: string | null;
  anchored: boolean;
  via: "direct" | "chain" | "none";
  chain: DomainAnchorChainMember[];
  error?: string;
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

declare const __BUILD_ID__: string;
const BUILD_ID = typeof __BUILD_ID__ !== "undefined" ? __BUILD_ID__ : "dev";
console.log(`[HTTP Sig] Extension initialized (build: ${BUILD_ID})`);

// ── did:key Resolution ────────────────────────────────────────────

/** Convert a Uint8Array to a base64url string (no padding). */
function uint8ArrayToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Decode a base58btc string (without the 'z' multibase prefix) to bytes. */
function base58btcDecode(input: string): Uint8Array {
  const alphabetMap = new Map<string, number>();
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    alphabetMap.set(BASE58_ALPHABET[i], i);
  }

  // Convert from base-58 to a big integer (using BigInt)
  let value = 0n;
  for (const char of input) {
    const digit = alphabetMap.get(char);
    if (digit === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    value = value * 58n + BigInt(digit);
  }

  // Convert big integer to bytes
  const bytes: number[] = [];
  while (value > 0n) {
    bytes.unshift(Number(value & 0xffn));
    value >>= 8n;
  }

  // Preserve leading zeros (each leading '1' in base58 = one zero byte)
  for (const char of input) {
    if (char !== "1") break;
    bytes.unshift(0);
  }

  return new Uint8Array(bytes);
}

/**
 * Decompress a SEC1 compressed P-256 public key (33 bytes) to x, y coordinates.
 *
 * Uses the P-256 curve equation y² = x³ + ax + b (mod p) and computes the
 * modular square root via (y²)^((p+1)/4) mod p.
 */
function decompressP256Point(compressed: Uint8Array): { x: Uint8Array; y: Uint8Array } {
  if (compressed.length !== 33) {
    throw new Error(`Expected 33-byte compressed key, got ${compressed.length}`);
  }
  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error(`Invalid compression prefix: 0x${prefix.toString(16)}`);
  }

  const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
  const a = p - 3n;

  // Read x coordinate
  let xBig = 0n;
  for (let i = 1; i < 33; i++) {
    xBig = (xBig << 8n) | BigInt(compressed[i]);
  }

  // y² = x³ + ax + b (mod p)
  const x3 = modPow(xBig, 3n, p);
  const ySquared = ((x3 + a * xBig + b) % p + p) % p;

  // Square root: y = ySquared^((p+1)/4) mod p
  const yCandidate = modPow(ySquared, (p + 1n) / 4n, p);

  // Choose the y with correct parity
  const isEven = (yCandidate & 1n) === 0n;
  const wantEven = prefix === 0x02;
  const yBig = isEven === wantEven ? yCandidate : p - yCandidate;

  return {
    x: bigIntToUint8Array(xBig, 32),
    y: bigIntToUint8Array(yBig, 32),
  };
}

/** Modular exponentiation: base^exp mod m using binary method. */
function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = ((base % m) + m) % m;
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % m;
    }
    exp >>= 1n;
    base = (base * base) % m;
  }
  return result;
}

/** Convert a BigInt to a fixed-length Uint8Array (big-endian). */
function bigIntToUint8Array(value: bigint, length: number): Uint8Array {
  const result = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    result[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return result;
}

/**
 * Resolve a did:key identifier to an EC public key JWK.
 *
 * Supports P-256 keys (multicodec prefix 0x8024).
 * Reference: atproto-identity-rs identify_key()
 */
function resolveDidKey(didKey: string): EcPublicJwk {
  const multibaseValue = didKey.startsWith("did:key:")
    ? didKey.slice("did:key:".length)
    : didKey;

  if (multibaseValue[0] !== "z") {
    throw new Error("Expected base58btc multibase prefix 'z'");
  }

  const decoded = base58btcDecode(multibaseValue.slice(1));

  if (decoded.length < 3) {
    throw new Error("Decoded key data too short");
  }

  // Check multicodec prefix for P-256 public key
  if (decoded[0] !== 0x80 || decoded[1] !== 0x24) {
    throw new Error(
      `Unsupported multicodec prefix: 0x${decoded[0].toString(16)}${decoded[1].toString(16)}`,
    );
  }

  const compressedKey = decoded.slice(2);
  const { x, y } = decompressP256Point(compressedKey);

  return {
    kty: "EC",
    crv: "P-256",
    x: uint8ArrayToBase64url(x),
    y: uint8ArrayToBase64url(y),
  };
}

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
  signatureBytes: Uint8Array,
  message: string,
): Promise<boolean> {
  try {
    let rawSignature: Uint8Array;
    if (signatureBytes[0] === 0x30) {
      // DER/ASN.1 encoded (produced by Go and Python)
      rawSignature = derToRaw(signatureBytes, 32);
    } else if (signatureBytes.length === 64) {
      // Already IEEE P1363 format (r || s, 32 + 32)
      rawSignature = signatureBytes;
    } else {
      throw new Error(
        `Unknown signature format: length=${signatureBytes.length}, first byte=0x${signatureBytes[0].toString(16)}`,
      );
    }

    console.log("[HTTP Sig] JWK for verification:", JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }));
    console.log("[HTTP Sig] Raw signature (P1363, hex):", Array.from(rawSignature).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log("[HTTP Sig] Raw signature length:", rawSignature.length);

    const publicKey = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );

    const messageBytes = new TextEncoder().encode(message);
    console.log("[HTTP Sig] Message to verify length:", messageBytes.length);

    const result = await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: "SHA-256" } },
      publicKey,
      rawSignature.buffer as ArrayBuffer,
      messageBytes,
    );
    console.log("[HTTP Sig] crypto.subtle.verify result:", result);
    return result;
  } catch (error) {
    console.error("[HTTP Sig] ECDSA verification error:", error);
    return false;
  }
}

// ── JWK Thumbprint ─────────────────────────────────────────────────

/**
 * Compute the RFC 7638 JWK Thumbprint (SHA-256, base64url) for an EC key.
 *
 * The canonical JSON uses the required members in lexicographic order:
 * crv, kty, x, y — matching the Python implementation in server-py.
 */
async function computeJwkThumbprint(jwk: EcPublicJwk): Promise<string> {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
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

/**
 * Find a verification method in a DID document whose key matches the
 * given reference key by JWK thumbprint.
 *
 * This is used for cross-document key matching where verification method
 * IDs differ between identities.
 */
async function findVerificationMethodByThumbprint(
  didDoc: DidDocument,
  referenceJwk: EcPublicJwk,
): Promise<VerificationMethod | undefined> {
  if (!didDoc.verificationMethod) return undefined;

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

  return undefined;
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
  if (vm.publicKeyMultibase) {
    const value = vm.publicKeyMultibase;
    // Handle both did:key:-prefixed and bare multibase values
    if (value.startsWith("did:key:")) {
      return resolveDidKey(value);
    }
    return resolveDidKey(`did:key:${value}`);
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

// ── Controller Key Lookup ─────────────────────────────────────────

/**
 * Search controller DID documents for a signing key.
 *
 * When the site's own DID document doesn't contain the signing key,
 * this function resolves each controller and searches for the key
 * by JWK thumbprint or verification method ID.
 */
async function findKeyInControllers(
  didDoc: DidDocument,
  referenceJwk: EcPublicJwk | null,
  keyid: string | undefined,
  addStep: (name: string, status: VerificationStep["status"], info?: Record<string, unknown>) => void,
): Promise<{ jwk: EcPublicJwk; controllerDid: string; methodId: string } | null> {
  if (!didDoc.controller) return null;

  const controllers = Array.isArray(didDoc.controller)
    ? didDoc.controller
    : [didDoc.controller];

  for (const controller of controllers) {
    if (controller === didDoc.id) continue;
    if (resolveDidToUrl(controller) === null) continue;

    try {
      const controllerDoc = await resolveDidDocument(controller);

      // Try thumbprint match first
      if (referenceJwk) {
        const vm = await findVerificationMethodByThumbprint(controllerDoc, referenceJwk);
        if (vm) {
          return { jwk: referenceJwk, controllerDid: controller, methodId: vm.id };
        }
      }

      // Try keyid match
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

// ── Linked DID Checks ──────────────────────────────────────────────

/**
 * Resolve a single linked DID and check whether it contains a
 * verification method with the same key (matched by JWK thumbprint).
 *
 * For `alsoKnownAs` relationships, additionally verify that the linked
 * DID document reciprocally lists `originDid` in its own `alsoKnownAs`.
 * This guards against one-sided mutual-identity claims, where a site
 * could unilaterally reference a victim DID without the victim claiming
 * back.
 */
async function checkLinkedDid(
  did: string,
  originDid: string,
  referenceJwk: EcPublicJwk,
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
    const vm = await findVerificationMethodByThumbprint(linkedDoc, referenceJwk);
    const keyFound = vm !== undefined;

    if (relationship === "controller") {
      if (keyFound) {
        addStep(stepName, "success", {
          did,
          resolvedId: linkedDoc.id,
          matchingMethod: vm!.id,
        });
        return { did, relationship, status: "success", keyFound: true };
      }
      addStep(stepName, "failed", {
        did,
        resolvedId: linkedDoc.id,
        availableMethods: linkedDoc.verificationMethod?.map((v) => v.id) ?? [],
      });
      return { did, relationship, status: "failed", keyFound: false, error: "Key not found in linked document" };
    }

    // alsoKnownAs: require both key match AND reciprocal mutual claim.
    const reciprocal = Array.isArray(linkedDoc.alsoKnownAs)
      && linkedDoc.alsoKnownAs.includes(originDid);

    if (keyFound && reciprocal) {
      addStep(stepName, "success", {
        did,
        resolvedId: linkedDoc.id,
        matchingMethod: vm!.id,
        reciprocal: true,
      });
      return { did, relationship, status: "success", keyFound: true, reciprocal: true };
    }

    let error: string;
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
      availableMethods: linkedDoc.verificationMethod?.map((v) => v.id) ?? [],
    });
    return { did, relationship, status: "failed", keyFound, reciprocal, error };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    addStep(stepName, "failed", { did, error: message });
    return { did, relationship, status: "failed", error: message };
  }
}

/**
 * Check all linked DIDs referenced by a DID document's `controller`
 * and `alsoKnownAs` fields, matching keys by JWK thumbprint.
 */
async function performLinkedDidChecks(
  didDoc: DidDocument,
  referenceJwk: EcPublicJwk,
  addStep: (name: string, status: VerificationStep["status"], info?: Record<string, unknown>) => void,
  extraDids: string[] = [],
): Promise<LinkedDidCheck[]> {
  const checks: LinkedDidCheck[] = [];

  // Normalize controller to array, skip self-references
  if (didDoc.controller) {
    const controllers = Array.isArray(didDoc.controller)
      ? didDoc.controller
      : [didDoc.controller];

    for (const controller of controllers) {
      if (controller === didDoc.id) continue;
      checks.push(await checkLinkedDid(controller, didDoc.id, referenceJwk, "controller", addStep));
    }
  }

  // Check alsoKnownAs entries that are DIDs
  if (didDoc.alsoKnownAs) {
    for (const aka of didDoc.alsoKnownAs) {
      if (!aka.startsWith("did:")) continue;
      checks.push(await checkLinkedDid(aka, didDoc.id, referenceJwk, "alsoKnownAs", addStep));
    }
  }

  // Check the first valid at:// handle in alsoKnownAs (bidirectional handle binding)
  if (didDoc.alsoKnownAs) {
    for (const aka of didDoc.alsoKnownAs) {
      const handle = parseAtHandle(aka);
      if (!handle) continue;
      checks.push(await checkLinkedHandle(handle, didDoc.id, addStep));
      break; // only the first valid handle
    }
  }

  // Check DIDs from ?check= query parameters
  for (const did of extraDids) {
    if (!did.startsWith("did:")) continue;
    if (did === didDoc.id) continue;
    checks.push(await checkLinkedDid(did, didDoc.id, referenceJwk, "alsoKnownAs", addStep));
  }

  return checks;
}

// ── Handle Resolution ──────────────────────────────────────────────

/** TLDs that are not valid public AT Protocol handle suffixes. */
const RESERVED_HANDLE_TLDS = new Set([
  "local", "arpa", "internal", "invalid", "localhost", "onion", "example", "alt", "test",
]);

/**
 * Parse and validate an `at://<domain>` alsoKnownAs entry as an AT Protocol
 * handle. Returns the bare lowercase handle, or null if the value is not a
 * syntactically valid bare handle (e.g. it carries a path, or uses a
 * reserved/numeric TLD).
 */
function parseAtHandle(aka: string): string | null {
  if (!aka.startsWith("at://")) return null;
  const rest = aka.slice("at://".length);
  // A bare handle has no path, query, fragment, or userinfo.
  if (/[/?#@]/.test(rest)) return null;

  const handle = rest.toLowerCase();
  if (handle.length === 0 || handle.length > 253) return null;

  const labels = handle.split(".");
  if (labels.length < 2) return null; // must have at least a domain + TLD

  const labelRe = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/;
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return null;
    if (!labelRe.test(label)) return null;
  }

  const tld = labels[labels.length - 1];
  if (RESERVED_HANDLE_TLDS.has(tld)) return null;
  if (/^[0-9]+$/.test(tld)) return null; // TLD cannot be all-numeric

  return handle;
}

/**
 * Resolve an AT Protocol handle to a DID using the HTTPS well-known method:
 * `GET https://<handle>/.well-known/atproto-did`, whose body is the DID as
 * plaintext. (The DNS TXT method is not used: Firefox's dns.resolve cannot
 * read TXT records, and a DoH fallback would disclose the handle to a
 * third-party resolver.)
 */
async function resolveHandleToDid(handle: string): Promise<string> {
  const url = `https://${handle}/.well-known/atproto-did`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
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

/**
 * Resolve the first valid at:// handle in alsoKnownAs and verify that it
 * resolves back to the origin DID. Sourcing the handle from the origin DID
 * document already proves the DID→handle direction; this proves the
 * handle→DID direction, completing the bidirectional binding.
 */
async function checkLinkedHandle(
  handle: string,
  originDid: string,
  addStep: AddStep,
): Promise<LinkedDidCheck> {
  const stepName = `Resolve handle: at://${handle}`;
  addStep(stepName, "pending", { handle });

  try {
    const resolvedDid = await resolveHandleToDid(handle);
    const matchesOrigin = resolvedDid === originDid;

    if (matchesOrigin) {
      addStep(stepName, "success", { handle, resolvedDid });
      return {
        did: originDid, relationship: "handle", status: "success",
        handle, resolvedDid, resolvedVia: "http", matchesOrigin: true,
      };
    }

    const error = `Handle resolves to ${resolvedDid}, not the origin DID ${originDid}`;
    addStep(stepName, "failed", { handle, resolvedDid, error });
    return {
      did: originDid, relationship: "handle", status: "failed",
      handle, resolvedDid, resolvedVia: "http", matchesOrigin: false, error,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    addStep(stepName, "failed", { handle, error: message });
    return {
      did: originDid, relationship: "handle", status: "failed",
      handle, matchesOrigin: false, error: message,
    };
  }
}

// ── Domain Anchoring ───────────────────────────────────────────────

/** Maximum bidirectional alsoKnownAs hops to walk when seeking the origin. */
const MAX_CHAIN_DEPTH = 5;

/** Extract the host (with port) from a did:web DID, or null if not did:web. */
function didWebHost(did: string): string | null {
  if (!did.startsWith("did:web:")) return null;
  const rest = did.slice("did:web:".length);
  const firstSegment = rest.split(":")[0];
  // Port is percent-encoded in did:web (e.g. foo.com%3A8443 → foo.com:8443).
  return decodeURIComponent(firstSegment);
}

/** Whether a DID document contains a verification method for the given key. */
async function docHoldsKey(doc: DidDocument, jwk: EcPublicJwk): Promise<boolean> {
  return (await findVerificationMethodByThumbprint(doc, jwk)) !== undefined;
}

/**
 * Verify that the signing key's identity is bidirectionally anchored to the
 * request origin domain.
 *
 * Anchoring is satisfied when there is a `did:web:<originHost>` identity that
 * holds the signing key and is reachable from the key's DID through links that
 * are each bidirectional (mutual `alsoKnownAs`) and key-bearing (both
 * documents contain the key):
 *
 *  - direct: the key's own did:web domain is the request origin; or
 *  - chain:  a BFS over mutual, key-bearing did:web alsoKnownAs edges reaches
 *            a member whose host equals the origin.
 *
 * A `did:key`/unknown keyid carries no domain, so the walk starts from the
 * origin document (the identity served at the request origin).
 */
async function verifyDomainAnchoring(
  originHost: string,
  keyDid: string | null,
  jwk: EcPublicJwk,
  originDoc: DidDocument,
  addStep: AddStep,
): Promise<DomainAnchorResult> {
  const chain: DomainAnchorChainMember[] = [];
  const startDid = keyDid && keyDid.startsWith("did:web:") ? keyDid : originDoc.id;

  // Direct: the key holder's own did:web domain is the request origin.
  if (didWebHost(startDid) === originHost) {
    // did:web keyids resolve their key from the holder document by
    // construction; for did:key confirm the origin document holds the key.
    const holdsKey = keyDid ? true : await docHoldsKey(originDoc, jwk);
    if (holdsKey) {
      addStep("Domain Anchoring", "success", { via: "direct", originHost, keyDid: startDid });
      return {
        originHost, keyDid, anchored: true, via: "direct",
        chain: [{ did: startDid, host: originHost, holdsKey: true, reciprocal: true }],
      };
    }
  }

  addStep("Domain Anchoring", "pending", { originHost, keyDid: startDid });

  // Seed the BFS with the key holder's document.
  let frontier: Array<{ did: string; doc: DidDocument }>;
  try {
    const startDoc = startDid === originDoc.id
      ? originDoc
      : await resolveDidDocument(startDid);
    frontier = [{ did: startDid, doc: startDoc }];
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const failure = `Cannot resolve key DID ${startDid}: ${message}`;
    addStep("Domain Anchoring", "failed", { error: failure });
    return { originHost, keyDid, anchored: false, via: "none", chain, error: failure };
  }

  const visited = new Set<string>([startDid]);

  for (let depth = 0; depth < MAX_CHAIN_DEPTH && frontier.length > 0; depth++) {
    const next: Array<{ did: string; doc: DidDocument }> = [];

    for (const node of frontier) {
      const akas = Array.isArray(node.doc.alsoKnownAs) ? node.doc.alsoKnownAs : [];
      for (const aka of akas) {
        if (!aka.startsWith("did:web:")) continue;
        if (visited.has(aka)) continue;
        visited.add(aka);

        try {
          const linkedDoc = aka === originDoc.id ? originDoc : await resolveDidDocument(aka);
          const reciprocal = Array.isArray(linkedDoc.alsoKnownAs)
            && linkedDoc.alsoKnownAs.includes(node.did);
          const holdsKey = await docHoldsKey(linkedDoc, jwk);
          const host = didWebHost(aka);
          chain.push({ did: aka, host, holdsKey, reciprocal });

          if (reciprocal && holdsKey) {
            if (host === originHost) {
              addStep("Domain Anchoring", "success", {
                via: "chain", originHost, anchorDid: aka, hops: depth + 1,
              });
              return { originHost, keyDid, anchored: true, via: "chain", chain };
            }
            next.push({ did: aka, doc: linkedDoc });
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
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
    console.log("[HTTP Sig] URL:", details.url);
    console.log("[HTTP Sig] Response headers:", JSON.stringify(headers, null, 2));
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
    result.details.coveredComponents = sigParams.coveredComponents.join(", ");
    addStep("Parse Signature-Input", "success", {
      keyid: sigParams.keyid,
      algorithm: sigParams.alg,
      coveredComponents: sigParams.coveredComponents,
      created: sigParams.created
        ? new Date(parseInt(sigParams.created, 10) * 1000).toISOString()
        : "unknown",
    });

    // Step 4: Validate algorithm (infer from did:key if not specified)
    addStep("Validate Algorithm", "pending");
    let effectiveAlg = sigParams.alg;
    if (!effectiveAlg && sigParams.keyid?.startsWith("did:key:")) {
      try {
        const keyJwk = resolveDidKey(sigParams.keyid);
        if (keyJwk.crv === "P-256") {
          effectiveAlg = "ecdsa-p256-sha256";
        }
      } catch { /* will fail at key resolution step */ }
    }
    if (effectiveAlg !== "ecdsa-p256-sha256") {
      addStep("Validate Algorithm", "failed", {
        algorithm: effectiveAlg ?? sigParams.alg,
        expected: "ecdsa-p256-sha256",
      });
      result.errors.push(`Unsupported algorithm: ${effectiveAlg ?? sigParams.alg}`);
      return result;
    }
    result.details.algorithm = effectiveAlg;
    addStep("Validate Algorithm", "success", {
      algorithm: "ecdsa-p256-sha256",
      inferred: !sigParams.alg,
    });

    // Step 5: Parse Signature bytes
    addStep("Parse Signature", "pending");
    const signatureName = sigParams.signatureName || "sig";
    const signature = parseSignature(headers["signature"], signatureName);
    const sigFormat = signature[0] === 0x30 ? "DER/ASN.1" : signature.length === 64 ? "IEEE P1363" : "unknown";
    addStep("Parse Signature", "success", {
      signatureLength: signature.length,
      format: sigFormat,
    });

    // Step 6: Parse URL components for derived-component resolution
    addStep("Parse URL Components", "pending");
    const url = new URL(details.url);
    const requestInfo: HttpRequestInfo = {
      method: details.method,
      path: url.pathname,
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

    // Step 8-9: Resolve signing key
    addStep("Resolve Signing Key", "pending", { keyid: sigParams.keyid });
    let jwk: EcPublicJwk;

    if (sigParams.keyid?.startsWith("did:key:")) {
      // Resolve did:key directly to JWK
      jwk = resolveDidKey(sigParams.keyid);
      addStep("Resolve Signing Key", "success", {
        source: "did:key",
        keyType: jwk.kty,
        curve: jwk.crv,
      });

      // Check if the DID document contains the signing key (informational)
      addStep("Match Key in DID Document", "pending");
      let matchedVm = await findVerificationMethodByThumbprint(didDoc, jwk);
      if (!matchedVm) {
        // Try matching via publicKeyMultibase-extracted keys
        for (const vm of didDoc.verificationMethod ?? []) {
          if (!vm.publicKeyMultibase) continue;
          try {
            const vmJwk = extractPublicKey(vm);
            const vmThumb = await computeJwkThumbprint(vmJwk);
            const keyThumb = await computeJwkThumbprint(jwk);
            if (vmThumb === keyThumb) {
              matchedVm = vm;
              break;
            }
          } catch { continue; }
        }
      }
      if (matchedVm) {
        addStep("Match Key in DID Document", "success", { methodId: matchedVm.id });
      } else {
        // Key not in local document — try controller documents
        const controllerResult = await findKeyInControllers(didDoc, jwk, sigParams.keyid, addStep);
        if (controllerResult) {
          addStep("Match Key in DID Document", "success", {
            source: "controller",
            controllerDid: controllerResult.controllerDid,
            methodId: controllerResult.methodId,
          });
        } else {
          addStep("Match Key in DID Document", "failed", {
            keyid: sigParams.keyid,
            note: "Signing key not found in DID document or controller documents",
            availableMethods: didDoc.verificationMethod?.map((v) => v.id) ?? [],
          });
          result.errors.push(`Signing key ${sigParams.keyid} not found in DID document or controller documents`);
          return result;
        }
      }
    } else {
      // Find VM by id match in the origin document first
      let vm = findVerificationMethod(didDoc, sigParams.keyid ?? "");
      let keySource = "origin document";

      // did:web keyids carry their own document — resolve the key there when
      // it isn't published by the origin (e.g. did:web:bar.com#signing on
      // a request to foo.com).
      if (!vm && sigParams.keyid?.startsWith("did:web:")) {
        const keyDid = sigParams.keyid.split("#")[0];
        try {
          const keyDoc = await resolveDidDocument(keyDid);
          vm = findVerificationMethod(keyDoc, sigParams.keyid);
          if (vm) keySource = keyDid;
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
          curve: jwk.crv,
        });
      } else {
        // Key not in local document — try controller documents
        const controllerResult = await findKeyInControllers(didDoc, null, sigParams.keyid, addStep);
        if (controllerResult) {
          jwk = controllerResult.jwk;
          addStep("Resolve Signing Key", "success", {
            source: "controller",
            controllerDid: controllerResult.controllerDid,
            methodId: controllerResult.methodId,
            keyType: jwk.kty,
            curve: jwk.crv,
          });
        } else {
          addStep("Resolve Signing Key", "failed", {
            keyid: sigParams.keyid,
            availableMethods: didDoc.verificationMethod?.map((v) => v.id) ?? [],
          });
          result.errors.push(`Verification method not found: ${sigParams.keyid}`);
          return result;
        }
      }
    }

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
    console.log("[HTTP Sig] Signature base:\n" + signatureBase);
    console.log("[HTTP Sig] Component values:", JSON.stringify(componentValues, null, 2));
    console.log("[HTTP Sig] sigParamsValue:", sigParamsValue);
    console.log("[HTTP Sig] Signature base (hex):", Array.from(new TextEncoder().encode(signatureBase)).map(b => b.toString(16).padStart(2, '0')).join(' '));
    addStep("Build Signature Base", "success", {
      baseLength: signatureBase.length,
      components: sigParams.coveredComponents,
      signatureBase: signatureBase,
    });

    // Step 11: Verify the ECDSA P-256 signature
    addStep("Verify ECDSA P-256 Signature", "pending");
    console.log("[HTTP Sig] Signature bytes (hex):", Array.from(signature).map(b => b.toString(16).padStart(2, '0')).join(''));
    console.log("[HTTP Sig] Signature length:", signature.length, "first byte:", signature[0]?.toString(16));
    const isValid = await verifyEcdsaSignature(jwk, signature, signatureBase);

    if (isValid) {
      addStep("Verify ECDSA P-256 Signature", "success");
      console.log("[HTTP Sig] Signature verified successfully");

      // Gate: the signing key's identity must be bidirectionally anchored to
      // the request origin domain — directly (the key's did:web domain is the
      // origin) or through a chain of mutual, key-bearing did:web identities.
      const keyDid = sigParams.keyid && !sigParams.keyid.startsWith("did:key:")
        ? sigParams.keyid.split("#")[0]
        : null;
      const anchoring = await verifyDomainAnchoring(
        requestInfo.authority,
        keyDid,
        jwk,
        didDoc,
        addStep,
      );
      result.domainAnchoring = anchoring;

      if (anchoring.anchored) {
        result.verified = true;
        console.log("[HTTP Sig] Signature verified and domain-anchored");
      } else {
        result.verified = false;
        result.errors.push(
          anchoring.error
          ?? "Signing key identity is not anchored to the request origin domain",
        );
        console.log("[HTTP Sig] Signature valid but not domain-anchored:", anchoring.error);
      }

      // Resolve and validate linked DIDs (controller, alsoKnownAs, handle) —
      // supplementary diagnostics; these never change result.verified.
      try {
        const checkDids = url.searchParams.getAll("check");
        const linkedChecks = await performLinkedDidChecks(
          didDoc,
          jwk,
          addStep,
          checkDids,
        );
        if (linkedChecks.length > 0) {
          result.linkedDidChecks = linkedChecks;
        }
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        addStep("Linked DID Checks", "failed", { error: msg });
        // Do NOT change result.verified based on supplementary checks
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
