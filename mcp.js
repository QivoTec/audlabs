// ── AudLabs MCP server ("Sign in with AudLabs" + tools) ──
// Mounted from server.js with: require("./mcp")(app, { db, admin, uploadAudioToStorage });
const crypto = require("crypto");
const path = require("path");
const axios = require("axios");
const { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } = require("@modelcontextprotocol/sdk/server/auth/router.js");
const { requireBearerAuth } = require("@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js");
const { InvalidTokenError, InvalidGrantError } = require("@modelcontextprotocol/sdk/server/auth/errors.js");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const { StreamableHTTPServerTransport } = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const { z } = require("zod");

module.exports = function setupMcp(app, opts) {
  const db = opts.db;
  const admin = opts.admin;
  const uploadAudioToStorage = opts.uploadAudioToStorage;
  const http = opts.http || axios;
  const BASE = opts.baseUrl || "https://app.audlabs.io";
  const FIREBASE_WEB_API_KEY = opts.firebaseApiKey || "AIzaSyCJ12GtdhXTzfB0h0buHkjzsqZtRxzfxS8";
  const ACCESS_TOKEN_SECONDS = 60 * 60;            // 1 hour
  const REFRESH_TOKEN_SECONDS = 60 * 60 * 24 * 30; // 30 days
  const MAX_TTS_CHARS = 4800;

  let VOICES = [];
  try { VOICES = require(path.join(__dirname, "public", "voices.json")); } catch (e) { console.warn("MCP: voices.json not found"); }

  const hash = (t) => crypto.createHash("sha256").update(t).digest("hex");
  const randomToken = () => crypto.randomBytes(32).toString("hex");
  const nowSec = () => Math.floor(Date.now() / 1000);
  const toDate = (x) => !x ? null : (typeof x.toDate === "function" ? x.toDate() : (x._seconds ? new Date(x._seconds * 1000) : new Date(x)));

  // ── OAuth provider backed by Firestore ──
  const clientsStore = {
    async getClient(clientId) {
      const doc = await db.collection("mcpClients").doc(clientId).get();
      return doc.exists ? doc.data() : undefined;
    },
    async registerClient(client) {
      const clean = JSON.parse(JSON.stringify(client));
      await db.collection("mcpClients").doc(clean.client_id).set(clean);
      return clean;
    }
  };

  async function issueTokens(uid, clientId, scopes) {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    await db.collection("mcpTokens").doc(hash(accessToken)).set({
      type: "access", uid, clientId, scopes: scopes || [], expiresAt: nowSec() + ACCESS_TOKEN_SECONDS
    });
    await db.collection("mcpTokens").doc(hash(refreshToken)).set({
      type: "refresh", uid, clientId, scopes: scopes || [], expiresAt: nowSec() + REFRESH_TOKEN_SECONDS
    });
    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_SECONDS,
      refresh_token: refreshToken,
      scope: (scopes || []).join(" ")
    };
  }

  const provider = {
    get clientsStore() { return clientsStore; },

    async authorize(client, params, res) {
      const reqId = randomToken();
      await db.collection("mcpAuthRequests").doc(reqId).set({
        clientId: client.client_id,
        clientName: client.client_name || "An AI app",
        redirectUri: params.redirectUri,
        codeChallenge: params.codeChallenge,
        state: params.state || null,
        scopes: params.scopes || [],
        expiresAt: nowSec() + 10 * 60
      });
      res.redirect("/oauth/login?req=" + reqId);
    },

    async challengeForAuthorizationCode(client, code) {
      const doc = await db.collection("mcpCodes").doc(hash(code)).get();
      if (!doc.exists || doc.data().clientId !== client.client_id) throw new InvalidGrantError("Invalid authorization code");
      return doc.data().codeChallenge;
    },

    async exchangeAuthorizationCode(client, code, codeVerifier, redirectUri) {
      const ref = db.collection("mcpCodes").doc(hash(code));
      const doc = await ref.get();
      if (!doc.exists) throw new InvalidGrantError("Invalid authorization code");
      const data = doc.data();
      await ref.delete(); // single use
      if (data.clientId !== client.client_id) throw new InvalidGrantError("Code was issued to another client");
      if (data.expiresAt < nowSec()) throw new InvalidGrantError("Authorization code expired");
      if (redirectUri && redirectUri !== data.redirectUri) throw new InvalidGrantError("redirect_uri mismatch");
      return issueTokens(data.uid, client.client_id, data.scopes);
    },

    async exchangeRefreshToken(client, refreshToken) {
      const ref = db.collection("mcpTokens").doc(hash(refreshToken));
      const doc = await ref.get();
      if (!doc.exists) throw new InvalidGrantError("Invalid refresh token");
      const data = doc.data();
      if (data.type !== "refresh" || data.clientId !== client.client_id) throw new InvalidGrantError("Invalid refresh token");
      if (data.expiresAt < nowSec()) { await ref.delete(); throw new InvalidGrantError("Refresh token expired"); }
      await ref.delete(); // rotate
      return issueTokens(data.uid, client.client_id, data.scopes);
    },

    async verifyAccessToken(token) {
      const doc = await db.collection("mcpTokens").doc(hash(token)).get();
      if (!doc.exists) throw new InvalidTokenError("Invalid access token");
      const data = doc.data();
      if (data.type !== "access" || data.expiresAt < nowSec()) throw new InvalidTokenError("Access token expired");
      return { token, clientId: data.clientId, scopes: data.scopes || [], expiresAt: data.expiresAt, extra: { uid: data.uid } };
    },

    async revokeToken(client, request) {
      const ref = db.collection("mcpTokens").doc(hash(request.token));
      const doc = await ref.get();
      if (doc.exists && doc.data().clientId === client.client_id) await ref.delete();
    }
  };

  // ── OAuth routes: /authorize /token /register /revoke + .well-known metadata ──
  app.use(mcpAuthRouter({
    provider,
    issuerUrl: new URL(BASE),
    resourceServerUrl: new URL(BASE + "/mcp"),
    resourceName: "AudLabs",
    scopesSupported: ["audlabs"],
    authorizationOptions: { rateLimit: false },
    tokenOptions: { rateLimit: false },
    clientRegistrationOptions: { rateLimit: false },
    revocationOptions: { rateLimit: false }
  }));

  // ── Sign-in page and its two helper endpoints ──
  app.get("/oauth/login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "oauth-login.html"));
  });

  app.get("/oauth/request-info", async (req, res) => {
    try {
      const doc = await db.collection("mcpAuthRequests").doc(String(req.query.req || "")).get();
      if (!doc.exists || doc.data().expiresAt < nowSec()) return res.json({ valid: false });
      return res.json({ valid: true, clientName: doc.data().clientName });
    } catch (e) { return res.status(500).json({ valid: false }); }
  });

  app.post("/oauth/approve", async (req, res) => {
    try {
      const { req: reqId, idToken, decision } = req.body || {};
      if (!reqId) return res.status(400).json({ error: "Missing request" });
      const reqRef = db.collection("mcpAuthRequests").doc(String(reqId));
      const reqDoc = await reqRef.get();
      if (!reqDoc.exists || reqDoc.data().expiresAt < nowSec()) {
        return res.status(400).json({ error: "This sign-in link has expired. Please connect AudLabs again from your AI app." });
      }
      const r = reqDoc.data();
      const target = new URL(r.redirectUri);
      if (r.state) target.searchParams.set("state", r.state);
      if (decision === "deny") {
        await reqRef.delete();
        target.searchParams.set("error", "access_denied");
        return res.json({ redirect: target.href });
      }
      if (!idToken) return res.status(401).json({ error: "Please sign in first." });
      const decoded = await admin.auth().verifyIdToken(idToken);
      const code = randomToken();
      await db.collection("mcpCodes").doc(hash(code)).set({
        clientId: r.clientId,
        uid: decoded.uid,
        codeChallenge: r.codeChallenge,
        redirectUri: r.redirectUri,
        scopes: r.scopes || [],
        expiresAt: nowSec() + 5 * 60
      });
      await reqRef.delete();
      target.searchParams.set("code", code);
      return res.json({ redirect: target.href });
    } catch (e) {
      console.error("MCP approve error:", e.message);
      return res.status(401).json({ error: "Sign-in could not be verified. Please try again." });
    }
  });

  // ── Calling AudLabs' own endpoints as the signed-in user ──
  const idTokenCache = {};
  async function getUserIdToken(uid) {
    const cached = idTokenCache[uid];
    if (cached && cached.exp > Date.now() + 60000) return cached.token;
    const customToken = await admin.auth().createCustomToken(uid);
    const r = await http.post(
      "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=" + FIREBASE_WEB_API_KEY,
      { token: customToken, returnSecureToken: true }
    );
    idTokenCache[uid] = { token: r.data.idToken, exp: Date.now() + (parseInt(r.data.expiresIn, 10) || 3600) * 1000 };
    return r.data.idToken;
  }

  function errorFromResponse(e, fallback) {
    let data = e.response && e.response.data;
    if (data && (Buffer.isBuffer(data) || data instanceof ArrayBuffer)) {
      try { data = JSON.parse(Buffer.from(data).toString("utf8")); } catch (x) { data = null; }
    }
    return (data && data.error) || fallback;
  }

  function textResult(text, isError) {
    return { content: [{ type: "text", text }], isError: !!isError };
  }

  // ── The MCP tools ──
  function buildServer(uid) {
    const server = new McpServer({ name: "AudLabs", version: "1.0.0" });

    server.registerTool("check_credits", {
      title: "Check AudLabs credits",
      description: "Shows the user's AudLabs credit balance (free monthly, purchased monthly and lifetime credits) and when each expires.",
      inputSchema: {}
    }, async () => {
      const doc = await db.collection("users").doc(uid).get();
      if (!doc.exists) return textResult("No AudLabs account found for this user.", true);
      const d = doc.data();
      const now = new Date();
      const freeExp = toDate(d.freeMonthlyCreditsExpiresAt);
      const monthlyExp = toDate(d.monthlyCreditsExpiresAt);
      const free = (freeExp && freeExp > now) ? (d.freeMonthlyCredits || 0) : 0;
      const monthly = (monthlyExp && monthlyExp > now) ? (d.monthlyCredits || 0) : 0;
      const legacy = d.credits || 0;
      const fmt = (dt) => dt.toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
      const lines = [
        "Total credits available: " + (free + monthly + legacy).toLocaleString() + " (1 credit = 1 character)",
        "Free monthly credits: " + free.toLocaleString() + (free && freeExp ? " (expire " + fmt(freeExp) + ")" : ""),
        "Purchased monthly credits: " + monthly.toLocaleString() + (monthly && monthlyExp ? " (expire " + fmt(monthlyExp) + ")" : ""),
        "Lifetime credits: " + legacy.toLocaleString(),
        "Top up: https://app.audlabs.io/buy-credits"
      ];
      return textResult(lines.join("\n"));
    });

    server.registerTool("list_voices", {
      title: "Find AudLabs voices",
      description: "Search AudLabs voices by name, language code (for example en, es, fr) or gender. Returns voice IDs to use with generate_voiceover.",
      inputSchema: {
        search: z.string().optional().describe("Part of a voice name, for example 'narrator' or 'brian'"),
        language: z.string().optional().describe("Language code, for example en, es, fr, de"),
        gender: z.enum(["male", "female"]).optional(),
        limit: z.number().int().min(1).max(50).optional().describe("How many voices to return (default 25)")
      }
    }, async ({ search, language, gender, limit }) => {
      if (!VOICES.length) return textResult("The voice list is not available right now.", true);
      const q = (search || "").toLowerCase();
      const matches = VOICES.filter((v) =>
        (!q || (v.name || "").toLowerCase().includes(q) || (v.id || "").toLowerCase().includes(q)) &&
        (!language || (v.lang || "").toLowerCase() === language.toLowerCase()) &&
        (!gender || (v.gender || "").toLowerCase() === gender)
      ).slice(0, limit || 25);
      if (!matches.length) return textResult("No voices matched. Try a different search, or leave the filters empty.");
      return textResult(matches.map((v) => v.name + " — " + (v.meta || "") + " — voice_id: " + v.id).join("\n"));
    });

    server.registerTool("generate_voiceover", {
      title: "Generate an AudLabs voiceover",
      description: "Turns a script into a voiceover MP3 using the user's AudLabs credits (1 credit per character). Returns a download link that works for 48 hours. Use list_voices first to get a voice_id. Pauses can be added with markers like <#0.5#>.",
      inputSchema: {
        text: z.string().min(1).max(MAX_TTS_CHARS).describe("The script to read, up to " + MAX_TTS_CHARS + " characters"),
        voice_id: z.string().describe("A voice_id from list_voices"),
        speed: z.number().min(0.5).max(2).optional().describe("0.5 to 2.0, default 1.0"),
        volume: z.number().min(0.1).max(2).optional().describe("0.1 to 2.0, default 1.0"),
        pitch: z.number().int().min(-12).max(12).optional().describe("-12 to 12, default 0")
      }
    }, async ({ text, voice_id, speed, volume, pitch }) => {
      let idToken;
      try { idToken = await getUserIdToken(uid); }
      catch (e) { console.error("MCP token error:", e.message); return textResult("Could not verify your AudLabs session. Please reconnect AudLabs.", true); }
      const headers = { "Content-Type": "application/json", Authorization: "Bearer " + idToken };
      let audioBuffer;
      try {
        const genRes = await http.post(BASE + "/api/generate-voice",
          { voiceId: voice_id, text, speed: speed || 1.0, vol: volume || 1.0, pitch: pitch || 0 },
          { headers, responseType: "arraybuffer", timeout: 120000 });
        audioBuffer = Buffer.from(genRes.data);
      } catch (e) {
        return textResult("Voiceover failed: " + errorFromResponse(e, "please try again in a moment."), true);
      }
      const voice = VOICES.find((v) => v.id === voice_id);
      const voiceName = voice ? voice.name : voice_id;
      const stored = await uploadAudioToStorage(audioBuffer, uid, "audio/mpeg");
      if (!stored || !stored.url) return textResult("The voiceover was generated but could not be saved. Please try again.", true);
      let remaining = null;
      try {
        const dr = await http.post(BASE + "/api/deduct-credits", { characters: text.length, voiceName }, { headers });
        remaining = dr.data && dr.data.remaining;
      } catch (e) { console.error("MCP deduct error:", errorFromResponse(e, e.message)); }
      return textResult(
        "Your voiceover is ready (" + voiceName + ", " + text.length.toLocaleString() + " characters).\n" +
        "Download MP3 (link works for 48 hours): " + stored.url +
        (remaining !== null && remaining !== undefined ? "\nCredits remaining: " + Number(remaining).toLocaleString() : "")
      );
    });

    return server;
  }

  // ── The MCP endpoint itself ──
  const bearer = requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(BASE + "/mcp"))
  });

  app.post("/mcp", bearer, async (req, res) => {
    const server = buildServer(req.auth.extra.uid);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on("close", () => { transport.close(); server.close(); });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e) {
      console.error("MCP request error:", e.message);
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
    }
  });
  app.get("/mcp", (req, res) => res.status(405).set("Allow", "POST").json({ error: "Method not allowed" }));
  app.delete("/mcp", (req, res) => res.status(405).set("Allow", "POST").json({ error: "Method not allowed" }));

  console.log("✅ AudLabs MCP mounted at " + BASE + "/mcp");
};
