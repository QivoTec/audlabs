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
  const bucket = opts.bucket || admin.storage().bucket("voicegene.firebasestorage.app");
  const CLIP_COST = 1500, ALL_CLIPS_COST = 5000, MUSIC_COST = 3000, MAX_CLIPS_PER_CALL = 5;
  const LANGUAGES = ["English", "French", "Spanish", "German", "Italian", "Russian", "Portuguese", "Ukrainian", "Afrikaans"];
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


  // Call one of AudLabs' own endpoints as the signed-in user (reuses all existing checks and credit logic)
  async function callApi(uid, method, pathname, body) {
    const idToken = await getUserIdToken(uid);
    try {
      const r = await http.request({
        method, url: BASE + pathname, data: body,
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + idToken },
        timeout: 120000
      });
      return r.data;
    } catch (e) {
      throw new Error(errorFromResponse(e, "AudLabs could not complete that request. Please try again."));
    }
  }

  // Save a file to AudLabs storage and return a 48-hour download link (same pattern as voiceovers)
  async function storeFileForUser(uid, buffer, contentType, ext, folder, downloadName) {
    const filename = folder + "/" + uid + "/" + Date.now() + "_" + crypto.randomBytes(3).toString("hex") + "." + ext;
    const file = bucket.file(filename);
    await file.save(buffer, { metadata: { contentType, contentDisposition: 'attachment; filename="' + downloadName + '"' } });
    const expiryDate = new Date(Date.now() + 48 * 60 * 60 * 1000);
    const [url] = await file.getSignedUrl({ action: "read", expires: expiryDate });
    await db.collection("audioFiles").add({
      uid, filename, url,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromDate(expiryDate)
    });
    return { url, filename };
  }
  async function deleteStoredFile(filename) {
    try { await bucket.file(filename).delete(); } catch (e) {}
  }

  async function availableCredits(uid) {
    const doc = await db.collection("users").doc(uid).get();
    if (!doc.exists) return { total: 0, team: false };
    const d = doc.data();
    const now = new Date();
    const freeExp = toDate(d.freeMonthlyCreditsExpiresAt);
    const monthlyExp = toDate(d.monthlyCreditsExpiresAt);
    const free = (freeExp && freeExp > now) ? (d.freeMonthlyCredits || 0) : 0;
    const monthly = (monthlyExp && monthlyExp > now) ? (d.monthlyCredits || 0) : 0;
    return { total: free + monthly + (d.credits || 0), team: !!d.teamId, free, monthly, legacy: d.credits || 0, freeExp, monthlyExp, data: d };
  }

  const fmtDate = (dt) => dt ? dt.toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" }) : "—";
  const youtubeId = (url) => { const m = String(url || "").match(/(?:youtube\.com\/(?:watch\?v=|shorts\/|embed\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/); return m ? m[1] : null; };

  function textResult(text, isError) {
    return { content: [{ type: "text", text }], isError: !!isError };
  }

  // ── The MCP tools ──
  function buildServer(uid) {
    const server = new McpServer({
      name: "AudLabs",
      title: "AudLabs",
      version: "1.1.0",
      websiteUrl: "https://audlabs.io",
      icons: [{ src: "https://audlabs.io/logo-icon.png", mimeType: "image/png" }]
    });

    server.registerTool("check_credits", {
      title: "Check AudLabs credits",
      description: "Shows the user's AudLabs credit balance (free monthly, purchased monthly and lifetime credits) and when each expires.",
      inputSchema: {}
    }, async () => {
      const c = await availableCredits(uid);
      if (!c.data) return textResult("No AudLabs account found for this user.", true);
      return textResult([
        "Total credits available: " + c.total.toLocaleString() + " (1 credit = 1 character)",
        "Free monthly credits: " + c.free.toLocaleString() + (c.free ? " (expire " + fmtDate(c.freeExp) + ")" : ""),
        "Purchased monthly credits: " + c.monthly.toLocaleString() + (c.monthly ? " (expire " + fmtDate(c.monthlyExp) + ")" : ""),
        "Lifetime credits: " + c.legacy.toLocaleString(),
        "Top up: https://app.audlabs.io/buy-credits"
      ].join("\n"));
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

    server.registerTool("get_account_details", {
      title: "AudLabs account details",
      description: "Shows the user's AudLabs profile, usage stats, subscription status and their personal bank transfer (virtual) account for topping up credits.",
      inputSchema: {}
    }, async () => {
      const c = await availableCredits(uid);
      if (!c.data) return textResult("No AudLabs account found for this user.", true);
      const d = c.data;
      const lines = [
        "Name: " + (d.displayName || "—"),
        "Email: " + (d.email || "—"),
        "Voiceovers generated: " + (d.totalGenerations || 0).toLocaleString(),
        "Characters generated: " + (d.totalCharacters || 0).toLocaleString(),
        "Credits available: " + c.total.toLocaleString(),
        "Subscription: " + (c.monthly && c.monthlyExp ? "Active, monthly credits expire " + fmtDate(c.monthlyExp) : "No active subscription")
      ];
      const vas = Array.isArray(d.virtualAccount) ? d.virtualAccount : (d.virtualAccount ? [d.virtualAccount] : []);
      if (vas.length) {
        lines.push("", "Bank transfer account (for buying credits):");
        vas.forEach(function (va) {
          const num = va.accountNumber || va.account_number;
          const bank = va.bankName || va.bank_name;
          const name = va.accountName || va.account_name;
          if (num) lines.push("Account number: " + num);
          if (bank) lines.push("Bank: " + bank);
          if (name) lines.push("Account name: " + name);
        });
        lines.push("Transfer the exact Naira amount shown on the Buy Credits page so your credits are added automatically: https://app.audlabs.io/buy-credits");
      } else {
        lines.push("", "No bank transfer account yet. Open https://app.audlabs.io/buy-credits to create one.");
      }
      return textResult(lines.join("\n"));
    });

    server.registerTool("get_youtube_video_stats", {
      title: "YouTube video stats",
      description: "Shows when a YouTube video was posted, its views, likes and comments, the channel's details, and the video's tags/keywords. Free.",
      inputSchema: { video_url: z.string().describe("A YouTube video link") }
    }, async ({ video_url }) => {
      try {
        const data = await callApi(uid, "post", "/api/video-stats", { videoUrl: video_url });
        const v = data.video, c = data.channel;
        return textResult([
          "Title: " + v.title,
          "Posted: " + new Date(v.publishedAt).toLocaleString("en-US", { month: "long", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit", timeZone: "UTC" }) + " (UTC)",
          "Views: " + Number(v.viewCount).toLocaleString() + " · Likes: " + Number(v.likeCount).toLocaleString() + " · Comments: " + Number(v.commentCount).toLocaleString(),
          "",
          "Channel: " + c.title + " (created " + fmtDate(new Date(c.publishedAt)) + ")",
          "Subscribers: " + (c.subscriberCount === "Hidden" ? "Hidden" : Number(c.subscriberCount).toLocaleString()) + " · Videos: " + Number(c.videoCount).toLocaleString() + " · Total views: " + Number(c.viewCount).toLocaleString(),
          "",
          "Tags: " + ((v.tags && v.tags.length) ? v.tags.join(", ") : "none")
        ].join("\n"));
      } catch (e) { return textResult("Could not get video stats: " + e.message, true); }
    });

    server.registerTool("get_youtube_thumbnail", {
      title: "YouTube thumbnail grabber",
      description: "Returns the full-size thumbnail image link for a YouTube video. Free.",
      inputSchema: { video_url: z.string().describe("A YouTube video link") }
    }, async ({ video_url }) => {
      const id = youtubeId(video_url);
      if (!id) return textResult("That doesn't look like a valid YouTube video link.", true);
      return textResult("Full-size thumbnail: https://img.youtube.com/vi/" + id + "/maxresdefault.jpg\nIf that one doesn't load, use this version: https://img.youtube.com/vi/" + id + "/hqdefault.jpg");
    });

    server.registerTool("translate_script", {
      title: "Translate a script",
      description: "Translates a script into another language using the user's AudLabs credits (1 credit per character of the original script). Supported languages: " + LANGUAGES.join(", ") + ".",
      inputSchema: {
        text: z.string().min(1).max(60000).describe("The script to translate, up to 60,000 characters"),
        target_language: z.enum(LANGUAGES)
      }
    }, async ({ text, target_language }) => {
      try {
        const data = await callApi(uid, "post", "/api/translate-script", { text, targetLang: target_language });
        return textResult("Translated to " + target_language + " (" + text.length.toLocaleString() + " credits used" +
          (data.remaining !== undefined ? ", " + Number(data.remaining).toLocaleString() + " remaining" : "") + "):\n\n" + data.translatedText);
      } catch (e) { return textResult("Translation failed: " + e.message, true); }
    });

    server.registerTool("get_transactions", {
      title: "Recent AudLabs transactions",
      description: "Lists the user's recent credit top-ups and usage.",
      inputSchema: { limit: z.number().int().min(1).max(50).optional().describe("How many to show (default 15)") }
    }, async ({ limit }) => {
      try {
        const data = await callApi(uid, "get", "/api/transactions");
        const list = (data.transactions || []).slice(0, limit || 15);
        if (!list.length) return textResult("No transactions yet.");
        return textResult(list.map(function (t) {
          const sign = t.type === "credit" ? "+" : "-";
          return (t.createdAt ? fmtDate(new Date(t.createdAt)) : "") + "  " + sign + Math.abs(t.amount || 0).toLocaleString() + "  " + (t.note || "");
        }).join("\n"));
      } catch (e) { return textResult("Could not load transactions: " + e.message, true); }
    });

    server.registerTool("get_affiliate_info", {
      title: "AudLabs affiliate earnings",
      description: "Shows the user's AudLabs affiliate (referral) code, commission rate, earnings and recent referrals. Withdrawals can only be made in the AudLabs app.",
      inputSchema: {}
    }, async () => {
      const c = await availableCredits(uid);
      if (!c.data) return textResult("No AudLabs account found for this user.", true);
      const d = c.data;
      const lines = [
        "Referral code: " + (d.referralCode || "—"),
        "Commission rate: " + (d.referralRate || 10) + "% lifetime",
        "People referred: " + (d.referralCount || 0),
        "Earnings available: ₦" + (d.referralEarningsNGN || 0).toLocaleString(),
        "Your referral link and withdrawals are in the Affiliate Program tab: https://app.audlabs.io/refer-earn"
      ];
      try {
        const r = await callApi(uid, "get", "/api/my-referrals");
        const recent = (r.referrals || []).slice(0, 10);
        if (recent.length) {
          lines.push("", "Recent referrals:");
          recent.forEach(function (x) { lines.push("• " + x.firstName + " (" + x.country + ")" + (x.signedUpAt ? ", joined " + fmtDate(new Date(x.signedUpAt)) : "")); });
        }
      } catch (e) {}
      return textResult(lines.join("\n"));
    });

    server.registerTool("search_stock_videos", {
      title: "Search stock video clips",
      description: "Searches HD stock video clips by keywords. Searching is free; downloading costs " + CLIP_COST.toLocaleString() + " credits per clip (use download_stock_clips). For a full script, split it into sections and search each section with specific keywords, including place names where relevant (for example 'Marrakech medina market').",
      inputSchema: {
        keywords: z.string().min(1).max(100).describe("What the footage should show, 1-6 words"),
        orientation: z.enum(["landscape", "portrait", "square"]).optional().describe("landscape for YouTube (default), portrait for Shorts/Reels"),
        duration: z.enum(["any", "1-5s", "5-10s", "10-20s", "20s+"]).optional(),
        count: z.number().int().min(1).max(15).optional().describe("How many clips to return (default 8)")
      }
    }, async ({ keywords, orientation, duration, count }) => {
      const params = { query: keywords, per_page: count || 8, orientation: orientation || "landscape" };
      if (duration === "1-5s") { params.min_duration = 1; params.max_duration = 5; }
      else if (duration === "5-10s") { params.min_duration = 5; params.max_duration = 10; }
      else if (duration === "10-20s") { params.min_duration = 10; params.max_duration = 20; }
      else if (duration === "20s+") { params.min_duration = 20; }
      try {
        const r = await http.get("https://api.pexels.com/videos/search", { headers: { Authorization: process.env.PEXELS_API_KEY }, params, timeout: 30000 });
        const vids = r.data.videos || [];
        if (!vids.length) return textResult("No clips found for \"" + keywords + "\". Try different or more specific keywords.");
        return textResult("Clips for \"" + keywords + "\" (download with download_stock_clips using the clip_id):\n" +
          vids.map(function (v) { return "clip_id " + v.id + " · " + v.duration + "s · " + v.width + "x" + v.height + " · by " + ((v.user && v.user.name) || "unknown"); }).join("\n"));
      } catch (e) { return textResult("Clip search failed. Please try again.", true); }
    });

    server.registerTool("download_stock_clips", {
      title: "Download stock video clips",
      description: "Downloads up to " + MAX_CLIPS_PER_CALL + " stock clips by clip_id and returns download links that work for 48 hours. Costs " + CLIP_COST.toLocaleString() + " credits per clip, capped at " + ALL_CLIPS_COST.toLocaleString() + " credits per request. Larger clips can take a minute.",
      inputSchema: {
        clip_ids: z.array(z.number().int()).min(1).max(MAX_CLIPS_PER_CALL),
        quality: z.enum(["hd", "4k"]).optional().describe("hd (default) or 4k when available")
      }
    }, async ({ clip_ids, quality }) => {
      const ids = Array.from(new Set(clip_ids));
      const useAll = ids.length * CLIP_COST >= ALL_CLIPS_COST;
      const totalCost = useAll ? ALL_CLIPS_COST : ids.length * CLIP_COST;
      const c = await availableCredits(uid);
      if (!c.team && c.total < totalCost) return textResult("Not enough credits. This needs " + totalCost.toLocaleString() + " credits and you have " + c.total.toLocaleString() + ". Top up: https://app.audlabs.io/buy-credits", true);
      const stored = [];
      for (const id of ids) {
        try {
          const info = await http.get("https://api.pexels.com/videos/videos/" + id, { headers: { Authorization: process.env.PEXELS_API_KEY }, timeout: 30000 });
          const files = info.data.video_files || [];
          const file = (quality === "4k" && files.find(function (f) { return f.width >= 3840; })) || files.find(function (f) { return f.quality === "hd"; }) || files[0];
          if (!file) throw new Error("no file");
          const bin = await http.get(file.link, { responseType: "arraybuffer", timeout: 120000, maxContentLength: 400 * 1024 * 1024 });
          const s = await storeFileForUser(uid, Buffer.from(bin.data), "video/mp4", "mp4", "mcp-clips", "audlabs_clip_" + id + ".mp4");
          stored.push({ id, url: s.url, filename: s.filename, res: (file.width || "") + "x" + (file.height || "") });
        } catch (e) {
          console.error("MCP clip download error:", id, e.message);
        }
      }
      if (!stored.length) return textResult("Could not download those clips. Please check the clip_ids and try again. No credits were used.", true);
      let paid = stored;
      let note = "";
      const finalAll = stored.length * CLIP_COST >= ALL_CLIPS_COST;
      if (finalAll) {
        try { await callApi(uid, "post", "/api/deduct-clip-credits", { type: "all" }); }
        catch (e) { for (const f of stored) await deleteStoredFile(f.filename); return textResult("Download failed: " + e.message + " No credits were used.", true); }
      } else {
        paid = [];
        for (const f of stored) {
          try { await callApi(uid, "post", "/api/deduct-clip-credits", { type: "single" }); paid.push(f); }
          catch (e) { await deleteStoredFile(f.filename); note = "\nSome clips were not delivered and not charged: " + e.message; }
        }
        if (!paid.length) return textResult("Download failed: " + note.replace("\nSome clips were not delivered and not charged: ", "") + " No credits were used.", true);
      }
      const cost = finalAll ? ALL_CLIPS_COST : paid.length * CLIP_COST;
      const skipped = ids.length - stored.length;
      return textResult("Your clips are ready (" + cost.toLocaleString() + " credits used). Links work for 48 hours:\n" +
        paid.map(function (f) { return "clip " + f.id + " (" + f.res + "): " + f.url; }).join("\n") +
        (skipped ? "\n" + skipped + " clip(s) could not be downloaded and were not charged." : "") + note);
    });

    server.registerTool("search_music", {
      title: "Find background music",
      description: "Searches royalty-free (CC0) background music and sounds by keyword or mood. Searching is free; downloading costs " + MUSIC_COST.toLocaleString() + " credits per track (use download_music).",
      inputSchema: {
        keywords: z.string().min(1).max(100).describe("Mood or style, for example 'cinematic travel' or 'calm piano'"),
        duration: z.enum(["any", "under 30s", "30s-1min", "1-3min", "3min+"]).optional()
      }
    }, async ({ keywords, duration }) => {
      const ranges = { "any": [0, 600], "under 30s": [0, 30], "30s-1min": [30, 60], "1-3min": [60, 180], "3min+": [180, 600] };
      const rg = ranges[duration || "any"];
      try {
        const data = await callApi(uid, "post", "/api/music-finder", { query: keywords, minDuration: rg[0], maxDuration: rg[1] });
        const list = data.results || [];
        if (!list.length) return textResult("No tracks found for \"" + keywords + "\". Try a different keyword or mood.");
        return textResult("Tracks for \"" + keywords + "\" (download with download_music using the track_id):\n" +
          list.map(function (t) { const m = Math.floor(t.duration / 60), s2 = t.duration % 60; return "track_id " + t.id + " · " + t.name + " · " + m + ":" + (s2 < 10 ? "0" : "") + s2 + " · by " + t.username; }).join("\n"));
      } catch (e) { return textResult("Music search failed: " + e.message, true); }
    });

    server.registerTool("download_music", {
      title: "Download a music track",
      description: "Downloads one royalty-free track by track_id and returns a download link that works for 48 hours. Costs " + MUSIC_COST.toLocaleString() + " credits.",
      inputSchema: { track_id: z.number().int() }
    }, async ({ track_id }) => {
      const c = await availableCredits(uid);
      if (!c.team && c.total < MUSIC_COST) return textResult("Not enough credits. A track costs " + MUSIC_COST.toLocaleString() + " credits and you have " + c.total.toLocaleString() + ". Top up: https://app.audlabs.io/buy-credits", true);
      let stored;
      try {
        const info = await http.get("https://freesound.org/apiv2/sounds/" + track_id + "/", { params: { token: process.env.FREESOUND_API_KEY, fields: "id,name,previews,license" }, timeout: 30000 });
        if (!/creativecommons\.org\/publicdomain\/zero/i.test(info.data.license || "") && !/Creative Commons 0/i.test(info.data.license || "")) {
          return textResult("That track is not CC0-licensed, so AudLabs can't provide it. Please pick another track from search_music.", true);
        }
        const prev = info.data.previews || {};
        const link = prev["preview-hq-mp3"] || prev["preview-lq-mp3"];
        if (!link) throw new Error("no audio");
        const bin = await http.get(link, { responseType: "arraybuffer", timeout: 60000 });
        const safeName = String(info.data.name || "track").replace(/[^a-z0-9]+/gi, "_").slice(0, 40);
        stored = await storeFileForUser(uid, Buffer.from(bin.data), "audio/mpeg", "mp3", "mcp-music", "audlabs_" + safeName + ".mp3");
      } catch (e) {
        console.error("MCP music download error:", e.message);
        return textResult("Could not download that track. No credits were used.", true);
      }
      try {
        const d = await callApi(uid, "post", "/api/deduct-music-credits", {});
        return textResult("Your track is ready (" + MUSIC_COST.toLocaleString() + " credits used" + (d.remaining !== undefined && d.remaining < 999999999 ? ", " + Number(d.remaining).toLocaleString() + " remaining" : "") + "). Link works for 48 hours:\n" + stored.url);
      } catch (e) {
        await deleteStoredFile(stored.filename);
        return textResult("Download failed: " + e.message + " No credits were used.", true);
      }
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
