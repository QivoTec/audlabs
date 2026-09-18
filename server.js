const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const app = express();
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

// ── BLOCK MALICIOUS REQUESTS ──
app.use(function(req, res, next){
  var p = req.path.toLowerCase();
  if(
    p.startsWith("/.") ||
    p.startsWith("/.git") ||
    p.startsWith("/.aws") ||
    p.endsWith(".sql") ||
    p.endsWith(".yml") ||
    p.endsWith(".bak") ||
    p.endsWith(".log") ||
    p.endsWith(".cfg") ||
    p.endsWith(".ini") ||
    p.includes("wp-config") ||
    p.includes("xmlrpc") ||
    p.includes("config.php") ||
    p.includes("settings.py") ||
    p.includes("docker-compose") ||
    p.includes("dump.sql") ||
    p.includes("backup.sql") ||
    p.includes("database.sql")
  ){
    return res.status(404).send("Not found");
  }
  next();
});


// ── CONFIG ──
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET;
const PAYSTACK_BASE = "https://api.paystack.co";
const NOW_API_KEY = process.env.NOW_API_KEY;
const NOW_IPN_SECRET = process.env.NOW_IPN_SECRET;
const FREE_CREDITS = 2000;
const REFERRAL_PCT = 0.10;
const MIN_WITHDRAWAL = 10000;
const FLW_SECRET_KEY = process.env.FLW_SECRET_KEY;
const FLW_WEBHOOK_SECRET = process.env.FLW_WEBHOOK_SECRET;
const ELEVENLABS_API_KEY = process.env.ELEVENLABS_API_KEY;
// ── EMAIL ──
const nodemailer = require("nodemailer");
const emailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  }
});

const audlabsTransporter = nodemailer.createTransport({
  host: "mail.privateemail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.AUDLABS_SMTP_USER,
    pass: process.env.AUDLABS_SMTP_PASS,
  },
  tls: {
    rejectUnauthorized: false
  }
});

const sendbyteTransporter = nodemailer.createTransport({
  host: process.env.SENDBYTE_SMTP_HOST,
  port: parseInt(process.env.SENDBYTE_SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SENDBYTE_SMTP_USER,
    pass: process.env.SENDBYTE_SMTP_PASS,
  }
});

const sesTransporter = nodemailer.createTransport({
  host: process.env.AWS_SES_SMTP_HOST,
  port: parseInt(process.env.AWS_SES_SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.AWS_SES_SMTP_USER,
    pass: process.env.AWS_SES_SMTP_PASS,
  }
});

async function sendWithdrawalAlert(data) {
  try {
    await emailTransporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: `AudLabs — USDT Withdrawal Request: $${data.usdAmount}`,
      html: `
        <h2>New USDT Withdrawal Request</h2>
        <table style="border-collapse:collapse;width:100%;">
          <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">User Email</td><td style="padding:8px;border:1px solid #ddd;">${data.email}</td></tr>
          <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Amount (NGN)</td><td style="padding:8px;border:1px solid #ddd;">₦${data.amountNGN.toLocaleString()}</td></tr>
          <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Amount (USDT)</td><td style="padding:8px;border:1px solid #ddd;">$${data.usdAmount} USDT</td></tr>
          <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Wallet Address</td><td style="padding:8px;border:1px solid #ddd;font-family:monospace;">${data.walletAddress}</td></tr>
          <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Exchange Rate</td><td style="padding:8px;border:1px solid #ddd;">₦${data.rateUsed} per $1</td></tr>
          <tr><td style="padding:8px;border:1px solid #ddd;font-weight:bold;">Time</td><td style="padding:8px;border:1px solid #ddd;">${new Date().toLocaleString()}</td></tr>
        </table>
        <p style="margin-top:16px;color:#888;">Please send the USDT to the wallet address above as soon as possible.</p>
      `
    });

        console.log("✅ Withdrawal alert email sent");
  } catch(e) {
    console.error("Email send failed:", e.message);
  }
}
async function sendPurchaseReceipt(data) {
  try {
    await audlabsTransporter.sendMail({
      from: '"AudLabs" <hello@audlabs.io>',
      to: data.email,
      subject: `Your AudLabs Receipt — ${data.creditsAdded.toLocaleString()} Credits`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;">
          <h2 style="color:#1a1a1a;">Payment Receipt</h2>
          <p style="color:#555;font-size:14px;">Thank you for your purchase! Here are your transaction details:</p>
          <table style="width:100%;border-collapse:collapse;margin:20px 0;">
            <tr><td style="padding:10px 0;border-bottom:1px solid #eee;color:#888;font-size:13px;">Credits Purchased</td><td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;font-weight:700;color:#c9a84c;">${data.creditsAdded.toLocaleString()}</td></tr>
            <tr><td style="padding:10px 0;border-bottom:1px solid #eee;color:#888;font-size:13px;">Amount Paid</td><td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;font-weight:600;">${data.amountDisplay}</td></tr>
            <tr><td style="padding:10px 0;border-bottom:1px solid #eee;color:#888;font-size:13px;">Payment Method</td><td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;">${data.method}</td></tr>
            <tr><td style="padding:10px 0;border-bottom:1px solid #eee;color:#888;font-size:13px;">Reference</td><td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;font-family:monospace;font-size:12px;">${data.reference}</td></tr>
            <tr><td style="padding:10px 0;color:#888;font-size:13px;">Date</td><td style="padding:10px 0;text-align:right;">${new Date().toLocaleString()}</td></tr>
          </table>
          <p style="color:#999;font-size:12px;">Thank you for choosing AudLabs. If you have any questions about this transaction, contact us at hello@audlabs.io.</p>
        </div>
      `
    });
    console.log("✅ Purchase receipt email sent to", data.email);
  } catch(e) {
    console.error("Purchase receipt email failed:", e.message);
  }
}
async function sendWithdrawalReceipt(data) {
  try {
    await audlabsTransporter.sendMail({
      from: '"AudLabs" <hello@audlabs.io>',
      to: data.email,
      subject: `Your AudLabs Withdrawal Receipt — ₦${data.amountNGN.toLocaleString()}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;">
          <h2 style="color:#1a1a1a;">Withdrawal Receipt</h2>
          <p style="color:#555;font-size:14px;">Your affiliate earnings withdrawal has been successfully processed. Here are the details:</p>
          <table style="width:100%;border-collapse:collapse;margin:20px 0;">
            <tr><td style="padding:10px 0;border-bottom:1px solid #eee;color:#888;font-size:13px;">Amount Withdrawn</td><td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;font-weight:700;color:#27ae60;">₦${data.amountNGN.toLocaleString()}</td></tr>
            <tr><td style="padding:10px 0;border-bottom:1px solid #eee;color:#888;font-size:13px;">Payment Method</td><td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;">${data.method}</td></tr>
            <tr><td style="padding:10px 0;border-bottom:1px solid #eee;color:#888;font-size:13px;">Date</td><td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;">${new Date().toLocaleString()}</td></tr>
          </table>
          <p style="color:#999;font-size:12px;">Thank you for being part of the AudLabs Affiliate Program. If you have any questions about this withdrawal, contact us at hello@audlabs.io.</p>
        </div>
      `
    });
    console.log("✅ Withdrawal receipt email sent to", data.email);
  } catch(e) {
    console.error("Withdrawal receipt email failed:", e.message);
  }
}

// ── FIREBASE ──
const admin = require("firebase-admin");
if (!admin.apps.length) {
  let privateKey = process.env.FIREBASE_PRIVATE_KEY || "";
  if (privateKey.startsWith('"')) privateKey = privateKey.slice(1,-1);
  privateKey = privateKey.replace(/\\n/g, "\n");
  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID || "voicegene",
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey,
      })
    });
    console.log("✅ Firebase initialized");
  } catch(e) { console.error("❌ Firebase:", e.message); }
}
const db = admin.firestore();
const bucket = admin.storage().bucket("voicegene.firebasestorage.app");
const ffmpegPath = require("ffmpeg-static");
const { spawn } = require("child_process");
const os = require("os");
// ── HELPERS ──
async function uploadAudioToStorage(audioBuffer, uid, mimeType){
  try {
    const ext = mimeType === "audio/wav" ? "wav" : "mp3";
    const filename = "voiceovers/"+uid+"/"+Date.now()+"."+ext;
    const file = bucket.file(filename);
    await file.save(audioBuffer, {
      metadata: {
        contentType: mimeType,
        contentDisposition: 'attachment; filename="AudLabs_voiceover.mp3"',
        metadata: {
          uid: uid,
          createdAt: Date.now().toString()
        }
      }
    });

    const expiryDate = new Date();
    expiryDate.setHours(expiryDate.getHours() + 48);
    const [url] = await file.getSignedUrl({
      action: "read",
      expires: expiryDate
    });
    await db.collection("audioFiles").add({
      uid: uid,
      filename: filename,
      url: url,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromDate(expiryDate)
    });
    return { url, filename };
  } catch(e){
    console.error("Storage upload failed:", e.message);
    return null;
  }
}
async function verifyUser(req, res) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) { res.status(401).json({ error:"Unauthorized" }); return null; }
  try { return await admin.auth().verifyIdToken(auth.split(" ")[1]); }
  catch(e) { res.status(401).json({ error:"Invalid token" }); return null; }
}

function genRefCode(uid, email, displayName) {
  var base = "";
  if (displayName && displayName.trim()) {
    var first = displayName.trim().split(" ")[0].replace(/[^a-zA-Z]/g,"").toLowerCase();
    if (first.length >= 2) base = first;
  }
  if(!base){
    base = (email||"").split("@")[0].replace(/[^a-z]/gi,"").toLowerCase();
  }
  if(!base) base = uid.slice(0,4).toLowerCase();
  // Add unique suffix from UID to prevent duplicates
  var suffix = uid.slice(-3).toLowerCase().replace(/[^a-z0-9]/g,"");
  // Cap total length at 7 characters, reserving space for the suffix
  var maxBaseLength = 7 - suffix.length;
  base = base.slice(0, maxBaseLength);
  return base + suffix;
}

app.use((req,res,next) => {
  if(["/api/paystack-webhook","/api/crypto-webhook"].includes(req.path)) return next();
  express.json({ limit: "10mb" })(req,res,next);
});
app.use(express.urlencoded({ limit: "10mb", extended: true }));
// ── UPLOAD TEMP AUDIO CHUNK ──
app.post("/api/upload-audio-chunk", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { sessionId, chunkIndex, audioBase64 } = req.body;
    if(!sessionId || chunkIndex === undefined || !audioBase64) return res.status(400).json({ error:"sessionId, chunkIndex, and audioBase64 are required" });
    const buffer = Buffer.from(audioBase64, "base64");
    const filename = "temp-chunks/" + user.uid + "/" + sessionId + "/chunk" + chunkIndex + ".mp3";
    const file = bucket.file(filename);
    await file.save(buffer, { metadata: { contentType: "audio/mpeg" } });
    return res.json({ success:true });
  } catch(e){
    console.error("Chunk upload failed:", e.message);
    return res.status(500).json({ error:"Failed to upload audio chunk: " + e.message });
  }
});
// ── MERGE UPLOADED CHUNKS (SERVER-SIDE, VIA STORAGE) ──
app.post("/api/merge-uploaded-chunks", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { sessionId, totalChunks } = req.body;
  if(!sessionId || !totalChunks) return res.status(400).json({ error:"sessionId and totalChunks are required" });
  const tempDir = path.join(os.tmpdir(), "audlabs-merge-" + sessionId);
  const storagePrefix = "temp-chunks/" + user.uid + "/" + sessionId + "/";
  try {
    fs.mkdirSync(tempDir, { recursive: true });
    const inputFiles = [];
    for(let i = 0; i < totalChunks; i++){
      const storagePath = storagePrefix + "chunk" + i + ".mp3";
      const localPath = path.join(tempDir, "chunk" + i + ".mp3");
      await bucket.file(storagePath).download({ destination: localPath });
      inputFiles.push(localPath);
    }
    const listFilePath = path.join(tempDir, "list.txt");
    const listContent = inputFiles.map(function(f){ return "file '" + f.replace(/'/g, "'\\''") + "'"; }).join("\n");
    fs.writeFileSync(listFilePath, listContent);
    const outputPath = path.join(tempDir, "output.mp3");
    await new Promise(function(resolve, reject){
      const ffmpegArgs = ["-f","concat","-safe","0","-i",listFilePath,"-acodec","libmp3lame","-ar","32000","-ab","128k","-y",outputPath];
      const ffmpegProcess = spawn(ffmpegPath, ffmpegArgs);
      let stderrOutput = "";
      ffmpegProcess.stderr.on("data", function(data){ stderrOutput += data.toString(); });
      ffmpegProcess.on("close", function(code){
        if(code === 0) resolve();
        else reject(new Error("ffmpeg exited with code " + code + ": " + stderrOutput.slice(-500)));
      });
      ffmpegProcess.on("error", function(err){ reject(err); });
    });
    const mergedBuffer = fs.readFileSync(outputPath);
    fs.rmSync(tempDir, { recursive: true, force: true });

          try {
      const [files] = await bucket.getFiles({ prefix: storagePrefix });
      console.log("Cleanup found", files.length, "files for prefix:", storagePrefix);
      await Promise.all(files.map(function(f){ return f.delete().catch(function(delErr){ console.warn("Failed to delete", f.name, ":", delErr.message); }); }));
      console.log("Cleanup completed for session:", sessionId);
    } catch(cleanupErr){ console.warn("Storage cleanup failed:", cleanupErr.message); }
    res.set("Content-Type", "audio/mpeg");
    res.set("Content-Length", mergedBuffer.length);
    return res.send(mergedBuffer);
  } catch(e){
    console.error("Merge from storage failed:", e.message);
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch(cleanupErr2){}
    return res.status(500).json({ error:"Failed to merge audio: " + e.message });
  }
});
// ── TRACK SIGNUP LOCATION ──
app.post("/api/track-signup-source", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    const { trafficSource } = req.body;
    const userIP = (req.headers['x-forwarded-for']||"").split(',')[0].trim() || req.socket.remoteAddress || "";
    let location = { country: "Unknown", state: "Unknown", city: "Unknown" };
    if(userIP && userIP !== "unknown"){
      try {
        const geoRes = await axios.get(`http://ip-api.com/json/${userIP}?fields=status,country,regionName,city`, { timeout: 5000 });
        if(geoRes.data?.status === "success"){
          location = {
            country: geoRes.data.country || "Unknown",
            state: geoRes.data.regionName || "Unknown",
            city: geoRes.data.city || "Unknown"
          };
        }
      } catch(geoErr){ console.warn("Geolocation lookup failed:", geoErr.message); }
    }
        await db.collection("users").doc(user.uid).set({
      trafficSource: trafficSource || "Direct / Unknown",
      location: location
    }, { merge: true });
    return res.json({ success:true });
  } catch(e){
    console.error("Track signup source error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── SETUP ACCOUNT ──
app.post("/api/setup-account", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { uid, email, name } = { uid:user.uid, email:user.email, name:user.name||user.email.split("@")[0] };
  try {
    try {
      const userDoc2 = await db.collection("users").doc(uid).get();
      if(!userDoc2.exists){
        const userIP = (req.headers['x-forwarded-for']||"").split(',')[0].trim() || req.socket.remoteAddress || "unknown";
        const ipKey = userIP.replace(/[.:]/g,"_");
        const ipDoc = await db.collection("ipSignups").doc(ipKey).get();
        if(ipDoc.exists && (ipDoc.data().count||0) >= 2){
          return res.status(429).json({ error:"Maximum accounts reached for this device. Please sign in instead or contact support at hello@audlabs.io" });
        }
        await db.collection("ipSignups").doc(ipKey).set({ count: admin.firestore.FieldValue.increment(1), lastSignup: admin.firestore.FieldValue.serverTimestamp() }, {merge:true});
      }
    } catch(ipErr){ console.warn("IP check failed:", ipErr.message); }


  
    const userDoc = await db.collection("users").doc(uid).get();
    const refCode = req.body?.refCode || "";
    console.log("setup-account called for:", email, "refCode:", refCode);
    
    // Process referral code first (before early return)
    let referredBy = null;
    if (refCode) {
      const refSnap = await db.collection("users").where("referralCode","==",refCode).limit(1).get();
      if (!refSnap.empty && refSnap.docs[0].id !== uid) {
        referredBy = refSnap.docs[0].id;
        console.log("Referral found - referredBy:", referredBy);
      }
    }
    
    if (userDoc.exists && userDoc.data().virtualAccount) {
      // Already has virtual account
      const existingData = userDoc.data();
      // Save referredBy if not already set and refCode provided
      if (referredBy && !existingData.referredBy) {
        const referrerDocSnap = await db.collection("users").doc(referredBy).get();
        const referrerRate = referrerDocSnap.exists && referrerDocSnap.data().referralRate ? referrerDocSnap.data().referralRate : 10;
        await db.collection("users").doc(uid).update({ referredBy, referralCommissionRate: referrerRate });
        console.log("Saved referredBy for existing user:", referredBy, "at rate:", referrerRate+"%");
      }
      // Give credits if email just got verified and credits are still 0
      const firebaseUser2 = await admin.auth().getUser(uid);
      if(firebaseUser2.emailVerified && (existingData.credits||0) === 0 && !existingData.creditsGiven){
        await db.collection("users").doc(uid).update({
          credits: FREE_CREDITS,
          creditsGiven: true,
          emailVerified: true
        });
        await db.collection("users").doc(uid).collection("transactions").add({
          type:"credit", amount:FREE_CREDITS,
          note:"Welcome Bonus — 2,000 free credits to get you started! 🎙",
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        existingData.credits = FREE_CREDITS;
        console.log("Credits given to newly verified user:", email);
      }
      return res.json({ success:true, data:{...existingData, referredBy: referredBy||existingData.referredBy} });
    }

    // User exists but no virtual account - will retry creating one below
    const myRefCode = genRefCode(uid, email, req.body?.displayName||name);
    let virtualAccount = null;

    // Create Paystack Dedicated Virtual Account
    try {
      console.log("Creating Paystack customer for:", email);
      const firstName = name.split(" ")[0] || name;
      const lastName = name.split(" ").slice(1).join(" ") || firstName;
      let customerCode;
      try {
        const custRes = await axios.post(`${PAYSTACK_BASE}/customer`, {
          email, first_name: firstName, last_name: lastName, phone: "+2348000000000"
        }, { headers: { Authorization:`Bearer ${PAYSTACK_SECRET}`, "Content-Type":"application/json" }});
        if(!custRes.data.status) throw new Error(custRes.data.message);
        customerCode = custRes.data.data.customer_code;
      } catch(custErr){
        const fetchRes = await axios.get(`PAYSTACKBASE/customer/{email}`,
          { headers: { Authorization:`Bearer ${PAYSTACK_SECRET}` }});
        if(fetchRes.data.status && fetchRes.data.data?.customer_code){
          customerCode = fetchRes.data.data.customer_code;
        } else {
          throw new Error("Could not create or fetch customer");
        }
      }
      for(const bank of ["titan-paystack","wema-bank"]){
        try {
          const vaRes = await axios.post(`${PAYSTACK_BASE}/dedicated_account`, {
            customer: customerCode, preferred_bank: bank
          }, { headers: { Authorization:`Bearer ${PAYSTACK_SECRET}`, "Content-Type":"application/json" }});
          if(vaRes.data.status && vaRes.data.data){
            const va = vaRes.data.data;
            virtualAccount = {
              bankName: va.bank?.name || "Titan Trust Bank",
              accountNumber: va.account_number,
              accountName: va.account_name
            };
            console.log("Paystack VA created:", virtualAccount.accountNumber);
            break;
          }
        } catch(e){ console.log("Bank",bank,"failed:",e.response?.data?.message||e.message); }
      }
      if(!virtualAccount) throw new Error("All banks failed");
    } catch(paErr){
      console.error("Paystack VA error:", paErr.response?.data || paErr.message);
    }


    // Check if email is verified
const firebaseUser = await admin.auth().getUser(uid);
const emailVerified = firebaseUser.emailVerified;
const creditsToGive = emailVerified ? FREE_CREDITS : 0;

const userData = {
  uid, email, name,
  credits: creditsToGive,
  emailVerified: emailVerified,
      virtualAccount: virtualAccount || null,
      referralCode: myRefCode,
      referredBy: referredBy || null,
      referralCommissionRate: referredBy ? await (async () => {
        try {
          const refDoc = await db.collection("users").where("referralCode","==", refCode).limit(1).get();
          if(!refDoc.empty && refDoc.docs[0].data().referralRate) return refDoc.docs[0].data().referralRate;
          return 10;
        } catch(e){ return 10; }
      })() : 10,
      referralEarningsNGN: 0,
      referralCount: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    console.log("Creating user:", email, "referralCode:", myRefCode, "referredBy:", referredBy);
    await db.collection("users").doc(uid).set(userData, { merge:true });
    if(emailVerified){
await db.collection("users").doc(uid).collection("transactions").add({
  type:"credit", amount:FREE_CREDITS, 
  note:"Welcome Bonus — 2,000 free credits to get you started! 🎙",
  createdAt: admin.firestore.FieldValue.serverTimestamp(),
});
}

try {
  await audlabsTransporter.sendMail({
    from: `"AudLabs" <${process.env.AUDLABS_SMTP_USER}>`,
    to: email,
    subject: "Welcome to AudLabs — Your 2000 Free Credits Are Ready! 🎙",
    html: `
      <div style="font-family:Inter,sans-serif;max-width:600px;margin:0 auto;background:#080c14;color:#fff;padding:40px;border-radius:16px;">
        <div style="text-align:center;margin-bottom:32px;">
          <h1 style="font-size:28px;font-weight:300;color:#fff;">Welcome to <span style="color:#c9a84c;">AudLabs</span></h1>
          <p style="color:rgba(255,255,255,0.6);font-size:15px;">AI-Powered Voice Generation Platform.</p>
        </div>
        <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">Hi ${name},</p>
        <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">Welcome to AudLabs! We are excited to have you on board. Your account has been created successfully and we have added <strong style="color:#c9a84c;">2000 free credits</strong> to get you started.</p>
        <div style="background:rgba(201,168,76,0.1);border:1px solid rgba(201,168,76,0.3);border-radius:12px;padding:24px;margin:24px 0;text-align:center;">
          <div style="font-size:36px;font-weight:700;color:#c9a84c;">2,000</div>
<div style="font-size:14px;color:rgba(255,255,255,0.6);margin-top:4px;">Free Credits Added to Your Account.</div>
        </div>
        <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">With AudLabs you can:</p>
        <ul style="color:rgba(255,255,255,0.7);font-size:14px;line-height:2;">
          <li>🎙 Generate professional voiceovers with 50+ AI voices.</li>
          <li>⚡ Clone any voice instantly.</li>
          <li>📥 Download in high quality MP3.</li>
          <li>🌍 Generate in 10+ languages.</li>
        </ul>
        <div style="text-align:center;margin:32px 0;">
          <a href="https://t.me/AudLabs" style="background:linear-gradient(135deg,#c9a84c,#e8c97a);color:#111;padding:10px 24px;border-radius:10px;text-decoration:none;font-weight:700;font-size:13px;">Join Our Telegram Channel</a>
        </div>
        <p style="font-size:13px;color:rgba(255,255,255,0.4);text-align:center;margin-top:32px;">Follow us for updates: <a href="https://x.com/AudLabs" style="color:#c9a84c;">X</a> · <a href="https://youtube.com/@AudLabs" style="color:#c9a84c;">YouTube</a> · <a href="https://t.me/AudLabs" style="color:#c9a84c;">Telegram</a></p>
        <p style="font-size:12px;color:rgba(255,255,255,0.3);text-align:center;">© 2026 AudLabs. All rights reserved.</p>
      </div>
    `
  });
  console.log("✅ Welcome email sent to:", email);
} catch(emailErr){
  console.warn("Welcome email failed:", emailErr.message);
}


    if (referredBy) {
      console.log("Incrementing referral count for:", referredBy);
      await db.collection("users").doc(referredBy).update({
        referralCount: admin.firestore.FieldValue.increment(1),
      });
    }

    return res.json({ success:true, data:userData });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── LEADERBOARD CACHE ──
let leaderboardCache = [];
let leaderboardLastUpdated = null;

async function buildLeaderboard(){
try {
const excludedUids = ["9wHZC04fOlWqNhS1Pnnn2r92taf1", "eutZiD4PPOcHOVXoYEwdKbGl16p2", "ZjEAZtw4xHc5wW19KIfQD080w8u2"];
const snap = await db.collection("users").orderBy("totalCharacters","desc").limit(20).get();
leaderboardCache = snap.docs.filter(function(d){ return !excludedUids.includes(d.id); }).slice(0,10).map(function(d, i){
var data = d.data();
var firstName = "Creator";
if(data.displayName && data.displayName.trim()){
firstName = data.displayName.trim().split(" ")[0];
} else if(data.email){
firstName = data.email.split("@")[0].replace(/[0-9._]/g,"").trim();
}
if(!firstName) firstName = "Creator";
firstName = firstName.charAt(0).toUpperCase() + firstName.slice(1).toLowerCase();
return {
rank: i+1,
firstName: firstName,
totalCharacters: data.totalCharacters || 0
};
});
leaderboardLastUpdated = new Date();
// Save to Firestore cache so server restarts don't re-query
await db.collection("cache").doc("leaderboard").set({
leaderboard: leaderboardCache,
lastUpdated: admin.firestore.FieldValue.serverTimestamp()
});
console.log("Leaderboard updated and cached:", leaderboardCache.length, "creators");
} catch(e){
console.error("Leaderboard build error:", e.message);
}
}

// Build leaderboard 5 seconds after server start only if not updated today
setTimeout(async function(){
try {
var cacheDoc = await db.collection("cache").doc("leaderboard").get();
if(cacheDoc.exists){
var cacheData = cacheDoc.data();
var lastUpdated = cacheData.lastUpdated ? cacheData.lastUpdated.toDate() : null;
var now = new Date();
var hoursSince = lastUpdated ? (now - lastUpdated) / (1000*60*60) : 999;
if(hoursSince < 24){
leaderboardCache = cacheData.leaderboard || [];
leaderboardLastUpdated = lastUpdated;
console.log("Leaderboard loaded from cache — skipping Firestore query");
return;
}
}
buildLeaderboard();
} catch(e){
console.error("Leaderboard cache check error:", e.message);
}
}, 5000);

// ── SEND CAMPAIGN EMAIL ──
app.post("/api/send-campaign", async (req,res) => {
const cronSecret = req.headers["x-cron-secret"];
const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
if(cronSecret !== "audlabs-monthly-2026" && !isAdmin) return res.status(401).json({ error:"Unauthorized" });
const testMode = req.headers["x-test-mode"] === "true";
try {
let users = [];
if(testMode){
users = [{email:"demolaadeyemo0@gmail.com", displayName:"Adeyemo", totalGenerations:10, referralCode:"aud"}];
console.log("Test mode - sending to:", users[0].email);
// Skip campaign tracking for test mode

} else {
const snap = await db.collection("users").select("email","displayName","totalGenerations").get();
users = snap.docs.map(function(d){ return d.data(); }).filter(function(u){
  if(!u.email) return false;
  var email = u.email.toLowerCase();
  // Filter out obviously fake emails
  var fakeDomains = ["tongtode.com","sudaley.com","llllan","lagagh","lastgg","lastt","laga.com"];
  for(var fd of fakeDomains){ if(email.includes(fd)) return false; }
  // Filter out emails with random character patterns
  var localPart = email.split("@")[0];
  if(/^[a-z0-9]{15,}$/.test(localPart)) return false;
  return true;
});
console.log("Total users to email:", users.length);
// Limit to 100 per batch to avoid Vercel timeout
}
const campaignId = req.headers["x-campaign-id"] || "campaign-feedback-august-2026";
console.log("Campaign ID:", campaignId);

// Filter out users who already received this campaign (skip for test mode)
if(!testMode){
  const sentSnap = await db.collection("campaignSent").doc(campaignId).get();
  const alreadySent = sentSnap.exists ? (sentSnap.data().emails || []) : [];
  users = users.filter(function(u){ return u.email && !alreadySent.includes(u.email); });
}
console.log("Remaining users to email:", users.length);
const batchSize = 100;
users = users.slice(0, batchSize);
console.log("Sending next batch of:", users.length);
let sent = 0, failed = 0;
for(const userData of users){
if(!userData.email) continue;
try {
var firstName = "";
if(userData.displayName && userData.displayName.trim()){
firstName = userData.displayName.trim().split(" ")[0];
} else if(userData.email){
firstName = userData.email.split("@")[0].replace(/[0-9._]/g,"").trim();
}
if(!firstName) firstName = "Creator";
firstName = firstName.charAt(0).toUpperCase() + firstName.slice(1).toLowerCase();
var hasGenerated = (userData.totalGenerations || 0) > 0;
await sesTransporter.sendMail({
from: 'Adeyemo from AudLabs <hello@audlabs.io>',
to: userData.email,
subject: `${firstName}, what's missing from AudLabs?`,
html: `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
<tr><td style="background:#0a1628;padding:24px 32px;text-align:left;">
<span style="font-size:22px;font-weight:700;color:#c9a84c;letter-spacing:1px;">AudLabs</span>
</td></tr>
<tr><td style="padding:32px;">
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 16px;">Hi ${firstName},</p>
<p style="font-size:14px;color:#555;line-height:1.8;margin:0 0 16px;">I want to ask you something directly: what's the one feature you wish AudLabs had?</p>
<p style="font-size:14px;color:#555;line-height:1.8;margin:0 0 16px;">Maybe it's something small — a setting you keep wishing existed. Maybe it's something bigger — a whole new capability that would change how you use the platform. Maybe it's something you've mentioned to a friend but never actually told me.</p>
<p style="font-size:14px;color:#555;line-height:1.8;margin:0 0 16px;">Whatever it is, I want to hear it.</p>
<p style="font-size:14px;color:#555;line-height:1.8;margin:0 0 16px;">I read every single reply personally, and the features we've built over the past few months — the Transcript Extractor, improved voice cloning, the developer API — all came from listening to what creators like you actually needed. This one could be next.</p>
<p style="font-size:14px;color:#555;line-height:1.8;margin:0 0 24px;">Just hit reply and tell me. One sentence is enough. I'm genuinely listening.</p>
<p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 4px;">Talk soon,</p>
<p style="font-size:15px;color:#333;margin:0;"><strong>Adeyemo Oluwaseyi</strong><br><span style="font-size:13px;color:#888;">Founder, AudLabs</span></p>
</td></tr>
<tr><td style="background:#f8f9fa;padding:16px 32px;border-top:1px solid #eee;">
<p style="font-size:11px;color:#bbb;margin:0;text-align:center;">You are receiving this because you created an account at audlabs.io. Reply to unsubscribe.</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
});


sent++;

await db.collection("campaignSent").doc(campaignId).set({
  emails: admin.firestore.FieldValue.arrayUnion(userData.email),
  updatedAt: admin.firestore.FieldValue.serverTimestamp()
}, {merge:true});
await new Promise(function(resolve){ setTimeout(resolve, 100); });

} catch(emailErr){
console.error("Failed to send to:", userData.email, emailErr.message);
failed++;
}
}
console.log("Campaign sent:", sent, "success,", failed, "failed");
return res.json({ success:true, sent, failed });
} catch(e){
console.error("Campaign error:", e.message);
return res.status(500).json({ error:e.message });
}
});
// ── SAVE CAMPAIGN (DYNAMIC) ──
app.post("/api/admin/save-campaign", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const { name, subject, htmlBody } = req.body;
    if(!name || !subject || !htmlBody) return res.status(400).json({ error:"name, subject, and htmlBody are required" });
    const slug = name.toLowerCase().trim().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"");
    if(!slug) return res.status(400).json({ error:"Invalid campaign name" });
    const existing = await db.collection("emailCampaigns").doc(slug).get();
    if(existing.exists && existing.data().sentAt) return res.status(400).json({ error:"A campaign with this name has already been sent. Please choose a different name." });
    await db.collection("emailCampaigns").doc(slug).set({
      name: name.trim(),
      slug: slug,
      subject: subject,
      htmlBody: htmlBody,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      sentAt: existing.exists ? (existing.data().sentAt || null) : null
    }, { merge: true });
    return res.json({ success:true, slug: slug });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});
// ── LIST CAMPAIGNS (DYNAMIC) ──
app.get("/api/admin/campaigns-list", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const snap = await db.collection("emailCampaigns").orderBy("createdAt","desc").limit(50).get();
    const campaigns = snap.docs.map(function(d){
      const data = d.data();
      return {
        slug: d.id,
        name: data.name,
        subject: data.subject,
        htmlBody: data.htmlBody,
        createdAt: data.createdAt ? new Date(data.createdAt._seconds*1000).toISOString() : null,
        sentAt: data.sentAt ? new Date(data.sentAt._seconds*1000).toISOString() : null,
        sentCount: data.sentCount || 0,
        failedCount: data.failedCount || 0
      };
    });
    return res.json({ success:true, campaigns: campaigns });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});
// ── SEND CAMPAIGN (DYNAMIC) ──
app.post("/api/admin/send-campaign-v2", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  const testMode = req.headers["x-test-mode"] === "true";
  try {
    const { slug } = req.body;
    if(!slug) return res.status(400).json({ error:"slug is required" });
    const campaignDoc = await db.collection("emailCampaigns").doc(slug).get();
    if(!campaignDoc.exists) return res.status(404).json({ error:"Campaign not found" });
    const campaign = campaignDoc.data();
    let users = [];
    if(testMode){
      users = [{email:"demolaadeyemo0@gmail.com", displayName:"Adeyemo"}];
    } else {
      const snap = await db.collection("users").select("email","displayName").get();
      users = snap.docs.map(function(d){ return d.data(); }).filter(function(u){
        if(!u.email) return false;
        var email = u.email.toLowerCase();
        var fakeDomains = ["tongtode.com","sudaley.com","llllan","lagagh","lastgg","lastt","laga.com"];
        for(var fd of fakeDomains){ if(email.includes(fd)) return false; }
        var localPart = email.split("@")[0];
        if(/^[a-z0-9]{15,}$/.test(localPart)) return false;
        return true;
      });
      const sentSnap = await db.collection("campaignSent").doc(slug).get();
      const alreadySent = sentSnap.exists ? (sentSnap.data().emails || []) : [];
      users = users.filter(function(u){ return u.email && !alreadySent.includes(u.email); });
    }
    const batchSize = 100;
    users = users.slice(0, batchSize);
    let sent = 0, failed = 0;
    for(const userData of users){
      if(!userData.email) continue;
      try {
        var firstName = "";
        if(userData.displayName && userData.displayName.trim()){
          firstName = userData.displayName.trim().split(" ")[0];
        } else if(userData.email){
          firstName = userData.email.split("@")[0].replace(/[0-9._]/g,"").trim();
        }
        if(!firstName) firstName = "Creator";
        firstName = firstName.charAt(0).toUpperCase() + firstName.slice(1).toLowerCase();
                var personalizedHtml = campaign.htmlBody.split("${firstName}").join(firstName).split("{{firstName}}").join(firstName);
        var personalizedSubject = campaign.subject.split("${firstName}").join(firstName).split("{{firstName}}").join(firstName);
        var trackingId = slug + "_" + Buffer.from(userData.email).toString("base64").replace(/[^a-zA-Z0-9]/g,"");
        var trackingPixel = '<img src="https://app.audlabs.io/api/track-email-open?id=' + trackingId + '" width="1" height="1" style="display:none;" alt="">';
        personalizedHtml = personalizedHtml.replace("</body>", trackingPixel + "</body>");
        await sesTransporter.sendMail({
          from: 'Adeyemo from AudLabs <hello@audlabs.io>',
          to: userData.email,
          subject: personalizedSubject,
          html: personalizedHtml
        });
        sent++;
        if(!testMode){
          await db.collection("campaignSent").doc(slug).set({
            emails: admin.firestore.FieldValue.arrayUnion(userData.email),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
          }, {merge:true});
        }
        await new Promise(function(resolve){ setTimeout(resolve, 100); });
      } catch(emailErr){
        console.error("Failed to send to:", userData.email, emailErr.message);
        failed++;
      }
    }
    if(!testMode){
      await db.collection("emailCampaigns").doc(slug).set({
        sentAt: admin.firestore.FieldValue.serverTimestamp(),
        sentCount: admin.firestore.FieldValue.increment(sent),
        failedCount: admin.firestore.FieldValue.increment(failed)
      }, {merge:true});
    }
        return res.json({ success:true, sent, failed });
  } catch(e){
    console.error("Dynamic campaign error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── TRACK EMAIL OPEN ──
const TRANSPARENT_PIXEL = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBTAA7", "base64");
app.get("/api/track-email-open", async (req,res) => {
  try {
    const id = req.query.id;
    if(id){
      const underscoreIndex = id.indexOf("_");
      const slug = underscoreIndex > -1 ? id.substring(0, underscoreIndex) : id;
      await db.collection("emailCampaigns").doc(slug).collection("opens").doc(id).set({
        openedAt: admin.firestore.FieldValue.serverTimestamp(),
        count: admin.firestore.FieldValue.increment(1)
      }, { merge: true });
    }
  } catch(e){
    console.error("Track open error:", e.message);
  }
  res.set("Content-Type", "image/gif");
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.send(TRANSPARENT_PIXEL);
});
// ── GET CAMPAIGN OPEN STATS ──
app.get("/api/admin/campaign-opens", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const slug = req.query.slug;
    if(!slug) return res.status(400).json({ error:"slug is required" });
        const opensSnap = await db.collection("emailCampaigns").doc(slug).collection("opens").get();
    return res.json({ success:true, uniqueOpens: opensSnap.size });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});
// ── DELETE DRAFT CAMPAIGN ──
app.post("/api/admin/delete-campaign", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const { slug } = req.body;
    if(!slug) return res.status(400).json({ error:"slug is required" });
    const campaignDoc = await db.collection("emailCampaigns").doc(slug).get();
    if(!campaignDoc.exists) return res.status(404).json({ error:"Campaign not found" });
    if(campaignDoc.data().sentAt) return res.status(400).json({ error:"Cannot delete a campaign that has already been sent." });
    await db.collection("emailCampaigns").doc(slug).delete();
    return res.json({ success:true });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});
// ── REBUILD LEADERBOARD (CRON) ──
app.post("/api/rebuild-leaderboard", async (req,res) => {
const cronSecret = req.headers["x-cron-secret"];
const vercelCron = req.headers["x-vercel-cron-schedule"];
if(!vercelCron && cronSecret !== "audlabs-monthly-2026") return res.status(401).json({ error:"Unauthorized" });
await buildLeaderboard();
return res.json({ success:true, count: leaderboardCache.length });
});

// ── REBUILD LEADERBOARD (GET — for Vercel cron) ──
app.get("/api/rebuild-leaderboard-cron", async (req,res) => {
const vercelCron = req.headers["x-vercel-cron-schedule"];
if(!vercelCron) return res.status(401).json({ error:"Unauthorized" });
await buildLeaderboard();
return res.json({ success:true, count: leaderboardCache.length });
});

// ── LEADERBOARD ENDPOINT ──
app.get("/api/leaderboard", async (req,res) => {
const user = await verifyUser(req,res);
if(!user) return;
return res.json({
success: true,
leaderboard: leaderboardCache,
lastUpdated: leaderboardLastUpdated
});
});

// ── CHECK MINIMAX STATUS ──
app.get("/api/minimax-status", async (req,res) => {
  try {
    const statusDoc = await db.collection("cache").doc("minimaxStatus").get();
    if(statusDoc.exists){
      const data = statusDoc.data();
      // Auto reset after 6 hours
      if(data.exhausted && data.exhaustedAt){
        const exhaustedAt = data.exhaustedAt.toDate();
        const hoursSince = (Date.now() - exhaustedAt.getTime()) / (1000 * 60 * 60);
        if(hoursSince > 6){
          await db.collection("cache").doc("minimaxStatus").set({
            exhausted: false,
            resetAt: admin.firestore.FieldValue.serverTimestamp()
          }, {merge: true});
          return res.json({ exhausted: false });
        }
      }
      return res.json(data);
    }
    return res.json({ exhausted: false });
  } catch(e){
    return res.json({ exhausted: false });
  }
});


// ── VIDEO STATS ──
app.post("/api/video-stats", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { videoUrl } = req.body;
    if(!videoUrl) return res.status(400).json({ error:"videoUrl is required" });
    const idMatch = videoUrl.match(/(?:youtube\.com\/(?:watch\?v=|shorts\/|embed\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
    if(!idMatch) return res.status(400).json({ error:"Invalid YouTube URL. Please paste a valid video link." });
    const videoId = idMatch[1];
    const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY;
    const videoRes = await axios.get("https://www.googleapis.com/youtube/v3/videos", {
      params: { part: "snippet,statistics,contentDetails", id: videoId, key: YOUTUBE_API_KEY }
    });
    if(!videoRes.data.items || !videoRes.data.items.length){
      return res.status(404).json({ error:"Video not found. It may be private, deleted, or the link is incorrect." });
    }
    const video = videoRes.data.items[0];
    const channelId = video.snippet.channelId;
    const channelRes = await axios.get("https://www.googleapis.com/youtube/v3/channels", {
      params: { part: "snippet,statistics", id: channelId, key: YOUTUBE_API_KEY }
    });
    const channel = channelRes.data.items[0];
    return res.json({
      success: true,
      video: {
        title: video.snippet.title,
        description: video.snippet.description,
        publishedAt: video.snippet.publishedAt,
        tags: video.snippet.tags || [],
        viewCount: video.statistics.viewCount || "0",
        likeCount: video.statistics.likeCount || "0",
        commentCount: video.statistics.commentCount || "0",
        duration: video.contentDetails.duration,
        thumbnail: video.snippet.thumbnails?.high?.url || video.snippet.thumbnails?.default?.url
      },
      channel: {
        title: channel.snippet.title,
        description: channel.snippet.description,
        publishedAt: channel.snippet.publishedAt,
        subscriberCount: channel.statistics.subscriberCount || "Hidden",
        videoCount: channel.statistics.videoCount || "0",
        viewCount: channel.statistics.viewCount || "0",
        thumbnail: channel.snippet.thumbnails?.high?.url || channel.snippet.thumbnails?.default?.url
      }
    });
  } catch(e){
        console.error("Video stats error:", e.response?.data || e.message);
    return res.status(500).json({ error:"Failed to fetch video stats. Please try again." });
  }
});
// ── MUSIC FINDER ──
app.post("/api/music-finder", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { query, minDuration, maxDuration } = req.body;
    if(!query) return res.status(400).json({ error:"query is required" });
    const FREESOUND_API_KEY = process.env.FREESOUND_API_KEY;
    const minDur = minDuration || 0;
    const maxDur = maxDuration || 600;
    const searchQuery = query.toLowerCase().includes("music") ? query : query + " music";
    const filterStr = `duration:[${minDur} TO ${maxDur}] license:"Creative Commons 0"`;
    const searchRes = await axios.get("https://freesound.org/apiv2/search/text/", {
      params: {
        query: searchQuery,
        filter: filterStr,
        fields: "id,name,duration,previews,tags,username,license,download",
        page_size: 20,
        token: FREESOUND_API_KEY
      }
    });
    const results = (searchRes.data.results || []).map(function(track){
      return {
        id: track.id,
        name: track.name,
        duration: Math.round(track.duration),
        previewUrl: track.previews["preview-hq-mp3"] || track.previews["preview-lq-mp3"],
        tags: track.tags || [],
        username: track.username,
        license: "CC0 (Free to use)"
      };
    });
    return res.json({ success: true, results: results, count: searchRes.data.count });
  } catch(e){
    console.error("Music finder error:", e.response?.data || e.message);
    return res.status(500).json({ error:"Failed to search for music. Please try again." });
  }
});
// ── BALANCE ──
app.get("/api/balance", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const doc = await db.collection("users").doc(user.uid).get();
    if (!doc.exists) return res.json({ credits:0, virtualAccount:null });
    const d = doc.data();
    return res.json({
      credits: d.credits||0,
      virtualAccount: d.virtualAccount||null,
      virtualAccounts: d.virtualAccount ? [d.virtualAccount] : [],
      referralCode: d.referralCode||"",
      referralEarningsNGN: d.referralEarningsNGN||0,
      referralCount: d.referralCount||0,
      totalCharacters: d.totalCharacters||0,
      totalGenerations: d.totalGenerations||0,
      favVoice: d.voiceCount ? Object.keys(d.voiceCount).reduce(function(a,b){ return d.voiceCount[a]>d.voiceCount[b]?a:b; }) : "—",
            teamId: d.teamId||"",
      hasPurchased: d.hasPurchased||false,
      referralRate: d.referralRate||10,
      hasSeenDownloadWarning: d.hasSeenDownloadWarning||false,
    });

  } catch(e) { return res.status(500).json({ error:e.message }); }
});


// ── TRANSLATE SCRIPT ──
app.post("/api/translate-script", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { text, targetLang } = req.body;
    if(!text || !targetLang) return res.status(400).json({ error:"text and targetLang required" });
    if(text.length > 60000) return res.status(400).json({ error:"Script too long. Maximum 60,000 characters." });
    const cost = text.length;

    // Check user credits (or team membership) before calling Claude
    const userDoc = await db.collection("users").doc(user.uid).get();
    const teamId = userDoc.data()?.teamId;
    let isTeamMember = false;
    if(teamId){
      const teamDoc = await db.collection("teams").doc(teamId).get();
      if(teamDoc.exists){
        const team = teamDoc.data();
        if(team.credits === -1 || team.credits > 0) isTeamMember = true;
      }
    }
    if(!isTeamMember){
      const individualCredits = userDoc.data()?.credits || 0;
      if(!user.email_verified){
        return res.status(403).json({ error:"Please verify your email address before using this feature." });
      }
      if(individualCredits < cost){
        return res.status(402).json({ error:"Insufficient credits. You need "+cost.toLocaleString()+" but have "+individualCredits.toLocaleString()+". Please top up." });
      }
    }

            // Translate using official Google Cloud Translation API
    const langCodeMap = {
      "English": "en", "French": "fr", "Spanish": "es", "German": "de",
      "Italian": "it", "Russian": "ru", "Portuguese": "pt", "Ukrainian": "uk", "Afrikaans": "af"
    };
    const targetCode = langCodeMap[targetLang] || "en";
    const gRes = await axios.post(
      `https://translation.googleapis.com/language/translate/v2?key=${process.env.GOOGLE_TRANSLATE_API_KEY}`,
      { q: text, target: targetCode, format: "text" },
      { timeout: 30000 }
    );
    const translatedText = gRes.data?.data?.translations?.[0]?.translatedText;
    if(!translatedText) throw new Error("Translation failed — no content returned");

    // Only deduct credits after successful translation
    let remaining = 0;
    if(isTeamMember){
      remaining = 999999999;
      await db.collection("users").doc(user.uid).collection("transactions").add({
        type:"debit", amount:-cost,
        note:`Translation to ${targetLang} (Team)`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    } else {
      const current = userDoc.data()?.credits || 0;
      await db.collection("users").doc(user.uid).update({
        credits: admin.firestore.FieldValue.increment(-cost)
      });
      await db.collection("users").doc(user.uid).collection("transactions").add({
        type:"debit", amount:-cost,
        note:`Translation to ${targetLang}`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      remaining = current - cost;
    }

    return res.json({ success:true, translatedText, remaining });
  } catch(e){
    console.error("Translation error:", JSON.stringify(e.response?.data));
    return res.status(500).json({ error:"Translation failed. Please try again." });
  }
});

// ── GET MY REFERRALS ──
app.get("/api/my-referrals", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    const userDoc = await db.collection("users").doc(user.uid).get();
    const myReferralCode = userDoc.data()?.referralCode;
    if(!myReferralCode) return res.json({ success:true, referrals: [] });
    const referralsSnap = await db.collection("users").where("referredBy","==",user.uid).get();
    const referrals = referralsSnap.docs.map(function(doc){
      const d = doc.data();
      const displayName = d.displayName || d.name || "";
      const firstName = displayName ? displayName.split(" ")[0] : "Anonymous";
      return {
        firstName: firstName,
        country: (d.location && d.location.country) || "Unknown",
        signedUpAt: d.createdAt ? d.createdAt.toMillis() : null
      };
    }).sort(function(a,b){ return (b.signedUpAt||0) - (a.signedUpAt||0); });
    return res.json({ success:true, referrals });
  } catch(e){
    console.error("My referrals error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── MARK DOWNLOAD WARNING SEEN ──
app.post("/api/mark-download-warning-seen", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    await db.collection("users").doc(user.uid).set({
      hasSeenDownloadWarning: true
    }, { merge: true });
    return res.json({ success:true });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});
// ── DEDUCT CREDITS ──
app.post("/api/deduct-credits", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { characters, voiceName } = req.body;
  const cost = parseInt(characters)||0;
  if(!cost) return res.status(400).json({ error:"characters required" });
  try {
    const ref = db.collection("users").doc(user.uid);
    const doc = await ref.get();
    const teamId = doc.data()?.teamId;
    // Check if user is on a team
    if(teamId){
      const teamDoc = await db.collection("teams").doc(teamId).get();
      if(teamDoc.exists){
        const team = teamDoc.data();
        if(team.credits === -1){
          // Unlimited plan — just log, no deduction
          await ref.collection("transactions").add({
            type:"debit", amount:-cost,
            note:`Voiceover — ${voiceName||"Unknown"} (Team: ${team.teamName})`,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          });
          await ref.update({
            totalCharacters: admin.firestore.FieldValue.increment(cost),
            totalGenerations: admin.firestore.FieldValue.increment(1),
            [`voiceCount.${voiceName}`]: admin.firestore.FieldValue.increment(1),
          });
          return res.json({ success:true, remaining: 999999999, team:true });
        } else if(team.credits > 0){
          // Starter plan — deduct from team credits
          await db.collection("teams").doc(teamId).update({
            credits: admin.firestore.FieldValue.increment(-cost)
          });
          await ref.collection("transactions").add({
            type:"debit", amount:-cost,
            note:`Voiceover — ${voiceName||"Unknown"} (Team: ${team.teamName})`,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          });
          await ref.update({
            totalCharacters: admin.firestore.FieldValue.increment(cost),
            totalGenerations: admin.firestore.FieldValue.increment(1),
            [`voiceCount.${voiceName}`]: admin.firestore.FieldValue.increment(1),
          });
          return res.json({ success:true, remaining: team.credits - cost, team:true });
        }
      }
    }
    // Individual credits
    const current = doc.exists?(doc.data().credits||0):0;
    if (current<cost) return res.status(402).json({ error:"Insufficient credits", required:cost, available:current });
    await ref.update({ 
  credits: admin.firestore.FieldValue.increment(-cost),
  totalCharacters: admin.firestore.FieldValue.increment(characters),
  totalGenerations: admin.firestore.FieldValue.increment(1),
  [`voiceCount.${voiceName}`]: admin.firestore.FieldValue.increment(1),
});
    await ref.collection("transactions").add({
      type:"debit", amount:-cost,
      note:`Voiceover — ${voiceName||"Unknown"}`,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return res.json({ success:true, creditsUsed:cost, remaining:current-cost });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── FLUTTERWAVE WEBHOOK ──
app.post("/api/flutterwave-webhook", express.raw({ type:"*/*" }), async (req,res) => {
  try {
    const rawBody = req.body.toString("utf8");
    const sig = req.headers["verif-hash"];
    if(sig !== process.env.FLW_WEBHOOK_SECRET){
      console.error("Invalid Flutterwave webhook signature");
      return res.status(400).json({ error:"Invalid signature" });
    }
    const payload = JSON.parse(rawBody);
    console.log("Flutterwave webhook:", payload.event);
    if(payload.event !== "charge.completed") return res.json({ received:true });
    const data = payload.data;
    if(data.status !== "successful") return res.json({ received:true });
    const amountPaid = data.amount;
    const customerEmail = data.customer?.email;
    const reference = data.flw_ref || data.tx_ref;
    const accountNumber = data.meta_data?.accountnumber || data.virtual_account_number;
    console.log("FLW Payment received:", amountPaid, "NGN for", customerEmail, "account:", accountNumber);
    // Find user by account number first then email
    let snap = null;
    if(accountNumber){
      snap = await db.collection("users").where("virtualAccount.accountNumber","==",accountNumber).limit(1).get();
      if(!snap.empty) console.log("Found user by account number:", accountNumber);
    }
    if(!snap || snap.empty){
      snap = await db.collection("users").where("email","==",customerEmail).limit(1).get();
      if(!snap.empty) console.log("Found user by email:", customerEmail);
    }
    if(!snap || snap.empty){
      console.log("No user found for FLW payment:", customerEmail, accountNumber);
      return res.json({ received:true });
    }
    const uid = snap.docs[0].id;
    // Check duplicate
    const existing = await db.collection("users").doc(uid).collection("transactions")
      .where("paymentRef","==",reference).get();
    if(!existing.empty) return res.json({ received:true, duplicate:true });
    // Calculate credits
    let creditsToAdd = 0;
    try {
      const rateRes = await axios.get("https://open.er-api.com/v6/latest/USD");
      const ngnRate = rateRes.data?.rates?.NGN || 1600;
                        const usdAmount = amountPaid / ngnRate;
      const packages = [
        {usd:8, credits:500000},
        {usd:16, credits:1200000},
        {usd:24, credits:1900000},
        {usd:32, credits:2600000}
      ];
      let matched = packages[0];
      let minDiff = Math.abs(usdAmount - packages[0].usd);
      packages.forEach(function(pkg){
        const diff = Math.abs(usdAmount - pkg.usd);
        if(diff < minDiff){ minDiff = diff; matched = pkg; }
      });
            if(minDiff / matched.usd <= 0.10){
        creditsToAdd = matched.credits;
      } else {
        creditsToAdd = Math.floor(usdAmount * 100000);
      }
    } catch(rateErr){
      creditsToAdd = Math.floor(amountPaid / 1600 * 100000);
    }
    await db.collection("users").doc(user.uid).update({
        credits: admin.firestore.FieldValue.increment(creditsToAdd),
        hasPurchased: true,
      });
    const today = new Date().toISOString().split("T")[0];
    const amountUSD = amountPaid / 1400;
    await db.collection("stats").doc("revenue").set({
      totalUSD: admin.firestore.FieldValue.increment(amountUSD),
      totalTransactions: admin.firestore.FieldValue.increment(1),
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      [`daily.${today}`]: admin.firestore.FieldValue.increment(amountUSD)
    }, {merge:true});
        await db.collection("users").doc(uid).collection("transactions").add({
      type:"credit", amount:creditsToAdd, amountNGN:amountPaid, paymentRef:reference,
      note:`Top-up — ₦${amountPaid.toLocaleString()} — ${creditsToAdd.toLocaleString()} credits`,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    // Referral commission
    const userDoc = await db.collection("users").doc(uid).get();
    if(userDoc.data()?.email){
      sendPurchaseReceipt({
        email: userDoc.data().email,
        creditsAdded: creditsToAdd,
        amountDisplay: `₦${amountPaid.toLocaleString()}`,
        method: "Bank Transfer",
        reference: reference
      }).catch(function(){});
    }
    const referredBy = userDoc.data()?.referredBy;
    if(referredBy){
      const referredUserDoc2 = await db.collection("users").doc(uid).get();
      const savedRate2 = referredUserDoc2.data()?.referralCommissionRate || 10;
      const referrerDocCheck2 = await db.collection("users").doc(referredBy).get();
      const referrerDataCheck2 = referrerDocCheck2.exists ? referrerDocCheck2.data() : {};
      const rateExpiry2 = referrerDataCheck2.referralRateExpiry ? referrerDataCheck2.referralRateExpiry.toDate() : null;
      const effectiveRate2 = (rateExpiry2 && rateExpiry2 < new Date()) ? 10 : savedRate2;
      const referralRate2 = effectiveRate2 / 100;
      const commissionNGN = Math.floor(amountPaid * referralRate2);
      const commissionPct2 = Math.round(referralRate2 * 100);
      await db.collection("users").doc(referredBy).update({
        referralEarningsNGN: admin.firestore.FieldValue.increment(commissionNGN)
      });
      console.log("Referral commission paid:", commissionNGN, "NGN at", commissionPct2+"% to:", referredBy);
    }

    console.log("FLW credits added:", creditsToAdd, "to:", uid);
    return res.json({ received:true });
  } catch(e){
    console.error("FLW webhook error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});

// ── GENERATE BANK TRANSFER (Flutterwave one-time VA) ──
app.post("/api/generate-bank-transfer", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    const { usd, credits, ngnAmount } = req.body;
    if(!ngnAmount || !credits) return res.status(400).json({ error:"Missing amount or credits" });
    const firstName = user.name?.split(" ")[0] || user.email.split("@")[0];
    const lastName = user.name?.split(" ").slice(1).join(" ") || firstName;
    const txRef = "AUDLABS-" + user.uid.slice(0,8) + "-" + Date.now();
    const vaRes = await axios.post(
      "https://api.flutterwave.com/v3/virtual-account-numbers",
      {
        email: user.email,
        amount: ngnAmount,
        tx_ref: txRef,
        firstname: firstName,
        lastname: lastName,
        narration: "AudLabs Credits"
      },
      { headers: { Authorization:`Bearer ${process.env.FLW_SECRET_KEY}`, "Content-Type":"application/json" }}
    );
    console.log("FLW one-time VA:", JSON.stringify(vaRes.data));
    if(vaRes.data.status !== "success" || !vaRes.data.data){
      throw new Error(vaRes.data.message || "Could not generate virtual account");
    }
    const va = vaRes.data.data;
    return res.json({
      success: true,
      bankName: va.bank_name || "Wema Bank",
      accountNumber: va.account_number,
      accountName: firstName + " " + lastName,
      amount: ngnAmount,
      credits: credits
    });
  } catch(e){
    console.error("Generate bank transfer error:", e.message);
    return res.status(500).json({ error: e.message });
  }
});

// ── PAYSTACK WEBHOOK ──
app.post("/api/paystack-webhook", express.raw({ type:"*/*" }), async (req,res) => {
  try {
    const rawBody = req.body.toString("utf8");
    const sig = req.headers["x-paystack-signature"];
    const hash = crypto.createHmac("sha512", PAYSTACK_SECRET).update(rawBody).digest("hex");
    if (sig && hash !== sig) { console.error("Invalid Paystack signature"); return res.status(400).json({ error:"Invalid signature" }); }

    const payload = JSON.parse(rawBody);
    console.log("Paystack webhook:", payload.event);

    console.log("Webhook event:", payload.event, "channel:", payload.data?.channel);
    
    // Handle both charge.success and dedicated account transfers
    if (!["charge.success", "transfer.success"].includes(payload.event)) {
      return res.json({ received:true, event:payload.event });
    }

    const data = payload.data;
    const amountPaid = data.amount / 100; // Paystack sends in kobo
    const customerEmail = data.customer?.email || data.recipient?.email;
    const reference = data.reference || data.transfer_code;
    const accountNumber = data.authorization?.receiver_bank_account_number || 
                          data.metadata?.receiver_bank_account_number ||
                          data.dedicated_nuban?.account_number ||
                          data.paid_to?.nuban;
    
    console.log("Payment received:", amountPaid, "NGN for", customerEmail, "account:", accountNumber);

    // Find user by account number first, then fall back to email
    let snap = null;
    if (accountNumber) {
      snap = await db.collection("users").where("virtualAccount.accountNumber","==",accountNumber).limit(1).get();
      if (!snap.empty) console.log("Found user by account number:", accountNumber);
    }
    if (!snap || snap.empty) {
      snap = await db.collection("users").where("email","==",customerEmail).limit(1).get();
      if (!snap.empty) console.log("Found user by email:", customerEmail);
    }
    if (!snap || snap.empty) { 
      console.log("No user found for email:", customerEmail, "account:", accountNumber);
      // Check if this is a team payment via account map
      if(accountNumber){
        const teamAccDoc = await db.collection("teamAccountMap").doc(accountNumber).get();
        if(teamAccDoc.exists){
          const teamAccData = teamAccDoc.data();
          const txRef = teamAccData.txRef;
          const existingPay = await db.collection("teamPayments").doc(txRef).get();
          if(existingPay.exists && existingPay.data().status === "completed"){
            return res.json({ received:true, duplicate:true });
          }
          const teamCode = "TEAM-" + Math.random().toString(36).substring(2,8).toUpperCase();
          const teamRef = await db.collection("teams").add({
            teamName: teamAccData.teamName,
            plan: teamAccData.plan,
            price: teamAccData.price,
            maxMembers: teamAccData.members,
            credits: teamAccData.credits === -1 ? -1 : teamAccData.credits,
            teamCode,
            adminUid: teamAccData.uid,
            adminEmail: existingPay.data().email,
            members: [{uid: teamAccData.uid, email: existingPay.data().email, joinedAt: new Date()}],
            paymentMethod: "transfer",
            status: "active",
            paidAt: admin.firestore.FieldValue.serverTimestamp(),
            nextRenewal: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
            createdAt: admin.firestore.FieldValue.serverTimestamp()
          });
          await db.collection("users").doc(teamAccData.uid).update({
            teamId: teamRef.id,
            teamRole: "admin"
          });
          await db.collection("teamPayments").doc(txRef).update({ status:"completed", teamCode, teamId: teamRef.id });
          console.log("Team created via transfer:", teamCode);
          return res.json({ received:true });
        }
      }
      // Check if this is a developer payment via account map
      if(accountNumber){
        const devAccDoc = await db.collection("devAccountMap").doc(accountNumber).get();
        if(devAccDoc.exists){
          const devAccData = devAccDoc.data();
          const devKeySnap = await db.collection("apiKeys").where("uid","==",devAccData.uid).limit(1).get();
          if(!devKeySnap.empty){
            const now = new Date();
            const expiry = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
            await db.collection("apiKeys").doc(devKeySnap.docs[0].id).update({
              monthlyCredits: devAccData.credits,
              totalMonthlyCredits: devAccData.credits,
              plan: devAccData.plan,
              subscriptionExpiry: admin.firestore.Timestamp.fromDate(expiry),
              active: true
            });
            await db.collection("devAccountMap").doc(accountNumber).delete();
            console.log("Developer subscription activated:", devAccData.uid, devAccData.plan);
          }
          return res.json({ received:true });
        }
      }
      return res.json({ received:true }); 
    }

    const uid = snap.docs[0].id;


    // Check duplicate
    const existing = await db.collection("users").doc(uid).collection("transactions")
      .where("paymentRef","==",reference).get();
    if (!existing.empty) return res.json({ received:true, duplicate:true });

    // Match payment to package using live rate
    // $1 = 100,000 credits
    // Fetch live rate to convert NGN amount to credits
    let creditsToAdd = 0;
    try {
      const rateRes = await axios.get("https://open.er-api.com/v6/latest/USD");
      const ngnRate = rateRes.data?.rates?.NGN || 1600;
                        const usdAmount = amountPaid / ngnRate;
      // Match to nearest package
      const packages = [
        {usd:8, credits:500000},
        {usd:16, credits:1200000},
        {usd:24, credits:1900000},
        {usd:32, credits:2600000}
      ];
      // Find closest package
      let matched = packages[0];
      let minDiff = Math.abs(usdAmount - packages[0].usd);
      packages.forEach(function(pkg){
        const diff = Math.abs(usdAmount - pkg.usd);
        if(diff < minDiff){ minDiff = diff; matched = pkg; }
      });
      // Only match if within 10% of package price
            if(minDiff / matched.usd <= 0.10){
        creditsToAdd = matched.credits;
        console.log("Matched package:", matched.usd, "USD =", matched.credits, "credits, paid:", usdAmount.toFixed(2), "USD");
      } else {
        // Fallback: calculate proportionally
        creditsToAdd = Math.floor(usdAmount * 100000);
        console.log("No exact package match, proportional credits:", creditsToAdd, "for", usdAmount.toFixed(2), "USD");
      }
    } catch(rateErr) {
      // Fallback if rate fetch fails
      creditsToAdd = Math.floor(amountPaid / 1600 * 100000);
      console.log("Rate fetch failed, fallback credits:", creditsToAdd);
    }
    await db.collection("users").doc(uid).update({
      credits: admin.firestore.FieldValue.increment(creditsToAdd),
      hasPurchased: true,
    });
const today = new Date().toISOString().split("T")[0];
    const amountUSD = amountPaid / 1400;
    await db.collection("stats").doc("revenue").set({
      totalUSD: admin.firestore.FieldValue.increment(amountUSD),
      totalTransactions: admin.firestore.FieldValue.increment(1),
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      [`daily.${today}`]: admin.firestore.FieldValue.increment(amountUSD)
    }, {merge: true});

        await db.collection("users").doc(uid).collection("transactions").add({
      type:"credit", amount:creditsToAdd, amountNGN:amountPaid, paymentRef:reference,
      note:`Top-up — ₦${amountPaid.toLocaleString()} — ${creditsToAdd.toLocaleString()} credits`,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    // Referral commission
    const userDoc = await db.collection("users").doc(uid).get();
    if(userDoc.data()?.email){
      sendPurchaseReceipt({
        email: userDoc.data().email,
        creditsAdded: creditsToAdd,
        amountDisplay: `₦${amountPaid.toLocaleString()}`,
        method: "Card Payment",
        reference: reference
      }).catch(function(){});
    }
    const referredBy = userDoc.data()?.referredBy;
    console.log("Checking referral for uid:", uid, "referredBy:", referredBy);
    if (referredBy) {
      const savedRate = userDoc.data()?.referralCommissionRate || 10;
      // Check if referrer's custom rate has expired
      const referrerDocCheck = await db.collection("users").doc(referredBy).get();
      const referrerDataCheck = referrerDocCheck.exists ? referrerDocCheck.data() : {};
      const rateExpiry = referrerDataCheck.referralRateExpiry ? referrerDataCheck.referralRateExpiry.toDate() : null;
      const effectiveRate = (rateExpiry && rateExpiry < new Date()) ? 10 : savedRate;
      const referralRate = effectiveRate / 100;
      const commissionNGN = Math.floor(amountPaid * referralRate);
      const commissionPct = Math.round(referralRate * 100);
      console.log("Paying commission:", commissionNGN, "NGN to:", referredBy, "at rate:", commissionPct+"%");
      await db.collection("users").doc(referredBy).update({
        referralEarningsNGN: admin.firestore.FieldValue.increment(commissionNGN),
      });
      await db.collection("users").doc(referredBy).collection("referralEarnings").add({
        fromUid:uid, fromEmail:customerEmail, amountNGN:commissionNGN,
        note:`commissionPct%referralfrom₦{amountPaid.toLocaleString()}`,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      console.log("✅ Commission paid:", commissionNGN, "NGN to referrer:", referredBy);
    } else {
      console.log("No referredBy found for uid:", uid, "- no commission paid");
    }

    console.log(`✅ Credited ${creditsToAdd} to ${uid}`);
    return res.json({ success:true });
  } catch(e) { console.error("Webhook error:", e.message); return res.status(500).json({ error:e.message }); }
});

// ── CRYPTO WEBHOOK ──
app.post("/api/crypto-webhook", express.raw({ type:"*/*" }), async (req,res) => {
  try {
    const rawBody = req.body.toString("utf8");
    const sig = req.headers["x-nowpayments-sig"];
    const data = JSON.parse(rawBody);
    const sortedStr = JSON.stringify(data, Object.keys(data).sort());
    const hash = crypto.createHmac("sha512", NOW_IPN_SECRET).update(sortedStr).digest("hex");
    if (sig && hash !== sig) return res.status(400).json({ error:"Invalid signature" });

    const { payment_status, order_id, actually_paid, pay_amount } = data;
    if (!["finished","confirmed"].includes(payment_status)) return res.json({ received:true });

    const payDoc = await db.collection("cryptoPayments").doc(order_id).get();
    if (!payDoc.exists) return res.json({ received:true });
    const payData = payDoc.data();
    if (payData.status === "completed") return res.json({ received:true, duplicate:true });

    const creditsToAdd = payData.creditsAmount;
    await db.collection("users").doc(payData.uid).update({
      credits: admin.firestore.FieldValue.increment(creditsToAdd),
      hasPurchased: true,
    });
const today = new Date().toISOString().split("T")[0];
    await db.collection("stats").doc("revenue").set({
      totalUSD: admin.firestore.FieldValue.increment(payData.amountUSD || 0),
      totalTransactions: admin.firestore.FieldValue.increment(1),
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      [`daily.${today}`]: admin.firestore.FieldValue.increment(payData.amountUSD || 0)
    }, {merge: true});
        await db.collection("users").doc(payData.uid).collection("transactions").add({
      type:"credit", amount:creditsToAdd,
      note:`Crypto top-up — $${payData.amountUSD} USDT — ${creditsToAdd.toLocaleString()} credits`,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    await db.collection("cryptoPayments").doc(order_id).update({ status:"completed" });
    const cryptoUserDoc = await db.collection("users").doc(payData.uid).get();
    if(cryptoUserDoc.data()?.email){
      sendPurchaseReceipt({
        email: cryptoUserDoc.data().email,
        creditsAdded: creditsToAdd,
        amountDisplay: `$${payData.amountUSD} USDT`,
        method: "Crypto (USDT)",
        reference: order_id
      }).catch(function(){});
    }
    console.log(`✅ Crypto credited ${creditsToAdd} to ${payData.uid}`);
    return res.json({ success:true });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── VERIFY ACCOUNT ──
app.post("/api/verify-account", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { bankCode, accountNumber } = req.body;
  if (!bankCode || !accountNumber) {
    return res.status(400).json({ error:"Bank code and account number required" });
  }
  try {
        const response = await axios.get(
      `${PAYSTACK_BASE}/bank/resolve?account_number=${accountNumber}&bank_code=${bankCode}`,
      { headers: { Authorization:`Bearer ${PAYSTACK_SECRET}` }}
    );
    if (response.data.status && response.data.data?.account_name) {
      console.log(`✅ Account verified: ${response.data.data.account_name}`);
      return res.json({ success:true, accountName: response.data.data.account_name });
    }
    return res.status(400).json({ error:"Account not found" });
  } catch(e) {
    const errData = e.response?.data;
    const msg = errData?.message || e.message || "Verification failed";
const friendlyMsg = msg.includes("resolve") || msg.includes("parameters") || msg.includes("account") ? 
"Invalid account number. Please check and try again." : msg;
    console.error("Verify account error:", msg, errData);
    return res.status(400).json({ error: friendlyMsg });
  }
});

// ── WITHDRAWAL ──
app.post("/api/request-withdrawal", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { amount, currency, bankName, bankCode, accountNumber, accountName, walletAddress, usdAmount, rateUsed } = req.body;
  if (!amount || amount < MIN_WITHDRAWAL) return res.status(400).json({ error:`Minimum withdrawal is ₦${MIN_WITHDRAWAL.toLocaleString()}` });
  try {
    const ref = db.collection("users").doc(user.uid);
    const doc = await ref.get();
    const balance = doc.data()?.referralEarningsNGN || 0;
    if (balance < amount) return res.status(400).json({ error:"Insufficient balance" });

    // Deduct balance first
    await ref.update({ referralEarningsNGN: admin.firestore.FieldValue.increment(-amount) });

    let note = "";
    let withdrawalData = { uid:user.uid, email:user.email, amountNGN:amount, currency:currency||"NGN", status:"pending", createdAt:admin.firestore.FieldValue.serverTimestamp() };

    if (currency === "USD") {
      // USDT - manual processing with email alert
      withdrawalData.walletAddress = walletAddress;
      withdrawalData.usdAmount = usdAmount;
      withdrawalData.rateUsed = rateUsed;
      note = `Withdrawal ₦${amount.toLocaleString()} → $${usdAmount} USDT`;
            await db.collection("withdrawalRequests").add(withdrawalData);
      await ref.collection("transactions").add({ type:"withdrawal", amount:-amount, note, createdAt:admin.firestore.FieldValue.serverTimestamp() });
      // Send email alert
      await sendWithdrawalAlert({ email:user.email, amountNGN:amount, usdAmount, walletAddress, rateUsed });
      sendWithdrawalReceipt({ email:user.email, amountNGN:amount, method:"USDT (Crypto)" }).catch(function(){});
      return res.json({ success:true, message:"USDT withdrawal submitted. You will receive your USDT within 20 hours." });
    }

    // NGN - process instantly via Paystack Transfer
    try {
      // Step 1: Create transfer recipient
      console.log("Creating Paystack transfer recipient for:", accountNumber, bankCode);
      const recipientRes = await axios.post(`${PAYSTACK_BASE}/transferrecipient`, {
        type: "nuban",
        name: accountName,
        account_number: accountNumber,
        bank_code: bankCode,
        currency: "NGN"
      }, { headers: { Authorization:`Bearer ${PAYSTACK_SECRET}`, "Content-Type":"application/json" }});

      if (!recipientRes.data.status) throw new Error(recipientRes.data.message || "Failed to create recipient");
      const recipientCode = recipientRes.data.data.recipient_code;
      console.log("Recipient code:", recipientCode);

      // Step 2: Initiate transfer
            const transferRef = `VG-WD-${user.uid.slice(0,8)}-${Date.now()}`;
      const transferRes = await axios.post(`${PAYSTACK_BASE}/transfer`, {
        source: "balance",
        amount: amount * 100, // Paystack uses kobo
        recipient: recipientCode,
        reason: `AudLabs Affiliate Withdrawal`,
        reference: transferRef
      }, { headers: { Authorization:`Bearer ${PAYSTACK_SECRET}`, "Content-Type":"application/json" }});

      console.log("Transfer response:", JSON.stringify(transferRes.data));

      if (!transferRes.data.status) throw new Error(transferRes.data.message || "Transfer failed");

      const transferStatus = transferRes.data.data.status;
      note = `Withdrawal ₦${amount.toLocaleString()} to ${bankName} — ${accountNumber}`;
      withdrawalData.bankName = bankName;
      withdrawalData.bankCode = bankCode;
      withdrawalData.accountNumber = accountNumber;
      withdrawalData.accountName = accountName;
      withdrawalData.transferRef = transferRef;
      withdrawalData.recipientCode = recipientCode;
      withdrawalData.status = transferStatus;

            await db.collection("withdrawalRequests").add(withdrawalData);
      await ref.collection("transactions").add({ type:"withdrawal", amount:-amount, note, createdAt:admin.firestore.FieldValue.serverTimestamp() });
      console.log("✅ Transfer initiated:", transferRef, "status:", transferStatus);
      sendWithdrawalReceipt({ email:user.email, amountNGN:amount, method:`Bank Transfer — ${bankName}` }).catch(function(){});
      return res.json({ success:true, message:`Transfer of ₦${amount.toLocaleString()} initiated successfully! You will receive it shortly.`, status: transferStatus });

    } catch(transferErr) {
      // If Paystack transfer fails, refund the balance and return error
      console.error("Transfer error:", transferErr.response?.data || transferErr.message);
      await ref.update({ referralEarningsNGN: admin.firestore.FieldValue.increment(amount) });
      const errMsg = transferErr.response?.data?.message || transferErr.message || "Transfer failed";
      return res.status(400).json({ error:`Transfer failed: ${errMsg}. Your balance has been restored.` });
    }

  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── REFERRAL EARNINGS ──
app.get("/api/referral-earnings", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const snap = await db.collection("users").doc(user.uid).collection("referralEarnings")
      .orderBy("createdAt","desc").limit(50).get();
    return res.json({ earnings: snap.docs.map(d=>({ id:d.id,...d.data(),createdAt:d.data().createdAt?.toDate() })) });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── CREATE CRYPTO PAYMENT ──
app.get("/api/check-crypto-payment", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { paymentId } = req.query;
  if (!paymentId) return res.status(400).json({ error:"Payment ID required" });
  try {
    const result = await axios.get(
      `https://api.nowpayments.io/v1/payment/${paymentId}`,
      { headers: { "x-api-key": NOW_API_KEY } }
    );
    const status = result.data.payment_status;
    if (status === "finished" || status === "confirmed") {
      const paySnap = await db.collection("cryptoPayments")
        .where("paymentId","==",paymentId).limit(1).get();
      if (!paySnap.empty) {
        const payData = paySnap.docs[0].data();
        const orderId = paySnap.docs[0].id;
        if (payData.status !== "completed") {
          const creditsToAdd = payData.creditsAmount;
          await db.collection("users").doc(user.uid).update({
            credits: admin.firestore.FieldValue.increment(creditsToAdd)
          });
          await db.collection("users").doc(user.uid).collection("transactions").add({
            type:"credit", amount:creditsToAdd,
            note:`Crypto top-up — $${payData.amountUSD} USDT — ${creditsToAdd.toLocaleString()} credits`,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
          });
                    await db.collection("cryptoPayments").doc(orderId).update({ status:"completed" });
          console.log("✅ Manual check credited:", creditsToAdd, "to", user.uid);
          sendPurchaseReceipt({
            email: user.email,
            creditsAdded: creditsToAdd,
            amountDisplay: `$${payData.amountUSD} USDT`,
            method: "Crypto (USDT)",
            reference: orderId
          }).catch(function(){});
        }
      }
    }
    return res.json({ status, data: result.data });
  } catch(e) {
    return res.status(500).json({ error: e.response?.data?.message || e.message });
  }
});

app.post("/api/create-crypto-payment", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { amountUSD, creditsAmount } = req.body;
  try {
        const orderId = `VG-CRYPTO-${user.uid.slice(0,8)}-${Date.now()}`;
    const response = await axios.post("https://api.nowpayments.io/v1/payment", {
      price_amount: amountUSD, price_currency:"usd", pay_currency:"usdttrc20",
      order_id: orderId, order_description:`VoiceGen ${creditsAmount} credits`,
     ipn_callback_url:`${'https://app.audlabs.io'}/api/crypto-webhook`,
      is_fixed_rate: false,
      is_fee_paid_by_user: true
    }, { headers:{ "x-api-key":NOW_API_KEY }});

    await db.collection("cryptoPayments").doc(orderId).set({
      uid:user.uid, email:user.email, orderId,
      paymentId:response.data.payment_id,
      amountUSD, creditsAmount:parseInt(creditsAmount),
      status:"pending", createdAt:admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ success:true, payAddress:response.data.pay_address, payAmount:parseFloat(response.data.pay_amount).toFixed(4), payCurrency:response.data.pay_currency, orderId, paymentId:response.data.payment_id });
  } catch(e) { return res.status(500).json({ error:e.response?.data?.message||e.message }); }
});

// ── TRANSACTIONS ──
app.get("/api/transactions", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const snap = await db.collection("users").doc(user.uid).collection("transactions")
      .orderBy("createdAt","desc").limit(50).get();
    return res.json({ transactions: snap.docs.map(d=>({ id:d.id,...d.data(),createdAt:d.data().createdAt?.toDate() })) });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── CLONE VOICE (MiniMax) ──
app.post("/api/clone-voice", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { IncomingForm } = require("formidable");
    const FormData = require("form-data");
    const form = new IncomingForm({ maxFileSize: 20 * 1024 * 1024 });
    form.parse(req, async (err, fields, files) => {
      if (err) return res.status(400).json({ error:"File upload failed" });
      const file = files.file?.[0] || files.file;
      const name = fields.name?.[0] || fields.name || "My Voice";
      if (!file) return res.status(400).json({ error:"No file provided" });
      try {
        const filePath = file.filepath || file.path;
        const fileData = fs.readFileSync(filePath);
        const originalName = file.originalFilename || file.name || "audio.mp3";
        const mimeType = file.mimetype || "audio/wav";

        // Check credits
        const userDoc = await db.collection("users").doc(user.uid).get();
        const currentCredits = userDoc.data()?.credits || 0;
        const teamId = userDoc.data()?.teamId;
        let hasTeamCredits = false;
        if(teamId){
          const teamDoc = await db.collection("teams").doc(teamId).get();
          if(teamDoc.exists){
            const team = teamDoc.data();
            const nextRenewal = team.nextRenewal ? team.nextRenewal.toDate() : null;
            const isExpired = nextRenewal && new Date() > nextRenewal;
            if(!isExpired && (team.credits === -1 || team.credits >= 10000)){
              hasTeamCredits = true;
            }
          }
        }
        if(currentCredits < 15000 && !hasTeamCredits){
          return res.status(400).json({ error:"Insufficient credits. Voice cloning costs 15,000 credits." });
        }

        // Check if user already has a cloned voice — limit 1 per user
        const existingClones = await db.collection("users").doc(user.uid).collection("clonedVoices").get();
        if(existingClones.size >= 1){
          return res.status(400).json({ error:"You already have a cloned voice. Please delete it before cloning a new one." });
        }

        // Save audio to Firebase Storage permanently
        const storageFilename = "cloneAudio/" + user.uid + "/" + Date.now() + "_" + originalName;
        const storageFile = bucket.file(storageFilename);
        await storageFile.save(fileData, {
          metadata: { contentType: mimeType }
        });
        console.log("Audio saved to Firebase Storage:", storageFilename);

        // MiniMax accounts for cloning
        const minimaxAccounts = [
          { key: process.env.MINIMAX_API_KEY, name: "acc1" },
          { key: process.env.MINIMAX_API_KEY_2, name: "acc2" },
          { key: process.env.MINIMAX_API_KEY_3, name: "acc3" },
          { key: process.env.MINIMAX_API_KEY_4, name: "acc4" },
          { key: process.env.MINIMAX_API_KEY_5, name: "acc5" },
          { key: process.env.MINIMAX_API_KEY_6, name: "acc6" },
          { key: process.env.MINIMAX_API_KEY_7, name: "acc7" },
          { key: process.env.MINIMAX_API_KEY_8, name: "acc8" },
          { key: process.env.MINIMAX_API_KEY_9, name: "acc9" },
          { key: process.env.MINIMAX_API_KEY_10, name: "acc10" }
        ];



        // Generate unique voice ID for MiniMax
        const cleanUid = user.uid.slice(0,8).toLowerCase().replace(/[^a-z0-9]/g,"");
        const minimaxVoiceId = "audlabs" + cleanUid + Date.now().toString().slice(-4);

        let clonedOnAccount = null;
        let clonedAccountKey = null;

        for(const acc of minimaxAccounts){
          if(!acc.key) continue;
          try {
            // Quick check if account is active before uploading
            const quickCheck = await axios.post(
              "https://api.minimax.io/v1/t2a_v2",
              { model:"speech-2.8-hd", text:"test", stream:false,
                voice_setting:{ voice_id:"English_CaptivatingStoryteller", speed:1.0, vol:1.0, pitch:0 },
                audio_setting:{ sample_rate:32000, bitrate:128000, format:"mp3", channel:1 },
                output_format:"hex" },
              { headers:{ Authorization:`Bearer ${acc.key}`, "Content-Type":"application/json" }, timeout:8000 }
            );
            const qStatus = quickCheck.data?.base_resp?.status_code;
            const qMsg = quickCheck.data?.base_resp?.status_msg || "";
            if(qStatus === 1002 || qStatus === 2056 || qMsg.includes("limit") || qMsg.includes("quota")){
              console.warn("Account", acc.name, "is limited — skipping for cloning");
              continue;
            }
            // Step 1: Upload audio to MiniMax

            const uploadForm = new FormData();
            uploadForm.append("purpose", "voice_clone");
            uploadForm.append("file", fileData, { filename: originalName, contentType: mimeType });
            const uploadRes = await axios.post(
              "https://api.minimax.io/v1/files/upload",
              uploadForm,
              { headers: { ...uploadForm.getHeaders(), Authorization: `Bearer ${acc.key}` }, timeout: 30000 }
            );
            if(uploadRes.data?.base_resp?.status_code !== 0){
              console.warn("Upload failed on", acc.name, uploadRes.data?.base_resp?.status_msg);
              continue;
            }
            const fileId = uploadRes.data?.file?.file_id;
            if(!fileId){ console.warn("No file_id from", acc.name); continue; }
            console.log("File uploaded to MiniMax:", acc.name, "file_id:", fileId);

            // Step 2: Clone voice
            const cloneRes = await axios.post(
              "https://api.minimax.io/v1/voice_clone",
              { file_id: fileId, voice_id: minimaxVoiceId, noise_reduction: fields.noiseReduction?.[0] === "true" || fields.noiseReduction === "true" },
              { headers: { Authorization: `Bearer ${acc.key}`, "Content-Type": "application/json" }, timeout: 30000 }
            );
            if(cloneRes.data?.base_resp?.status_code === 0){
              clonedOnAccount = acc.name;
              clonedAccountKey = acc.key;
              console.log("Voice cloned on", acc.name, "voice_id:", minimaxVoiceId);
              break;
            } else {
              console.warn("Clone failed on", acc.name, cloneRes.data?.base_resp?.status_msg);
            }
          } catch(accErr){
            console.warn("Account error:", acc.name, accErr.message);
            continue;
          }
        }

        if(!clonedOnAccount){
          // Delete from storage if cloning failed
          try { await storageFile.delete(); } catch(e){}
          return res.status(500).json({ error:"Voice cloning temporarily unavailable. Please try again later." });
        }

        // Generate preview to make voice permanent on MiniMax (must use within 7 days)
        try {
          await axios.post(
            "https://api.minimax.io/v1/t2a_v2",
            {
              model: "speech-2.8-hd",
              text: "Hello, this is a preview of your cloned voice on AudLabs.",
              stream: false,
              voice_setting: { voice_id: minimaxVoiceId, speed: 1.0, vol: 1.0, pitch: 0 },
              audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
              output_format: "hex"
            },
            { headers: { Authorization: `Bearer ${clonedAccountKey}`, "Content-Type": "application/json" }, timeout: 30000 }
          );
          console.log("Preview generated — voice is now permanent on MiniMax");
        } catch(previewErr){
          console.warn("Preview generation failed:", previewErr.message);
        }

        // Deduct credits
        if(!hasTeamCredits){
          await db.collection("users").doc(user.uid).update({
            credits: admin.firestore.FieldValue.increment(-15000)
          });
        }

        // Save to Firestore
        const voiceDocRef = await db.collection("users").doc(user.uid).collection("clonedVoices").add({
          name: name,
          voiceId: minimaxVoiceId,
          minimaxVoiceId: minimaxVoiceId,
          clonedOnAccount: clonedOnAccount,
          storageFilename: storageFilename,
          provider: "minimax",
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log("Voice saved to Firestore:", voiceDocRef.id);
        return res.json({ success:true, voiceId: minimaxVoiceId, name: name, provider: "minimax" });

      } catch(innerErr){
        console.error("Clone inner error:", innerErr.message);
        return res.status(500).json({ error: innerErr.message });
      }
    });
  } catch(e){
    console.error("Clone voice error:", e.message);
    return res.status(500).json({ error: e.message });
  }
});


// ── GET CLONED VOICES ──
app.get("/api/cloned-voices", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const snap = await db.collection("users").doc(user.uid).collection("clonedVoices")
      .orderBy("createdAt","desc").get();
    return res.json({ voices: snap.docs.map(d=>({ id:d.id, ...d.data() })) });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── PREVIEW VOICE ──
app.post("/api/preview-voice", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { voiceId, text } = req.body;
 if (!voiceId || !text) return res.status(400).json({ error:"voiceId and text required" });
  try {
   const MK = process.env.MINIMAX_API_KEY;
    const MK2 = process.env.MINIMAX_API_KEY_2 || MK;
    const MK3 = process.env.MINIMAX_API_KEY_3 || MK;
    const MK4 = process.env.MINIMAX_API_KEY_4 || MK;
const MK5 = process.env.MINIMAX_API_KEY_5 || MK;
const MK6 = process.env.MINIMAX_API_KEY_6 || MK;
const MK7 = process.env.MINIMAX_API_KEY_7 || MK;
const MK8 = process.env.MINIMAX_API_KEY_8 || MK;
const MK9 = process.env.MINIMAX_API_KEY_9 || MK;
const MK10 = process.env.MINIMAX_API_KEY_10 || MK;
    const MG2 = process.env.MINIMAX_GROUP_ID_2 || process.env.MINIMAX_GROUP_ID;

    const voiceIdMap = {


      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_c6a2db4b-7255-11f1-83ef-8afcbb8b5b5c",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_6b545cbd-6e81-11f1-a3fb-6a64dd77666f",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_52793860-6249-11f1-8f84-faf87dcc54b3"
    };
    const voiceIdMap3 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_60328e8c-754d-11f1-8b87-ba0ad3e185a0",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_8e466452-754d-11f1-8b87-ba0ad3e185a0",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_77b427fc-754d-11f1-83ef-8afcbb8b5b5c"
    };
    const voiceIdMap4 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_8e134ce0-7587-11f1-8b87-ba0ad3e185a0",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_1eb29ec7-7588-11f1-a392-62a1f5ede8a7",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_cc4888fe-7587-11f1-8fdf-22f27a8feaff"
    };
    const voiceIdMap5 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_1530bf04-8376-11f1-be88-52778882d255",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_6f5b569b-8376-11f1-b0af-0eac018832f6",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_d495c97b-6520-11f1-8fdf-22f27a8feaff"
    };
    const voiceIdMap6 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_723c822a-9359-11f1-9bc8-c2d08a553394",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_088b4578-935a-11f1-8c05-cea64614d791",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_63c656cc-935a-11f1-8c05-cea64614d791"
    };
    const voiceIdMap7 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_c3df9419-9402-11f1-834d-364bc9e5c396",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_096c364f-9403-11f1-916c-ee98c056a384",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_7735ef42-9403-11f1-84c0-1e0b7b847846"
    };
    const voiceIdMap8 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_a8ebb1fc-9402-11f1-916c-ee98c056a384",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_eee5e94b-9402-11f1-916c-ee98c056a384",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_36d80c89-9403-11f1-b0af-0eac018832f6"
    };
    const voiceIdMap9 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_672e7c11-94bd-11f1-b0af-0eac018832f6",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_2f6d9d90-94be-11f1-8a72-5e514109a081",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_f73cdce5-94be-11f1-834d-364bc9e5c396"
    };
    const voiceIdMap10 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_4e69cfb0-94c3-11f1-9bc8-c2d08a553394",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_f1c71a0f-94c3-11f1-85f5-ee6191b6ca6b",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_6521e6fb-94c4-11f1-8a72-5e514109a081"
    };




    var voiceId2 = voiceIdMap[voiceId] || voiceId;
    var voiceId3 = voiceIdMap3[voiceId] || voiceId;
    var voiceId4 = voiceIdMap4[voiceId] || voiceId;
var voiceId5 = voiceIdMap5[voiceId] || voiceId;
var voiceId6 = voiceIdMap6[voiceId] || voiceId;
var voiceId7 = voiceIdMap7[voiceId] || voiceId;
var voiceId8 = voiceIdMap8[voiceId] || voiceId;
var voiceId9 = voiceIdMap9[voiceId] || voiceId;
var voiceId10 = voiceIdMap10[voiceId] || voiceId;



   if(voiceId.startsWith("clone_") && !voiceId.startsWith("moss_audio_clone_")){
  try {
    const kokoroPreviewRes = await axios.post(
      process.env.KOKORO_TTS_URL + "/generate-cloned",
      { text: text, voiceId: voiceId, speed: 1.0, language: "en" },
      { headers: { "x-api-key": process.env.KOKORO_TTS_KEY, "Content-Type": "application/json" }, responseType: "arraybuffer", timeout: 60000 }
    );
    res.set('Content-Type', 'audio/wav');
    res.set('Content-Length', kokoroPreviewRes.data.length);
    return res.send(Buffer.from(kokoroPreviewRes.data));
  } catch(kokoroErr){
    return res.status(500).json({ error: "Preview failed for cloned voice. Please try again." });
  }
}
// MiniMax cloned voice preview
if(voiceId.startsWith("audlabs")){
  try {
    const clonedSnap = await db.collection("users").doc(user.uid).collection("clonedVoices").where("voiceId","==",voiceId).limit(1).get();
    if(clonedSnap.empty) return res.status(404).json({ error:"Cloned voice not found" });
    const cloneData = clonedSnap.docs[0].data();
    const minimaxVoiceId = cloneData.minimaxVoiceId || voiceId;
    const storageFilename = cloneData.storageFilename;
    // Try generating preview on all accounts
    const previewAccounts = [MK, MK2, MK3, MK4, MK5, MK6, MK7, MK8, MK9, MK10];
    for(const previewKey of previewAccounts){
      if(!previewKey) continue;
      try {
        const previewRes = await axios.post(
          "https://api.minimax.io/v1/t2a_v2",
          {
            model: "speech-2.8-hd",
            text: "Hello, this is a preview of your cloned voice.",
            stream: false,
            voice_setting: { voice_id: minimaxVoiceId, speed: 1.0, vol: 1.0, pitch: 0 },
            audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
            output_format: "hex"
          },
          { headers: { Authorization: `Bearer ${previewKey}`, "Content-Type": "application/json" }, timeout: 15000 }
        );
        if(previewRes.data?.data?.audio){
          const audioBuffer = Buffer.from(previewRes.data.data.audio, "hex");
          res.set("Content-Type", "audio/mpeg");
          res.set("Content-Length", audioBuffer.length);
          return res.send(audioBuffer);
        }
        // If voice not found on this account — try temp re-clone
        const statusMsg = previewRes.data?.base_resp?.status_msg || "";
        if(statusMsg.includes("voice_id") || statusMsg.includes("access")){
          if(storageFilename){
            try {
              const tempRes = await tempCloneAndGenerate(minimaxVoiceId, storageFilename, previewKey, "Hello, this is a preview of your cloned voice.", 1.0, 1.0, 0);
              if(tempRes?.data?.data?.audio){
                const audioBuffer = Buffer.from(tempRes.data.data.audio, "hex");
                res.set("Content-Type", "audio/mpeg");
                res.set("Content-Length", audioBuffer.length);
                return res.send(audioBuffer);
              }
            } catch(tempErr){ console.warn("Preview temp re-clone failed:", tempErr.message); }
          }
        }
      } catch(accErr){ console.warn("Preview account failed:", accErr.message); }
    }
    return res.status(500).json({ error:"Preview failed. Please try again." });
  } catch(e){
    return res.status(500).json({ error:"Preview failed: " + e.message });
  }
}

if(voiceId.startsWith("voice_") || voiceId.startsWith("moss_audio_")){

      try {
        const clonedSnap = await db.collection("users").doc(user.uid).collection("clonedVoices").where("voiceId","==",voiceId).limit(1).get();
        if(!clonedSnap.empty){
          // Same voice ID works on all accounts now
          voiceId2 = voiceId;
          voiceId3 = voiceId;
          voiceId4 = voiceId;
        }
      } catch(clonedErr){ console.warn("Failed to fetch cloned voice IDs:", clonedErr.message); }
    }
    let response;
    try {
    response = await axios.post(
      "https://api.minimax.io/v1/t2a_v2",
      {
        model: "speech-2.8-hd",
        text: text,
        stream: false,
        voice_setting: { voice_id: voiceId, speed: 1.0, vol: 1.0, pitch: 0 },
        audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
        output_format: "hex"
      },
      { headers: { Authorization:`Bearer ${MK}`, "Content-Type":"application/json" }}
    );
    if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access") || response.data.base_resp.status_msg?.includes("voice_id"))){
      throw new Error("Rate limit hit on primary key");
    }
    } catch(primaryErr){
      console.warn("Primary key failed for preview, switching to secondary:", primaryErr.message);
      try {
      response = await axios.post(
        "https://api.minimax.io/v1/t2a_v2",
        {
          model: "speech-2.8-hd",
          text: text,
          stream: false,
          voice_setting: { voice_id: voiceId2, speed: 1.0, vol: 1.0, pitch: 0 },
          audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
          output_format: "hex"
        },
        { headers: { Authorization:`Bearer ${MK2}`, "Content-Type":"application/json" }}
      );
      if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access") || response.data.base_resp.status_msg?.includes("voice_id"))){
        throw new Error("Rate limit hit on secondary key");
      }
      } catch(secondaryErr){
        console.warn("Secondary key failed for preview, switching to tertiary:", secondaryErr.message);
        try {
        response = await axios.post(
          "https://api.minimax.io/v1/t2a_v2",
          {
            model: "speech-2.8-hd",
            text: text,
            stream: false,
            voice_setting: { voice_id: voiceId3, speed: 1.0, vol: 1.0, pitch: 0 },
            audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
            output_format: "hex"
          },
          { headers: { Authorization:`Bearer ${MK3}`, "Content-Type":"application/json" }}
        );
        if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access") || response.data.base_resp.status_msg?.includes("voice_id"))){
          throw new Error("Rate limit hit on tertiary key");
        }
        } catch(tertiaryErr){
          console.warn("Tertiary key failed for preview, switching to quaternary:", tertiaryErr.message);
          try {
          response = await axios.post(
            "https://api.minimax.io/v1/t2a_v2",
            {
              model: "speech-2.8-hd",
              text: text,
              stream: false,
              voice_setting: { voice_id: voiceId4, speed: 1.0, vol: 1.0, pitch: 0 },
              audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
              output_format: "hex"
            },
            { headers: { Authorization:`Bearer ${MK4}`, "Content-Type":"application/json" }}
          );
          if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
            throw new Error("Rate limit hit on quaternary key");
          }
          } catch(quaternaryErr){
            console.warn("Quaternary key failed for preview, switching to quinary:", quaternaryErr.message);
            try {
              response = await axios.post(
                "https://api.minimax.io/v1/t2a_v2",
                {
                  model: "speech-2.8-hd",
                  text: text,
                  stream: false,
                  voice_setting: { voice_id: voiceId5, speed: 1.0, vol: 1.0, pitch: 0 },
                  audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                  output_format: "hex"
                },
                { headers: { Authorization:`Bearer ${MK5}`, "Content-Type":"application/json" }}
              );
              if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                throw new Error("Rate limit hit on quinary key for preview");
              }
            } catch(quinaryErr){
              console.warn("Quinary key failed for preview, switching to senary:", quinaryErr.message);
              try {
                response = await axios.post(
                  "https://api.minimax.io/v1/t2a_v2",
                  {
                    model: "speech-2.8-hd",
                    text: text,
                    stream: false,
                    voice_setting: { voice_id: voiceId6, speed: 1.0, vol: 1.0, pitch: 0 },
                    audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                    output_format: "hex"
                  },
                  { headers: { Authorization:`Bearer ${MK6}`, "Content-Type":"application/json" }}
                );
                if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                  throw new Error("Rate limit hit on senary key for preview");
                }
              } catch(senaryErr){
                console.warn("Senary key failed for preview, switching to septenary:", senaryErr.message);
                try {
                  response = await axios.post(
                    "https://api.minimax.io/v1/t2a_v2",
                    {
                      model: "speech-2.8-hd",
                      text: text,
                      stream: false,
                      voice_setting: { voice_id: voiceId7, speed: 1.0, vol: 1.0, pitch: 0 },
                      audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                      output_format: "hex"
                    },
                    { headers: { Authorization:`Bearer ${MK7}`, "Content-Type":"application/json" }}
                  );
                  if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                    throw new Error("Rate limit hit on septenary key for preview");
                  }
                } catch(septenaryErr){
                  console.warn("Septenary key failed for preview, switching to octonary:", septenaryErr.message);
                  try {
                    response = await axios.post(
                      "https://api.minimax.io/v1/t2a_v2",
                      {
                        model: "speech-2.8-hd",
                        text: text,
                        stream: false,
                        voice_setting: { voice_id: voiceId8, speed: 1.0, vol: 1.0, pitch: 0 },
                        audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                        output_format: "hex"
                      },
                      { headers: { Authorization:`Bearer ${MK8}`, "Content-Type":"application/json" }}
                    );
                    if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                      throw new Error("Rate limit hit on octonary key for preview");
                    }
                  } catch(octonaryErr){
                    console.warn("Octonary key failed for preview, switching to nonary:", octonaryErr.message);
                    try {
                      response = await axios.post(
                        "https://api.minimax.io/v1/t2a_v2",
                        {
                          model: "speech-2.8-hd",
                          text: text,
                          stream: false,
                          voice_setting: { voice_id: voiceId9, speed: 1.0, vol: 1.0, pitch: 0 },
                          audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                          output_format: "hex"
                        },
                        { headers: { Authorization:`Bearer ${MK9}`, "Content-Type":"application/json" }}
                      );
                      if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                        throw new Error("Rate limit hit on nonary key for preview");
                      }
                    } catch(nonaryErr){
                      console.warn("Nonary key failed for preview, switching to denary:", nonaryErr.message);
                      response = await axios.post(
                        "https://api.minimax.io/v1/t2a_v2",
                        {
                          model: "speech-2.8-hd",
                          text: text,
                          stream: false,
                          voice_setting: { voice_id: voiceId10, speed: 1.0, vol: 1.0, pitch: 0 },
                          audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                          output_format: "hex"
                        },
                        { headers: { Authorization:`Bearer ${MK10}`, "Content-Type":"application/json" }}
                      );
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    console.log("Preview response status:", response.data?.base_resp?.status_code, response.data?.base_resp?.status_msg);



    if (response.data?.data?.audio) {
      const hexAudio = response.data.data.audio;
      const audioBuffer = Buffer.from(hexAudio, 'hex');
      res.set('Content-Type', 'audio/mpeg');
      res.set('Content-Length', audioBuffer.length);
      return res.send(audioBuffer);
    }
    const errMsg = response.data?.base_resp?.status_msg || "Preview failed";
    return res.status(400).json({ error: errMsg, raw: response.data?.base_resp });
  } catch(e) {
    console.error("Preview error:", e.response?.data || e.message);
    var previewErr = e.response?.data?.base_resp?.status_msg || e.message || "";
if(previewErr.includes("Token Plan") || previewErr.includes("usage limit") || previewErr.includes("limit") || previewErr.includes("quota")){
  previewErr = "⚠️ Preview unavailable right now due to high traffic.";
}
return res.status(500).json({ error: previewErr });
  }
});

// ── GENERATE VOICE ──
async function tempCloneAndGenerate(minimaxVoiceId, storageFilename, apiKey, text, speed, vol, pitch){
  try {
    // Download audio from Firebase Storage
    const file = bucket.file(storageFilename);
    const [audioBuffer] = await file.download();
    
    // Upload to MiniMax
    const FormData = require("form-data");
    const formData = new FormData();
    formData.append("purpose", "voice_clone");
    formData.append("file", audioBuffer, { filename: "sample.wav", contentType: "audio/wav" });
    const uploadRes = await axios.post(
      "https://api.minimax.io/v1/files/upload",
      formData,
      { headers: { ...formData.getHeaders(), Authorization: `Bearer ${apiKey}` }, timeout: 30000 }
    );
    if(uploadRes.data?.base_resp?.status_code !== 0) throw new Error("Upload failed");
    const fileId = uploadRes.data?.file?.file_id;

    // Clone voice temporarily
    const tempVoiceId = minimaxVoiceId + "tmp" + Date.now().toString().slice(-4);
    const cloneRes = await axios.post(
      "https://api.minimax.io/v1/voice_clone",
      { file_id: fileId, voice_id: tempVoiceId, noise_reduction: true },
      { headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" }, timeout: 30000 }
    );
    if(cloneRes.data?.base_resp?.status_code !== 0) throw new Error("Clone failed");

    // Generate audio
    const genRes = await axios.post(
      "https://api.minimax.io/v1/t2a_v2",
      {
        model: "speech-2.8-hd",
        text: text,
        stream: false,
        voice_setting: { voice_id: tempVoiceId, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
        audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
        output_format: "hex"
      },
      { headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" }, timeout: 60000 }
    );

    // Delete temporary clone immediately
    try {
      await axios.post("https://api.minimax.io/v1/delete_voice",
        { voice_type: "voice_cloning", voice_id: tempVoiceId },
        { headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" }, timeout: 10000 }
      );
      console.log("Deleted temp clone:", tempVoiceId);
    } catch(delErr){ console.warn("Temp clone delete failed:", delErr.message); }

    return genRes;
  } catch(e){
    console.error("tempCloneAndGenerate failed:", e.message);
    throw e;
  }
}

// ── MERGE AUDIO CHUNKS (SERVER-SIDE, PROPER RE-ENCODE) — UNUSED, KEPT FOR REFERENCE ──
app.post("/api/merge-audio-chunks", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { chunks } = req.body;
  if (!chunks || !Array.isArray(chunks) || chunks.length === 0) {
    return res.status(400).json({ error: "chunks array is required" });
  }
  const tempDir = path.join(os.tmpdir(), "audlabs-merge-" + Date.now());
  try {
    fs.mkdirSync(tempDir, { recursive: true });
    const inputFiles = [];
    for (let i = 0; i < chunks.length; i++) {
      const filePath = path.join(tempDir, "chunk" + i + ".mp3");
      const buffer = Buffer.from(chunks[i], "base64");
      fs.writeFileSync(filePath, buffer);
      inputFiles.push(filePath);
    }
    const listFilePath = path.join(tempDir, "list.txt");
    const listContent = inputFiles.map(function(f){ return "file '" + f.replace(/'/g, "'\\''") + "'"; }).join("\n");
    fs.writeFileSync(listFilePath, listContent);
    const outputPath = path.join(tempDir, "output.mp3");
    await new Promise(function(resolve, reject){
      const ffmpegArgs = [
        "-f", "concat",
        "-safe", "0",
        "-i", listFilePath,
        "-acodec", "libmp3lame",
        "-ar", "32000",
        "-ab", "128k",
        "-y",
        outputPath
      ];
      const ffmpegProcess = spawn(ffmpegPath, ffmpegArgs);
      let stderrOutput = "";
      ffmpegProcess.stderr.on("data", function(data){ stderrOutput += data.toString(); });
      ffmpegProcess.on("close", function(code){
        if (code === 0) resolve();
        else reject(new Error("ffmpeg exited with code " + code + ": " + stderrOutput.slice(-500)));
      });
      ffmpegProcess.on("error", function(err){ reject(err); });
    });
    const mergedBuffer = fs.readFileSync(outputPath);
    fs.rmSync(tempDir, { recursive: true, force: true });
    res.set("Content-Type", "audio/mpeg");
    res.set("Content-Length", mergedBuffer.length);
    return res.send(mergedBuffer);
  } catch (e) {
    console.error("Audio merge failed:", e.message);
    try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch(cleanupErr){}
    return res.status(500).json({ error: "Failed to merge audio: " + e.message });
  }
});
app.post("/api/generate-voice", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { voiceId, text, speed, vol, pitch } = req.body;
  if (!voiceId || !text) return res.status(400).json({ error:"voiceId and text required" });
// Check if user is on a team - skip if Firestore quota exceeded
    let userDoc = null;
    let teamId = null;
    try {
      userDoc = await db.collection("users").doc(user.uid).get();
      teamId = userDoc.data()?.teamId;
    } catch(quotaErr){
      console.warn("Firestore quota exceeded - bypassing credit check:", quotaErr.message);
      // Allow generation to proceed without credit check
      userDoc = { data: function(){ return { credits: 999999, teamId: null }; }, exists: true };
    }
    let isTeamMember = false;
    if(teamId){
      const teamDoc = await db.collection("teams").doc(teamId).get();
      if(teamDoc.exists){
        const team = teamDoc.data();
        const nextRenewal = team.nextRenewal ? team.nextRenewal.toDate() : null;
        const isExpired = nextRenewal && new Date() > nextRenewal;
        if(isExpired){
          return res.status(402).json({ error:"Your team plan has expired. Please ask your admin to renew." });
        }
        if(team.credits === -1 || team.credits > 0){
          isTeamMember = true;
          console.log("Team generation allowed for:", user.uid, "plan:", team.plan, "credits:", team.credits);
        } else {
          return res.status(402).json({ error:"Your team has run out of credits. Please ask your admin to top up." });
        }
      }
    }
    // Only check individual credits if not a team member
    if(!isTeamMember){
      const individualCredits = userDoc.data()?.credits || 0;
      const cost = text.length;
      if(!user.email_verified){
        return res.status(403).json({ error:"Please verify your email address before generating. Check your inbox for the verification link." });
      }
      if(individualCredits < cost){
        return res.status(402).json({ error:"Insufficient credits. You need "+cost.toLocaleString()+" but have "+individualCredits.toLocaleString()+". Please top up." });
      }
    }



    try {
    const MK = process.env.MINIMAX_API_KEY;
    const MK2 = process.env.MINIMAX_API_KEY_2 || MK;
    const MK3 = process.env.MINIMAX_API_KEY_3 || MK;
    const MK4 = process.env.MINIMAX_API_KEY_4 || MK;
const MK5 = process.env.MINIMAX_API_KEY_5 || MK;
const MK6 = process.env.MINIMAX_API_KEY_6 || MK;
const MK7 = process.env.MINIMAX_API_KEY_7 || MK;
const MK8 = process.env.MINIMAX_API_KEY_8 || MK;
const MK9 = process.env.MINIMAX_API_KEY_9 || MK;
const MK10 = process.env.MINIMAX_API_KEY_10 || MK;
    const voiceIdMap = {



      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_c6a2db4b-7255-11f1-83ef-8afcbb8b5b5c",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_6b545cbd-6e81-11f1-a3fb-6a64dd77666f",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_52793860-6249-11f1-8f84-faf87dcc54b3"
    };
    const voiceIdMap3 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_60328e8c-754d-11f1-8b87-ba0ad3e185a0",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_8e466452-754d-11f1-8b87-ba0ad3e185a0",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_77b427fc-754d-11f1-83ef-8afcbb8b5b5c"
    };
    const voiceIdMap4 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_8e134ce0-7587-11f1-8b87-ba0ad3e185a0",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_1eb29ec7-7588-11f1-a392-62a1f5ede8a7",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_cc4888fe-7587-11f1-8fdf-22f27a8feaff"
    };
    const voiceIdMap5 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_1530bf04-8376-11f1-be88-52778882d255",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_6f5b569b-8376-11f1-b0af-0eac018832f6",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_d495c97b-6520-11f1-8fdf-22f27a8feaff"
    };
    const voiceIdMap6 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_723c822a-9359-11f1-9bc8-c2d08a553394",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_088b4578-935a-11f1-8c05-cea64614d791",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_63c656cc-935a-11f1-8c05-cea64614d791"
    };
    const voiceIdMap7 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_c3df9419-9402-11f1-834d-364bc9e5c396",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_096c364f-9403-11f1-916c-ee98c056a384",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_7735ef42-9403-11f1-84c0-1e0b7b847846"
    };
    const voiceIdMap8 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_a8ebb1fc-9402-11f1-916c-ee98c056a384",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_eee5e94b-9402-11f1-916c-ee98c056a384",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_36d80c89-9403-11f1-b0af-0eac018832f6"
    };
    const voiceIdMap9 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_672e7c11-94bd-11f1-b0af-0eac018832f6",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_2f6d9d90-94be-11f1-8a72-5e514109a081",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_f73cdce5-94be-11f1-834d-364bc9e5c396"
    };
    const voiceIdMap10 = {
      "moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e": "moss_audio_4e69cfb0-94c3-11f1-9bc8-c2d08a553394",
      "moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff": "moss_audio_f1c71a0f-94c3-11f1-85f5-ee6191b6ca6b",
      "moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181": "moss_audio_6521e6fb-94c4-11f1-8a72-5e514109a081"
    };



    var voiceId2 = voiceIdMap[voiceId] || voiceId;
    var voiceId3 = voiceIdMap3[voiceId] || voiceId;
    var voiceId4 = voiceIdMap4[voiceId] || voiceId;
var voiceId5 = voiceIdMap5[voiceId] || voiceId;
var voiceId6 = voiceIdMap6[voiceId] || voiceId;
var voiceId7 = voiceIdMap7[voiceId] || voiceId;
var voiceId8 = voiceIdMap8[voiceId] || voiceId;
var voiceId9 = voiceIdMap9[voiceId] || voiceId;
var voiceId10 = voiceIdMap10[voiceId] || voiceId;



    // Check if this is a user-cloned voice with multiple account IDs
    if(voiceId.startsWith("clone_") || voiceId.startsWith("voice_") || voiceId.startsWith("moss_audio_") || voiceId.startsWith("audlabs")){
      try {
        const clonedSnap = await db.collection("users").doc(user.uid).collection("clonedVoices").where("voiceId","==",voiceId).limit(1).get();
        if(!clonedSnap.empty){
          const cloneData = clonedSnap.docs[0].data();
          // If it's a Kokoro clone, use Kokoro server for generation
          if(cloneData.provider === "kokoro" && voiceId.startsWith("clone_")){
            try {
              // Limit cloned voice to 1500 characters to prevent memory issues
              const cloneText = text.length > 1500 ? text.slice(0, 1500) : text;
              const kokoroCloneRes = await axios.post(
                process.env.KOKORO_TTS_URL + "/generate-cloned",
                { text: cloneText, voiceId: voiceId, speed: parseFloat(speed)||1.0, language: "en" },
                { headers: { "x-api-key": process.env.KOKORO_TTS_KEY, "Content-Type": "application/json" }, responseType: "arraybuffer", timeout: 280000 }
              );
              res.set('Content-Type', 'audio/wav');
              res.set('Content-Length', kokoroCloneRes.data.length);
              return res.send(Buffer.from(kokoroCloneRes.data));
            } catch(kokoroCloneErr){
              console.error("Kokoro clone generation failed:", kokoroCloneErr.message);
              return res.status(500).json({ error: "Failed to generate with cloned voice. Please try again." });
            }
          }
          // MiniMax clones — handle failover with temporary re-cloning
          const minimaxVoiceId = cloneData.minimaxVoiceId || voiceId;
          const storageFilename = cloneData.storageFilename;
          voiceId2 = minimaxVoiceId;
          voiceId3 = minimaxVoiceId;
          voiceId4 = minimaxVoiceId;
          voiceId5 = minimaxVoiceId;
          voiceId6 = minimaxVoiceId;
          voiceId7 = minimaxVoiceId;
          voiceId8 = minimaxVoiceId;
          voiceId9 = minimaxVoiceId;
          voiceId10 = minimaxVoiceId;

          // Store clone data for failover re-cloning
          req.cloneData = { minimaxVoiceId, storageFilename, cloneData };
        }
      } catch(clonedErr){ console.warn("Failed to fetch cloned voice IDs:", clonedErr.message); }
    }

    let response;
    try {
        response = await axios.post(
      "https://api.minimax.io/v1/t2a_v2",
      {
        model: "speech-2.8-hd",
        text: text,
        stream: false,
        voice_setting: { voice_id: voiceId, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
        audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
        output_format: "hex"
      },
      { headers: { Authorization:`Bearer ${MK}`, "Content-Type":"application/json" }, timeout: 20000 }
    );
    if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access") || response.data.base_resp.status_msg?.includes("voice_id"))){
      throw new Error("Rate limit hit on primary key");
    }
   } catch(primaryErr){
      console.warn("Primary API key failed, switching to secondary:", primaryErr.message);
      // If cloned voice failed on primary — try temp re-clone on secondary
      console.log("Primary error for cloneData check:", primaryErr.message, "cloneData:", !!req.cloneData);
      if(req.cloneData){

        try {
          console.log("Trying temp re-clone on Account 2 for cloned voice");

          response = await tempCloneAndGenerate(req.cloneData.minimaxVoiceId, req.cloneData.storageFilename, MK2, text, speed, vol, pitch);
          if(response?.data?.data?.audio) {
            console.log("Temp re-clone on Account 2 succeeded");
          }
        } catch(tempErr){
          console.warn("Temp re-clone on Account 2 failed:", tempErr.message);
          try {
            response = await tempCloneAndGenerate(req.cloneData.minimaxVoiceId, req.cloneData.storageFilename, MK3, text, speed, vol, pitch);
          } catch(temp3Err){
            console.warn("Temp re-clone on Account 3 failed:", temp3Err.message);
            try {
              response = await tempCloneAndGenerate(req.cloneData.minimaxVoiceId, req.cloneData.storageFilename, MK4, text, speed, vol, pitch);
            } catch(temp4Err){
              console.warn("Temp re-clone on Account 4 failed:", temp4Err.message);
              try {
                response = await tempCloneAndGenerate(req.cloneData.minimaxVoiceId, req.cloneData.storageFilename, MK5, text, speed, vol, pitch);
              } catch(temp5Err){
                console.warn("Temp re-clone on Account 5 failed:", temp5Err.message);
                try {
                  response = await tempCloneAndGenerate(req.cloneData.minimaxVoiceId, req.cloneData.storageFilename, MK6, text, speed, vol, pitch);
                } catch(temp6Err){
                  console.warn("Temp re-clone on Account 6 failed:", temp6Err.message);
                  try {
                    response = await tempCloneAndGenerate(req.cloneData.minimaxVoiceId, req.cloneData.storageFilename, MK7, text, speed, vol, pitch);
                  } catch(temp7Err){
                    console.warn("Temp re-clone on Account 7 failed:", temp7Err.message);
                    try {
                      response = await tempCloneAndGenerate(req.cloneData.minimaxVoiceId, req.cloneData.storageFilename, MK8, text, speed, vol, pitch);
                    } catch(temp8Err){
                      console.warn("Temp re-clone on Account 8 failed:", temp8Err.message);
                      try {
                        response = await tempCloneAndGenerate(req.cloneData.minimaxVoiceId, req.cloneData.storageFilename, MK9, text, speed, vol, pitch);
                      } catch(temp9Err){
                        console.warn("Temp re-clone on Account 9 failed:", temp9Err.message);
                        try {
                          response = await tempCloneAndGenerate(req.cloneData.minimaxVoiceId, req.cloneData.storageFilename, MK10, text, speed, vol, pitch);
                        } catch(temp10Err){
                          console.warn("All temp re-clone attempts failed");
                        }
                      }
                    }
                  }
                }
              }
            }
          }

        }
      }
      if(!response || !response?.data?.data?.audio){
      try {
            response = await axios.post(
        "https://api.minimax.io/v1/t2a_v2",
        {
          model: "speech-2.8-hd",
          text: text,
          stream: false,
          voice_setting: { voice_id: voiceId2, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
          audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
          output_format: "hex"
        },
        { headers: { Authorization:`Bearer ${MK2}`, "Content-Type":"application/json" }, timeout: 20000 }
      );
      if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access") || response.data.base_resp.status_msg?.includes("voice_id"))){
        throw new Error("Rate limit hit on secondary key");
      }
      } catch(secondaryErr){
        console.warn("Secondary API key failed, switching to tertiary:", secondaryErr.message);
        try {
                response = await axios.post(
          "https://api.minimax.io/v1/t2a_v2",
          {
            model: "speech-2.8-hd",
            text: text,
            stream: false,
            voice_setting: { voice_id: voiceId3, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
            audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
            output_format: "hex"
          },
          { headers: { Authorization:`Bearer ${MK3}`, "Content-Type":"application/json" }, timeout: 20000 }
        );
        if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access") || response.data.base_resp.status_msg?.includes("voice_id"))){
          throw new Error("Rate limit hit on tertiary key");
        }
        } catch(tertiaryErr){
          console.warn("Tertiary API key failed, switching to quaternary:", tertiaryErr.message);
          try {
                    response = await axios.post(
            "https://api.minimax.io/v1/t2a_v2",
            {
              model: "speech-2.8-hd",
              text: text,
              stream: false,
              voice_setting: { voice_id: voiceId4, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
              audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
              output_format: "hex"
            },
            { headers: { Authorization:`Bearer ${MK4}`, "Content-Type":"application/json" }, timeout: 20000 }
          );
          if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access") || response.data.base_resp.status_msg?.includes("voice_id"))){
            throw new Error("Rate limit hit on quaternary key");
          }
          } catch(quaternaryErr){
            console.warn("Quaternary API key failed, switching to quinary:", quaternaryErr.message);
            try {
                            response = await axios.post(
                "https://api.minimax.io/v1/t2a_v2",
                {
                  model: "speech-2.8-hd",
                  text: text,
                  stream: false,
                  voice_setting: { voice_id: voiceId5, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
                  audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                  output_format: "hex"
                },
                { headers: { Authorization:`Bearer ${MK5}`, "Content-Type":"application/json" }, timeout: 20000 }
              );
              if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                throw new Error("Rate limit hit on quinary key");
              }
            } catch(quinaryErr){
                            console.warn("Quinary key failed, switching to senary:", quinaryErr.message);
              try {
                response = await axios.post(
                  "https://api.minimax.io/v1/t2a_v2",
                  {
                    model: "speech-2.8-hd",
                    text: text,
                    stream: false,
                    voice_setting: { voice_id: voiceId6, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
                    audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                    output_format: "hex"
                  },
                  { headers: { Authorization:`Bearer ${MK6}`, "Content-Type":"application/json" }, timeout: 20000 }
                );
                if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                  throw new Error("Rate limit hit on senary key");
                }
              } catch(senaryErr){
                                console.warn("Senary key failed, switching to septenary:", senaryErr.message);
                try {
                  response = await axios.post(
                    "https://api.minimax.io/v1/t2a_v2",
                    {
                      model: "speech-2.8-hd",
                      text: text,
                      stream: false,
                      voice_setting: { voice_id: voiceId7, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
                      audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                      output_format: "hex"
                    },
                    { headers: { Authorization:`Bearer ${MK7}`, "Content-Type":"application/json" }, timeout: 20000 }
                  );
                  if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                    throw new Error("Rate limit hit on septenary key");
                  }
                } catch(septenaryErr){
                  console.warn("Septenary key failed, switching to octonary:", septenaryErr.message);
                  try {
                    response = await axios.post(
                      "https://api.minimax.io/v1/t2a_v2",
                      {
                        model: "speech-2.8-hd",
                        text: text,
                        stream: false,
                        voice_setting: { voice_id: voiceId8, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
                        audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                        output_format: "hex"
                      },
                      { headers: { Authorization:`Bearer ${MK8}`, "Content-Type":"application/json" }, timeout: 20000 }
                    );
                    if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                      throw new Error("Rate limit hit on octonary key");
                    }
                  } catch(octonaryErr){
                    console.warn("Octonary key failed, switching to nonary:", octonaryErr.message);
                    try {
                      response = await axios.post(
                        "https://api.minimax.io/v1/t2a_v2",
                        {
                          model: "speech-2.8-hd",
                          text: text,
                          stream: false,
                          voice_setting: { voice_id: voiceId9, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
                          audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                          output_format: "hex"
                        },
                        { headers: { Authorization:`Bearer ${MK9}`, "Content-Type":"application/json" }, timeout: 20000 }
                      );
                      if(response.data && response.data.base_resp && (response.data.base_resp.status_code === 1002 || response.data.base_resp.status_code === 2056 || response.data.base_resp.status_msg?.includes("limit") || response.data.base_resp.status_msg?.includes("access"))){
                        throw new Error("Rate limit hit on nonary key");
                      }
                    } catch(nonaryErr){
                      console.warn("Nonary key failed, switching to denary:", nonaryErr.message);
                      response = await axios.post(
                        "https://api.minimax.io/v1/t2a_v2",
                        {
                          model: "speech-2.8-hd",
                          text: text,
                          stream: false,
                          voice_setting: { voice_id: voiceId10, speed: parseFloat(speed)||1.0, vol: parseFloat(vol)||1.0, pitch: parseInt(pitch)||0 },
                          audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
                          output_format: "hex"
                        },
                        { headers: { Authorization:`Bearer ${MK10}`, "Content-Type":"application/json" }, timeout: 20000 }
                      );
                    }
                  }
                }
              }
            }
          }
        }
      }
      }
    }
    // ── KOKORO FALLBACK REMOVED ──




        if(!response?.data?.data?.audio){
      const errMsg400 = response?.data?.base_resp?.status_msg || "Generation failed";
      const userAgent = req.headers["user-agent"] || "unknown";
      console.error("Final generation failure — actual MiniMax error:", errMsg400, "| User-Agent:", userAgent, "| UID:", user.uid);
      const isCapacityIssue = errMsg400.includes("limit") || errMsg400.includes("quota") || errMsg400.includes("exceeded") || errMsg400.includes("Token Plan") || errMsg400.includes("Credits");
      const isVoiceIssue = errMsg400.includes("voice_id") || errMsg400.includes("access") || errMsg400.includes("not found");
      if(isCapacityIssue){
        try {
          await db.collection("cache").doc("minimaxStatus").set({
            exhausted: true,
            exhaustedAt: admin.firestore.FieldValue.serverTimestamp(),
            message: "⚠️ High traffic alert! Our voice generation servers are at capacity."
          }, {merge: true});
        } catch(e){ console.warn("Status save failed:", e.message); }
        return res.status(400).json({ error:"⚠️ High traffic alert! Too many creators are generating at the same time. Please wait 2-3 hours and try again — we appreciate your patience." });
      }
      if(isVoiceIssue){
        return res.status(400).json({ error:"⚠️ Your cloned voice is not available on the current server. Please delete your cloned voice and re-clone it to fix this permanently." });
      }
      return res.status(400).json({ error: "⚠️ Generation failed: " + errMsg400 + ". Please try again — if this continues, contact support." });
    }


    if (response.data?.data?.audio) {
      const hexAudio = response.data.data.audio;
      const audioBuffer = Buffer.from(hexAudio, 'hex');
      try {
        await db.collection("cache").doc("minimaxStatus").set({
          exhausted: false,
          resetAt: admin.firestore.FieldValue.serverTimestamp()
        }, {merge: true});
      } catch(e){}
      res.set('Content-Type', 'audio/mpeg');
      res.set('Content-Length', audioBuffer.length);
      return res.send(audioBuffer);
    }

    var errMsg400 = response.data?.base_resp?.status_msg || "Generation failed";
    if(errMsg400?.includes("access") || errMsg400?.includes("voice_id")){
      return res.status(400).json({ error:"⚠️ Your cloned voice is not available on the current server. Please delete your cloned voice and re-clone it to fix this permanently." });
    }
    var friendlyMsg = "⚠️ High traffic alert! Too many creators are generating at the same time. Please wait 2-3 hours and try again — we appreciate your patience.";
    if(errMsg400.includes("Token Plan") || errMsg400.includes("usage limit") || errMsg400.includes("Credits") || errMsg400.includes("limit") || errMsg400.includes("quota") || errMsg400.includes("exceeded") || errMsg400.includes("upgrade") || errMsg400.includes("Upgrade")){
      errMsg400 = friendlyMsg;
    }
    return res.status(400).json({ error: errMsg400 });
    } catch(e) {
    const userAgentErr = req.headers["user-agent"] || "unknown";
    console.error("Generate error:", e.response?.data || e.message, "| User-Agent:", userAgentErr, "| UID:", user.uid);
    var errMsg = e.response?.data?.base_resp?.status_msg || e.message || "";
    if(errMsg400?.includes("access") || errMsg400?.includes("voice_id") || errMsg?.includes("access") || errMsg?.includes("voice_id")){
      return res.status(400).json({ error:"⚠️ Your cloned voice is not available on the current server. Please delete your cloned voice and re-clone it to fix this permanently." });
    }
    var friendlyMsg = "⚠️ High traffic alert! Too many creators are generating at the same time. Please wait 2-3 hours and try again — we appreciate your patience.";
    if(errMsg.includes("Token Plan") || errMsg.includes("usage limit") || errMsg.includes("Credits") || errMsg.includes("limit") || errMsg.includes("quota") || errMsg.includes("exceeded") || errMsg.includes("upgrade") || errMsg.includes("Upgrade")){
      errMsg = friendlyMsg;
    }
    if(e.response?.status === 429 || e.response?.status === 402){
      errMsg = friendlyMsg;
    }
    return res.status(500).json({ error: errMsg });
  }
});


// ── CARD PAYMENT (FLUTTERWAVE) ──
app.post("/api/create-card-payment", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { amountUSD, creditsAmount } = req.body;
  if (!amountUSD || amountUSD < 5) return res.status(400).json({ error:"Minimum payment is $5" });
  try {
    const txRef = `VG-CARD-user.uid.slice(0,8)-{Date.now()}`;
    // Save pending payment to Firestore
    await db.collection("cardPayments").doc(txRef).set({
      uid: user.uid, email: user.email,
      amountUSD, creditsAmount: parseInt(creditsAmount),
      txRef, status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ success:true, txRef, amountUSD });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── FLUTTERWAVE WEBHOOK ──
app.post("/api/flutterwave-webhook", express.raw({ type:"*/*" }), async (req,res) => {
  try {
    const sig = req.headers["verif-hash"];
    if (sig !== FLW_WEBHOOK_SECRET) {
      console.error("Invalid Flutterwave webhook signature");
      return res.status(400).json({ error:"Invalid signature" });
    }
    const payload = typeof req.body === "string" ? JSON.parse(req.body) : (Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString("utf8")) : req.body);
    console.log("Flutterwave webhook:", payload.event, payload.data?.tx_ref);
    if (payload.event !== "charge.completed") return res.json({ received:true });
    if (payload.data?.status !== "successful") return res.json({ received:true });
    const txRef = payload.data?.tx_ref;
    if (!txRef) return res.json({ received:true });
    // Find payment record
    const payDoc = await db.collection("cardPayments").doc(txRef).get();
    if (!payDoc.exists) return res.json({ received:true });
    const payData = payDoc.data();
    if (payData.status === "completed") return res.json({ received:true, duplicate:true });
 // Credit user
    const creditsToAdd = payData.creditsAmount;

    await db.collection("users").doc(payData.uid).update({
      credits: admin.firestore.FieldValue.increment(creditsToAdd),
      hasPurchased: true,
    });
const today = new Date().toISOString().split("T")[0];
    await db.collection("stats").doc("revenue").set({
      totalUSD: admin.firestore.FieldValue.increment(payData.amountUSD || 0),
      totalTransactions: admin.firestore.FieldValue.increment(1),
      lastUpdated: admin.firestore.FieldValue.serverTimestamp(),
      [`daily.${today}`]: admin.firestore.FieldValue.increment(payData.amountUSD || 0)
    }, {merge: true});
    await db.collection("users").doc(payData.uid).collection("transactions").add({
      type:"credit", amount:creditsToAdd,
      note:`Card top-up — $${payData.amountUSD} — ${creditsToAdd.toLocaleString()} credits`,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    await db.collection("cardPayments").doc(txRef).update({ status:"completed" });
    // Referral commission
    const userDoc = await db.collection("users").doc(payData.uid).get();
    const referredBy = userDoc.data()?.referredBy;
    if (referredBy) {
      const savedRate3 = userDoc.data()?.referralCommissionRate || 10;
      const referrerDocCheck3 = await db.collection("users").doc(referredBy).get();
      const referrerDataCheck3 = referrerDocCheck3.exists ? referrerDocCheck3.data() : {};
      const rateExpiry3 = referrerDataCheck3.referralRateExpiry ? referrerDataCheck3.referralRateExpiry.toDate() : null;
      const effectiveRate3 = (rateExpiry3 && rateExpiry3 < new Date()) ? 10 : savedRate3;
      const referralRate3 = effectiveRate3 / 100;
      const commissionNGN = Math.floor(payData.amountNGN * referralRate3);
      const commissionPct3 = Math.round(referralRate3 * 100);
      await db.collection("users").doc(referredBy).update({
        referralEarningsNGN: admin.firestore.FieldValue.increment(commissionNGN),
      });
      await db.collection("users").doc(referredBy).collection("referralEarnings").add({
        fromUid:payData.uid, fromEmail:payData.email, amountNGN:commissionNGN,
        note:`${commissionPct3}% referral from $${payData.amountUSD} card payment`,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }
    console.log("✅ Card payment credited:", creditsToAdd, "to", payData.uid);
    return res.json({ success:true });
  } catch(e) { console.error("FLW webhook error:", e.message); return res.status(500).json({ error:e.message }); }
});

// ── VERIFY CARD PAYMENT ──
app.post("/api/verify-card-payment", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  const { txRef } = req.body;
  if (!txRef) return res.status(400).json({ error:"txRef required" });
  try {
    const FLW_SECRET = FLW_SECRET_KEY;
    const verifyRes = await axios.get(
      `https://api.flutterwave.com/v3/transactions/verify_by_reference?tx_ref=${txRef}`,
      { headers: { Authorization:`Bearer ${FLW_SECRET}` }}
    );
    const data = verifyRes.data?.data;
    if (data?.status === "successful") {
      const payDoc = await db.collection("cardPayments").doc(txRef).get();
      if (!payDoc.exists) return res.status(400).json({ error:"Payment not found" });
      const payData = payDoc.data();
      if (payData.status === "completed") return res.json({ success:true, alreadyCredited:true });
      const creditsToAdd = payData.creditsAmount;
      await db.collection("users").doc(user.uid).update({
        credits: admin.firestore.FieldValue.increment(creditsToAdd)
      });
      await db.collection("users").doc(user.uid).collection("transactions").add({
        type:"credit", amount:creditsToAdd,
        note:`Card top-up — $${payData.amountUSD} — ${creditsToAdd.toLocaleString()} credits`,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
      await db.collection("cardPayments").doc(txRef).update({ status:"completed" });
      return res.json({ success:true, credits:creditsToAdd });
    }
    return res.json({ success:false, status:data?.status });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// Serve frontend
app.get("/.env", (req,res) => { res.status(404).send("Not found"); });
app.get("/.env*", (req,res) => { res.status(404).send("Not found"); });
app.get("/secrets*", (req,res) => { res.status(404).send("Not found"); });
app.get("/config.json", (req,res) => { res.status(404).send("Not found"); });
app.get("/firebase-config.json", (req,res) => { res.status(404).send("Not found"); });
app.get("/.aws*", (req,res) => { res.status(404).send("Not found"); });
app.get("/api/config", (req,res) => { res.status(404).send("Not found"); });
app.get("/api/env", (req,res) => { res.status(404).send("Not found"); });
app.get("/api/settings", (req,res) => { res.status(404).send("Not found"); });
app.get("/google-services.json", (req,res) => { res.status(404).send("Not found"); });
app.get("/xmlrpc.php", (req,res) => { res.status(404).send("Not found"); });
app.get("/blog/xmlrpc.php", (req,res) => { res.status(404).send("Not found"); });
app.get("/wordpress/xmlrpc.php", (req,res) => { res.status(404).send("Not found"); });
app.get("/landing.html", (req,res) => {
  res.redirect("/");
});
app.get("/robots.txt", (req,res) => {
  var host = req.headers.host || "";
  if(host.startsWith("app.")){
    res.set("Content-Type","text/plain");
    return res.send("User-agent: *\nDisallow: /");
  }
  res.set("Content-Type","text/plain");
  res.send("User-agent: *\nDisallow: /api/\nDisallow: /login\nDisallow: /admin\nSitemap: https://audlabs.io/sitemap.xml");
});

app.get("/ads.txt", (req,res) => {
  res.set("Content-Type","text/plain");
  res.send("google.com, pub-6338752366923352, DIRECT, f08c47fec0942fa0");
});


app.get("/", (req,res) => {
  var host = req.headers.host || "";
  if(host.startsWith("app.")){
    res.redirect("https://app.audlabs.io/login");
  } else if(host.startsWith("platform.")){
    res.sendFile(path.join(__dirname, "public", "platform.html"));
    } else if(host.startsWith("mail.")){
    res.sendFile(path.join(__dirname, "public", "mail.html"));
  } else if(host.startsWith("reply.")){
    res.sendFile(path.join(__dirname, "public", "reply.html"));
  } else {
    res.sendFile(path.join(__dirname, "landing.html"));
  }
});

app.get("/admin", (req,res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});
app.get("/login", (req,res) => {
  var host = req.headers.host || "";
  if(host.startsWith("app.")){
    res.sendFile(path.join(__dirname, "public", "app.html"));
  } else {
    res.redirect("https://app.audlabs.io/login");
  }
});
app.get("/__/auth/action", (req,res) => {
  res.sendFile(path.join(__dirname, "public", "app.html"));
});

app.get("/privacy-policy", (req,res) => {
  res.sendFile(path.join(__dirname, "public", "privacy.html"));
});
app.get("/seyi", (req,res) => {
  res.sendFile(path.join(__dirname, "public", "seyi.html"));
});
// ── SITEMAP ──
app.get("/sitemap.xml", async (req,res) => {
  try {
    const snap = await db.collection("blogPosts").where("published","==",true).get();
    const posts = snap.docs.map(function(d){ return d.data(); });
    const urls = [
      "https://audlabs.io/",
      "https://audlabs.io/blog",
      "https://audlabs.io/privacy-policy",
      "https://audlabs.io/status"
    ];
    posts.forEach(function(p){ if(p.slug) urls.push("https://audlabs.io/blog/"+p.slug); });
    const xml = '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+
      urls.map(function(u){ return '<url><loc>'+u+'</loc></url>'; }).join("")+
      '</urlset>';
    res.set("Content-Type","application/xml");
    res.send(xml);
  } catch(e){
    res.status(500).send("Error generating sitemap");
  }
});

// ── SAVE PUSH TOKEN ──
app.post("/api/save-push-token", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    const pushToken = req.body.pushToken;
    if(!pushToken) return res.status(400).json({ error:"pushToken required" });
    await db.collection("users").doc(user.uid).set({ pushToken: pushToken }, { merge: true });
    return res.json({ success:true });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});
// ── SEND PUSH NOTIFICATION (ADMIN) ──
app.post("/api/admin-send-push", async (req,res) => {
  const adminPassword = req.headers["x-admin-password"] || req.headers["x-admin-secret"];
  if(adminPassword !== "(Oluwaseyi23)" && adminPassword !== "audlabs-admin-2026") return res.status(401).json({ error:"Unauthorized" });
  try {
    const title = req.body.title;
    const body = req.body.body;
    if(!title || !body) return res.status(400).json({ error:"title and body required" });
        const usersSnap = await db.collection("users").where("pushToken","!=",null).get();
    const tokenSet = new Set();
    usersSnap.docs.forEach(function(doc){
      const t = doc.data().pushToken;
      if(t) tokenSet.add(t);
    });
    const tokens = Array.from(tokenSet);
    if(!tokens.length){
      return res.json({ success:true, sent:0, message:"No devices registered yet." });
    }
    const messaging = admin.messaging();
    const response = await messaging.sendEachForMulticast({
      tokens: tokens,
      notification: { title: title, body: body }
    });
    return res.json({ success:true, sent:response.successCount, failed:response.failureCount, totalDevices:tokens.length });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});
// ── SEND VERIFICATION CODE ──
app.post("/api/send-verification-code", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + (10 * 60 * 1000);
    await db.collection("users").doc(user.uid).set({
      verificationCode: code,
      verificationCodeExpiresAt: expiresAt
    }, { merge: true });
    await audlabsTransporter.sendMail({
      from: '"AudLabs" <hello@audlabs.io>',
      to: user.email,
      subject: `Your AudLabs verification code: ${code}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;">
          <h2 style="color:#1a1a1a;">Verify your email</h2>
          <p style="color:#555;font-size:14px;line-height:1.6;">Enter this code to verify your AudLabs account:</p>
          <div style="background:#f5f5f5;border-radius:10px;padding:20px;text-align:center;margin:20px 0;">
            <span style="font-size:32px;font-weight:700;letter-spacing:8px;color:#c9a84c;">${code}</span>
          </div>
                    <p style="color:#999;font-size:12px;">This code expires in 10 minutes.</p>
          <p style="color:#999;font-size:12px;margin-top:16px;">If you didn't request to verify this email address, kindly ignore this email.<br><br>Best regards,<br>The AudLabs Team</p>
        </div>
      `
    });
    return res.json({ success:true });
  } catch(e){
    console.error("Send verification code error:", e.message);
    return res.status(500).json({ error:"Failed to send verification code. Please try again." });
  }
});
// ── VERIFY CODE ──
app.post("/api/verify-code", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    const code = req.body.code;
    if(!code) return res.status(400).json({ error:"Code required" });
    const userDoc = await db.collection("users").doc(user.uid).get();
    const data = userDoc.data();
    if(!data.verificationCode) return res.status(400).json({ error:"No verification code found. Please request a new one." });
    if(Date.now() > data.verificationCodeExpiresAt) return res.status(400).json({ error:"Code expired. Please request a new one." });
    if(data.verificationCode !== code) return res.status(400).json({ error:"Incorrect code. Please try again." });
    await admin.auth().updateUser(user.uid, { emailVerified: true });
    await db.collection("users").doc(user.uid).update({
      verificationCode: admin.firestore.FieldValue.delete(),
      verificationCodeExpiresAt: admin.firestore.FieldValue.delete()
    });
    return res.json({ success:true });
  } catch(e){
    console.error("Verify code error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});

app.get("/delete-account", (req,res) => {
  var host = req.headers.host || "";
  if(host.startsWith("app.")) return res.redirect("https://audlabs.io/delete-account");
  res.sendFile(path.join(__dirname, "public", "delete-account.html"));
});
app.get("/contact", (req,res) => {
  var host = req.headers.host || "";
  if(host.startsWith("app.")) return res.redirect("https://audlabs.io/contact");
  res.sendFile(path.join(__dirname, "public", "contact.html"));
});

app.get("/status", (req,res) => {
  res.sendFile(path.join(__dirname, "public", "status.html"));
});

app.get("/docs", (req,res) => {
  var host = req.headers.host || "";
  if(host.startsWith("platform.")){
    res.sendFile(path.join(__dirname, "public", "docs.html"));
  } else {
    res.redirect("https://platform.audlabs.io/docs");
  }
});
app.get("/platform", (req,res) => {
  var host = req.headers.host || "";
  if(host.startsWith("platform.")){
    res.redirect("https://platform.audlabs.io");
  } else {
    res.sendFile(path.join(__dirname, "public", "platform.html"));
  }
});

app.get("/blog", (req,res) => {
  res.sendFile(path.join(__dirname, "public", "blog.html"));
});
app.get("/blog/:slug", (req,res) => {
  res.sendFile(path.join(__dirname, "public", "blog-post.html"));
});


// ── FOLLOW-UP EMAILS ──
app.post("/api/send-followup-emails", async (req,res) => {
  const secret = req.headers["x-cron-secret"] || "";
  if(secret !== "audlabs-monthly-2026"){
    return res.status(401).json({ error:"Unauthorized" });
  }
  try {
    const now = new Date();
    const usersSnap = await db.collection("users").orderBy("createdAt", "desc").limit(200).get();
    let sent = 0;
    for(const doc of usersSnap.docs){
      const data = doc.data();
      if(!data.email || !data.createdAt) continue;
      const createdAt = data.createdAt.toDate();
      const daysSince = Math.floor((now - createdAt) / (1000 * 60 * 60 * 24));
      const emailsSent = data.followupEmailsSent || [];

      // Day 3 email
      if(daysSince >= 3 && !emailsSent.includes("day3")){
        await sendbyteTransporter.sendMail({
          from: `"AudLabs" <${process.env.AUDLABS_SMTP_USER}>`,
          to: data.email,
          subject: "Have you tried AudLabs yet? 🎙",
          html: `
            <div style="font-family:Inter,sans-serif;max-width:600px;margin:0 auto;background:#080c14;color:#fff;padding:40px;border-radius:16px;">
              <div style="text-align:center;margin-bottom:32px;">
                <img src="https://app.audlabs.io/logo.png" style="width:60px;height:60px;object-fit:contain;margin-bottom:16px;">
                <h1 style="font-size:24px;font-weight:300;color:#fff;">Have you tried <span style="color:#c9a84c;">AudLabs</span> yet?</h1>
              </div>
              <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">Dear ${data.displayName||"Creator"},</p>
              <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">We noticed you recently joined AudLabs but have not yet generated your first voiceover. You still have <strong style="color:#c9a84c;">5,000 free credits</strong> waiting for you.</p>
              <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">With AudLabs, you can generate professional voiceovers for your YouTube videos, podcasts and content in seconds — no recording equipment needed.</p>
              <div style="text-align:center;margin:32px 0;">
                <a href="https://app.audlabs.io/text-to-speech" style="background:linear-gradient(135deg,#c9a84c,#e8c97a);color:#111;padding:12px 32px;border-radius:10px;text-decoration:none;font-weight:700;font-size:14px;">Generate Your First Voiceover</a>
              </div>
              <p style="font-size:13px;color:rgba(255,255,255,0.4);text-align:center;margin-top:32px;">Follow us: <a href="https://x.com/AudLabs" style="color:#c9a84c;">X</a> · <a href="https://youtube.com/@AudLabs" style="color:#c9a84c;">YouTube</a> · <a href="https://t.me/AudLabs" style="color:#c9a84c;">Telegram</a></p>
              <p style="font-size:12px;color:rgba(255,255,255,0.3);text-align:center;">© 2026 AudLabs. All rights reserved.</p>
            </div>
          `
        });
        await db.collection("users").doc(doc.id).update({
          followupEmailsSent: admin.firestore.FieldValue.arrayUnion("day3")
        });
        sent++;
      }

      // Day 7 email
      if(daysSince >= 7 && !emailsSent.includes("day7")){
        await sendbyteTransporter.sendMail({
          from: `"AudLabs" <${process.env.AUDLABS_SMTP_USER}>`,
          to: data.email,
          subject: "Your free credits are still waiting for you 🎙",
          html: `
            <div style="font-family:Inter,sans-serif;max-width:600px;margin:0 auto;background:#080c14;color:#fff;padding:40px;border-radius:16px;">
              <div style="text-align:center;margin-bottom:32px;">
                <img src="https://app.audlabs.io/logo.png" style="width:60px;height:60px;object-fit:contain;margin-bottom:16px;">
                <h1 style="font-size:24px;font-weight:300;color:#fff;">Your Free Credits Are <span style="color:#c9a84c;">Still Waiting</span></h1>
              </div>
              <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">Dear ${data.displayName||"Creator"},</p>
              <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">It has been a week since you joined AudLabs. Your <strong style="color:#c9a84c;">5,000 free credits</strong> are still available and waiting for you to use.</p>
              <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">Here is what AudLabs can do for you:</p>
              <ul style="color:rgba(255,255,255,0.7);font-size:14px;line-height:2;">
                <li>🎙 Generate professional voiceovers with 26+ AI voices</li>
                <li>⚡ Clone any voice instantly with just a 10-second sample</li>
                <li>🌍 Generate in English, French and Spanish</li>
                <li>📥 Download in high quality MP3 instantly</li>
              </ul>
              <div style="text-align:center;margin:32px 0;">
                <a href="https://app.audlabs.io/text-to-speech" style="background:linear-gradient(135deg,#c9a84c,#e8c97a);color:#111;padding:12px 32px;border-radius:10px;text-decoration:none;font-weight:700;font-size:14px;">Start Generating Now</a>
              </div>
              <p style="font-size:13px;color:rgba(255,255,255,0.4);text-align:center;margin-top:32px;">Follow us: <a href="https://x.com/AudLabs" style="color:#c9a84c;">X</a> · <a href="https://youtube.com/@AudLabs" style="color:#c9a84c;">YouTube</a> · <a href="https://t.me/AudLabs" style="color:#c9a84c;">Telegram</a></p>
              <p style="font-size:12px;color:rgba(255,255,255,0.3);text-align:center;">© 2026 AudLabs. All rights reserved.</p>
            </div>
          `
        });
        await db.collection("users").doc(doc.id).update({
          followupEmailsSent: admin.firestore.FieldValue.arrayUnion("day7")
        });
        sent++;
      }

      // Day 30 email
      if(daysSince >= 30 && !emailsSent.includes("day30")){
        await sendbyteTransporter.sendMail({
          from: `"AudLabs" <${process.env.AUDLABS_SMTP_USER}>`,
          to: data.email,
          subject: "A message from AudLabs 🎙",
          html: `
            <div style="font-family:Inter,sans-serif;max-width:600px;margin:0 auto;background:#080c14;color:#fff;padding:40px;border-radius:16px;">
              <div style="text-align:center;margin-bottom:32px;">
                <img src="https://app.audlabs.io/logo.png" style="width:60px;height:60px;object-fit:contain;margin-bottom:16px;">
                <h1 style="font-size:24px;font-weight:300;color:#fff;">Your Fellow Creators Are <span style="color:#c9a84c;">Already Creating</span></h1>
              </div>
              <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">Dear ${data.displayName||"Creator"},</p>
              <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">It has been 30 days since you joined AudLabs. While you have been away, thousands of creators are already using AudLabs to generate professional voiceovers for their YouTube videos, podcasts and content.</p>
              <p style="font-size:15px;color:rgba(255,255,255,0.8);line-height:1.7;">Do not be left behind. Come back today and start creating with your free credits.</p>
              <div style="background:rgba(201,168,76,0.1);border:1px solid rgba(201,168,76,0.3);border-radius:12px;padding:24px;margin:24px 0;text-align:center;">
                <div style="font-size:36px;font-weight:700;color:#c9a84c;">5,000</div>
                <div style="font-size:14px;color:rgba(255,255,255,0.6);margin-top:4px;">Free Credits Still Available</div>
              </div>
              <div style="text-align:center;margin:32px 0;">
                <a href="https://app.audlabs.io/text-to-speech" style="background:linear-gradient(135deg,#c9a84c,#e8c97a);color:#111;padding:12px 32px;border-radius:10px;text-decoration:none;font-weight:700;font-size:14px;">Come Back and Create</a>
              </div>
              <p style="font-size:13px;color:rgba(255,255,255,0.4);text-align:center;margin-top:32px;">Follow us: <a href="https://x.com/AudLabs" style="color:#c9a84c;">X</a> · <a href="https://youtube.com/@AudLabs" style="color:#c9a84c;">YouTube</a> · <a href="https://t.me/AudLabs" style="color:#c9a84c;">Telegram</a></p>
              <p style="font-size:12px;color:rgba(255,255,255,0.3);text-align:center;">© 2026 AudLabs. All rights reserved.</p>
            </div>
          `
        });
        await db.collection("users").doc(doc.id).update({
          followupEmailsSent: admin.firestore.FieldValue.arrayUnion("day30")
        });
        sent++;
      }
    }
    console.log("Follow-up emails sent:", sent);
    return res.json({ success:true, emailsSent:sent });
  } catch(e){
    console.error("Follow-up email error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── CREATE TEAM PAYMENT (CARD) ──
app.post("/api/create-team-payment", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { teamName, plan, price, members, credits } = req.body;
    const txRef = `VG-TEAM-user.uid.slice(0,8)-{Date.now()}`;
    await db.collection("teamPayments").doc(txRef).set({
      uid: user.uid,
      email: user.email,
      teamName, plan, price, members, credits,
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ success:true, txRef });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── VERIFY TEAM PAYMENT (CARD) ──
app.post("/api/verify-team-payment", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { txRef } = req.body;
    const payDoc = await db.collection("teamPayments").doc(txRef).get();
    if(!payDoc.exists) return res.status(404).json({ error:"Payment not found" });
    const payData = payDoc.data();
    if(payData.status === "completed") return res.json({ success:false, error:"Already processed" });
    // Check if user already has a team
    const existingUserDoc = await db.collection("users").doc(user.uid).get();
    if(existingUserDoc.data()?.teamId) return res.status(400).json({ error:"You already have a team. You cannot create another team." });
    // Create the team
    const teamCode = "TEAM-" + Math.random().toString(36).substring(2,8).toUpperCase();
    const userDoc = await db.collection("users").doc(user.uid).get();
    const userEmail = userDoc.data()?.email || user.email || "";
    const teamRef = await db.collection("teams").add({
      teamName: payData.teamName,
      plan: payData.plan,
      price: payData.price,
      maxMembers: payData.members,
      credits: payData.credits,
      teamCode,
      adminUid: user.uid,
      adminEmail: userEmail,
      members: [{uid: user.uid, email: userEmail, joinedAt: new Date()}],
      paymentMethod: "card",
      status: "active",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    await db.collection("users").doc(user.uid).update({
      teamId: teamRef.id,
      teamRole: "admin"
    });
    await db.collection("teamPayments").doc(txRef).update({ status:"completed" });
    return res.json({ success:true, teamCode });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});

// ── CREATE TEAM TRANSFER ──
app.post("/api/create-team-transfer", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { teamName, plan, price, members, credits } = req.body;
    const userDoc = await db.collection("users").doc(user.uid).get();
    if(userDoc.data()?.teamId) return res.status(400).json({ error:"You already have a team. You cannot create another team." });
    const userEmail = userDoc.data()?.email || user.email || "";

    // Get live rate
    const rateRes = await axios.get("https://open.er-api.com/v6/latest/USD");
    const ngnRate = rateRes.data.rates.NGN || 1600;
    const ngnAmount = Math.ceil(price * ngnRate);
    const txRef = `VG-TEAM-TRF-user.uid.slice(0,8)-{Date.now()}`;
    // Create dedicated Paystack customer using team name
    const teamEmail = `team-${Date.now()}@audlabs.io`;
    const custRes = await axios.post(`${PAYSTACK_BASE}/customer`, {
      email: teamEmail,
      first_name: teamName,
      last_name: "Team",
      phone: "+2340000000000",
      metadata: { txRef, type:"team_payment", uid: user.uid }
    }, { headers: { Authorization:`Bearer ${process.env.PAYSTACK_SECRET}` }});
    const customerCode = custRes.data.data.customer_code;
    // Create dedicated virtual account for this team
    const vaRes = await axios.post(`${PAYSTACK_BASE}/dedicated_account`, {
      customer: customerCode,
      preferred_bank: "wema-bank",
    }, { headers: { Authorization:`Bearer ${process.env.PAYSTACK_SECRET}` }});
    const va = vaRes.data.data;
    // Save pending team payment
    await db.collection("teamPayments").doc(txRef).set({
      uid: user.uid,
      email: userEmail,
      teamEmail,
      customerCode,
      teamName, plan, price, members, credits,
      ngnAmount, status: "pending", paymentMethod: "transfer",
      accountNumber: va.account_number,
      bankName: va.bank.name,
      paystackCustomerId: va.customer.id,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    // Save account number mapping for webhook lookup
    await db.collection("teamAccountMap").doc(va.account_number).set({
      txRef, uid: user.uid, teamName, plan, price, members, credits,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({
      success: true,
      ngnAmount,
      accountNumber: va.account_number,
      bankName: va.bank.name,
      txRef
    });
  } catch(e) {
    console.error("Team transfer error:", e.response?.data || e.message);
    return res.status(500).json({ error:e.message });
  }
});

// ── CREATE TEAM CRYPTO ──
app.post("/api/create-team-crypto", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { teamName, plan, price, members, credits } = req.body;
    const userDoc = await db.collection("users").doc(user.uid).get();
    const userEmail = userDoc.data()?.email || user.email || "";
    const txRef = `VG-TEAM-CRYPTO-user.uid.slice(0,8)-{Date.now()}`;
    // Create NOWPayments payment
    const nowRes = await axios.post("https://api.nowpayments.io/v1/payment", {
      price_amount: price,
      price_currency: "usd",
      pay_currency: "usdttrc20",
      ipn_callback_url: `https://app.audlabs.io/api/team-crypto-webhook`,
      order_id: txRef,
      order_description: `AudLabs Team Plan — ${plan}`
    }, { headers: { "x-api-key": process.env.NOW_API_KEY } });
    // Save pending payment
    await db.collection("teamPayments").doc(txRef).set({
      uid: user.uid,
      email: userEmail,
      teamName, plan, price, members, credits,
      paymentId: nowRes.data.payment_id,
      status: "pending", paymentMethod: "crypto",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({
      success: true,
      payAmount: nowRes.data.pay_amount,
      payAddress: nowRes.data.pay_address,
      paymentId: nowRes.data.payment_id,
      txRef
    });
  } catch(e) { return res.status(500).json({ error:e.message }); }
});
// ── CHECK TEAM TRANSFER STATUS ──
app.get("/api/check-team-transfer", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { txRef } = req.query;
    if(!txRef) return res.status(400).json({ error:"Missing txRef" });
    const payDoc = await db.collection("teamPayments").doc(txRef).get();
    if(!payDoc.exists) return res.status(404).json({ error:"Payment not found" });
    const payData = payDoc.data();
    if(payData.status === "completed"){
      const teamSnap = await db.collection("teams").where("adminUid","==",user.uid).get();
      const teamCode = teamSnap.empty ? "" : teamSnap.docs[0].data().teamCode;
      return res.json({ teamCreated:true, teamCode });
    }
    return res.json({ teamCreated:false });
  } catch(e) {
    return res.status(500).json({ error:e.message });
  }
});
// ── CHECK TEAM CRYPTO STATUS ──
app.get("/api/check-team-crypto", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { paymentId, txRef } = req.query;
    if(!paymentId || !txRef) return res.status(400).json({ error:"Missing paymentId or txRef" });
    // Check if team was already created
    const payDoc = await db.collection("teamPayments").doc(txRef).get();
    if(payDoc.exists && payDoc.data().status === "completed"){
      const teamSnap = await db.collection("teams").where("adminUid","==",user.uid).get();
      const teamCode = teamSnap.empty ? "" : teamSnap.docs[0].data().teamCode;
      return res.json({ status:"finished", teamCreated:true, teamCode });
    }
    const nowRes = await axios.get(`https://api.nowpayments.io/v1/payment/${paymentId}`, {
      headers: { "x-api-key": process.env.NOW_API_KEY }
    });
    return res.json({ status: nowRes.data.payment_status });
  } catch(e) {
    console.error("Check team crypto error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── TEAM CRYPTO WEBHOOK ──
app.post("/api/team-crypto-webhook", express.json(), async (req,res) => {
  try {
    const { payment_id, payment_status, order_id } = req.body;
    if(payment_status !== "finished" && payment_status !== "confirmed") return res.json({ received:true });
    const txRef = order_id;
    const payDoc = await db.collection("teamPayments").doc(txRef).get();
    if(!payDoc.exists) return res.json({ received:true });
    const payData = payDoc.data();
    if(payData.status === "completed") return res.json({ received:true, duplicate:true });
    // Create the team
    const teamCode = "TEAM-" + Math.random().toString(36).substring(2,8).toUpperCase();
    const teamRef = await db.collection("teams").add({
      teamName: payData.teamName,
      plan: payData.plan,
      price: payData.price,
      maxMembers: payData.members,
      credits: payData.credits,
      teamCode,
      adminUid: payData.uid,
      adminEmail: payData.email,
      members: [{uid: payData.uid, email: payData.email, joinedAt: new Date()}],
      paymentMethod: "crypto",
      status: "active",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    await db.collection("users").doc(payData.uid).update({
      teamId: teamRef.id,
      teamRole: "admin"
    });
    await db.collection("teamPayments").doc(txRef).update({ status:"completed" });
    console.log("Team created via crypto:", teamCode);
    return res.json({ received:true });
  } catch(e) {
    console.error("Team crypto webhook error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── CREATE TEAM ──
app.post("/api/create-team", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { teamName, plan, price, members, credits, paymentMethod } = req.body;
    if(!teamName || !plan) return res.status(400).json({ error:"Team name and plan required" });
    // Check if user already has a team
    const existingTeam = await db.collection("teams").where("adminUid","==",user.uid).get();
    if(!existingTeam.empty) return res.status(400).json({ error:"You already have a team. You can only create one team." });
    // Generate unique team code
    const teamCode = "TEAM-" + Math.random().toString(36).substring(2,8).toUpperCase();
    // Get user email
    const userDoc = await db.collection("users").doc(user.uid).get();
    const userEmail = userDoc.data()?.email || user.email || "";
    // Create team
    const teamRef = await db.collection("teams").add({
      teamName,
      plan,
      price,
      maxMembers: members,
      credits: credits === -1 ? -1 : credits,
      teamCode,
      adminUid: user.uid,
      adminEmail: userEmail,
      members: [{uid: user.uid, email: userEmail, joinedAt: new Date()}],
      paymentMethod,
      status: "active",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    // Add team to user document
    await db.collection("users").doc(user.uid).update({
      teamId: teamRef.id,
      teamRole: "admin"
    });
    console.log("Team created:", teamCode, "by", userEmail);
    return res.json({ success:true, teamCode, teamId:teamRef.id });
  } catch(e) {
    console.error("Create team error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});

// ── JOIN TEAM ──
app.post("/api/join-team", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { teamCode } = req.body;
    if(!teamCode) return res.status(400).json({ error:"Team code required" });
    // Find team
    const teamSnap = await db.collection("teams").where("teamCode","==",teamCode).get();
    if(teamSnap.empty) return res.status(404).json({ error:"Team not found. Please check the code and try again." });
    const teamDoc = teamSnap.docs[0];
    const team = teamDoc.data();
    // Check if team is full
    if(team.members.length >= team.maxMembers) return res.status(400).json({ error:"This team is full. Ask the admin to upgrade the plan." });
    // Check if user already in team
    const alreadyMember = team.members.some(function(m){ return m.uid === user.uid; });
    if(alreadyMember) return res.status(400).json({ error:"You are already a member of this team." });
    // Get user email
    const userDoc = await db.collection("users").doc(user.uid).get();
    const userEmail = userDoc.data()?.email || user.email || "";
    // Add user to team
    await db.collection("teams").doc(teamDoc.id).update({
      members: admin.firestore.FieldValue.arrayUnion({uid: user.uid, email: userEmail, joinedAt: new Date()})
    });
    // Add team to user document
    await db.collection("users").doc(user.uid).update({
      teamId: teamDoc.id,
      teamRole: "member"
    });
    console.log("User joined team:", teamCode, userEmail);
    return res.json({ success:true, teamName:team.teamName });
  } catch(e) {
    console.error("Join team error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});

// ── TEAM INFO ──
app.get("/api/team-info", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const userDoc = await db.collection("users").doc(user.uid).get();
    const teamId = userDoc.data()?.teamId;
    if(!teamId) return res.json({ success:false, team:null });
    const teamDoc = await db.collection("teams").doc(teamId).get();
    if(!teamDoc.exists) return res.json({ success:false, team:null });
    return res.json({ success:true, team:{ id:teamDoc.id, ...teamDoc.data() } });
  } catch(e) {
    return res.status(500).json({ error:e.message });
  }
});

// ── REMOVE MEMBER ──
app.post("/api/remove-member", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { memberUid } = req.body;
    if(!memberUid) return res.status(400).json({ error:"Member UID required" });
    // Get admin team
    const teamSnap = await db.collection("teams").where("adminUid","==",user.uid).get();
    if(teamSnap.empty) return res.status(400).json({ error:"You are not a team admin." });
    const teamDoc = teamSnap.docs[0];
    const team = teamDoc.data();
    // Remove member
    const updatedMembers = team.members.filter(function(m){ return m.uid !== memberUid; });
    await db.collection("teams").doc(teamDoc.id).update({ members: updatedMembers });
    // Remove team from member's user document
    await db.collection("users").doc(memberUid).update({
      teamId: admin.firestore.FieldValue.delete(),
      teamRole: admin.firestore.FieldValue.delete()
    });
    return res.json({ success:true });
  } catch(e) {
    return res.status(500).json({ error:e.message });
  }
});
// ── SEARCH VIDEOS ──
app.post("/api/search-videos", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { query, filters } = req.body;
    if(!query) return res.status(400).json({ error:"Query required" });
    const orientation = filters?.orientation || "landscape";
    const duration = filters?.duration || "any";
    const resolution = filters?.resolution || "hd";
    const params = { query, per_page: 12, orientation };
    if(duration === "vshort"){ params.min_duration = 1; params.max_duration = 5; }
else if(duration === "short"){ params.min_duration = 5; params.max_duration = 10; }
else if(duration === "medium"){ params.min_duration = 10; params.max_duration = 20; }
else if(duration === "long"){ params.min_duration = 20; }
    const pexelsRes = await axios.get("https://api.pexels.com/videos/search", {
      headers: { Authorization: process.env.PEXELS_API_KEY },
      params
    });
    const videos = (pexelsRes.data.videos||[]).map(function(v){
      let file;
      if(resolution === "4k"){
        file = v.video_files.find(function(f){ return f.width >= 3840; }) ||
               v.video_files.find(function(f){ return f.quality === "hd"; }) ||
               v.video_files[0];
      } else {
        file = v.video_files.find(function(f){ return f.quality === "hd"; }) || v.video_files[0];
      }
      return {
        url: file.link,
        downloadUrl: file.link,
        photographer: v.user.name,
        duration: v.duration,
        width: file.width || v.width,
        height: file.height || v.height,
        quality: file.quality,
        image: v.image
      };
    });
    return res.json({ success:true, videos });
  } catch(e){
    console.error("Search videos error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── GENERATE SCRIPT ──
app.post("/api/generate-script", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { topic, type, tone, audience, duration } = req.body;
    if(!topic) return res.status(400).json({ error:"Topic required" });
    const wordCounts = { "1": 150, "3": 450, "5": 750, "10": 1500 };
    const targetWords = wordCounts[duration] || 150;
    const typeLabels = {
      youtube: "YouTube video script",
      podcast: "podcast script",
      documentary: "documentary narration script",
      ad: "advertisement script",
      explainer: "explainer video script",
      storytime: "storytime narration",
      news: "news report script",
      motivational: "motivational speech script"
    };
    const toneLabels = {
      professional: "professional and authoritative",
      casual: "casual, warm and friendly",
      energetic: "energetic and exciting",
      storytelling: "narrative storytelling style",
      dramatic: "dramatic and cinematic",
      educational: "clear and educational",
      humorous: "humorous and entertaining",
      inspirational: "inspirational and uplifting"
    };
    const prompt = `You are a professional scriptwriter. Write a typeLabels[type]||"videoscript"about"{topic}".

Requirements:
- Tone: ${toneLabels[tone]||"professional"}
- Target audience: ${audience || "general audience"}
- Approximate length: ${targetWords} words (for a ${duration} minute video)
- Write ONLY the narration/voiceover text — no stage directions, no [brackets], no scene descriptions
- Write in a natural speaking style that flows well when read aloud
- Start with a strong hook that grabs attention immediately
- End with a clear call to action
- Do not include any headers, labels or formatting — just the pure script text

Write the complete script now:`;

    const claudeRes = await axios.post("https://api.anthropic.com/v1/messages", {
      model: "claude-haiku-4-5-20251001",
      max_tokens: 2000,
      messages: [{ role: "user", content: prompt }]
    }, {
      headers: {
        "x-api-key": process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json"
      }
    });
    const script = claudeRes.data.content[0].text.trim();
    return res.json({ success:true, script });
  } catch(e) {
    console.error("Generate script error:", e.response?.data || e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── SCRIPT TO VIDEOS ──
app.post("/api/script-to-videos", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { script, filters, niche } = req.body;
    if(!script) return res.status(400).json({ error:"Script required" });
    const orientation = filters?.orientation || "landscape";
    const resolution = filters?.resolution || "hd";
    const duration = filters?.duration || "any";
    // Split script into paragraphs
    const paragraphs = script.split(/\n+/).filter(function(p){ return p.trim().length > 30; });
    const sections = paragraphs.slice(0, 8);
    const results = [];
    for(const section of sections){
      // Use Claude AI to extract precise video search keywords
      let keywords = [];
      try {
        const claudeRes = await axios.post("https://api.anthropic.com/v1/messages", {
          model: "claude-haiku-4-5-20251001",
          max_tokens: 150,
          messages: [{
            role: "user",
            content: `You are a professional video editor${niche ? " specializing in "+niche+" content" : ""}. Extract 3 precise visual search keywords for finding cinematic stock footage that perfectly matches this script paragraph. Return ONLY a JSON array of 3 short 1-3 word search terms, nothing else. Example: ["aerial city night", "ocean waves crashing", "crowd cheering stadium"]\n\nParagraph: "${section.slice(0,300)}"`
          }]
        }, {
          headers: {
            "x-api-key": process.env.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "messages-2023-06-01",
            "Content-Type": "application/json"
          }
        });
        const responseText = claudeRes.data.content[0].text.trim();
        keywords = JSON.parse(responseText);
      } catch(aiErr){
        console.warn("Claude keyword extraction failed:", aiErr.message);
        // Fallback to simple extraction
        const words = section.toLowerCase().replace(/[^a-z\s]/g,"").split(/\s+/).filter(function(w){ return w.length > 4; });
        const freq = {};
        words.forEach(function(w){ freq[w]=(freq[w]||0)+1; });
        keywords = Object.keys(freq).sort(function(a,b){ return freq[b]-freq[a]; }).slice(0,3);
        if(keywords.length === 0) keywords = ["nature"];
      }
      // Search Pexels for matching videos
      const searchQuery = keywords[0] || "nature";
      try {
        const params = {
          query: searchQuery,
          per_page: 10,
          orientation: orientation
        };
        // Add duration filter
        if(duration === "short") { params.min_duration = 5; params.max_duration = 10; }
        else if(duration === "medium") { params.min_duration = 10; params.max_duration = 20; }
        else if(duration === "long") { params.min_duration = 20; }
        const pexelsRes = await axios.get("https://api.pexels.com/videos/search", {
          headers: { Authorization: process.env.PEXELS_API_KEY },
          params
        });
        let videos = (pexelsRes.data.videos||[]).map(function(v){
          // Select file based on resolution preference
          let file;
          if(resolution === "4k"){
            file = v.video_files.find(function(f){ return f.width >= 3840; }) ||
                   v.video_files.find(function(f){ return f.quality === "uhd"; }) ||
                   v.video_files.find(function(f){ return f.quality === "hd"; }) ||
                   v.video_files[0];
          } else {
            file = v.video_files.find(function(f){ return f.quality === "hd"; }) ||
                   v.video_files[0];
          }
          return {
            url: file.link,
            downloadUrl: file.link,
            photographer: v.user.name,
            duration: v.duration,
            width: file.width || v.width,
            height: file.height || v.height,
            image: v.image,
            quality: file.quality
          };
        });
        results.push({ text: section.slice(0, 200), keywords, videos });
      } catch(pexErr){
        console.warn("Pexels search failed for:", searchQuery, pexErr.message);
        results.push({ text: section.slice(0, 200), keywords, videos: [] });
      }
    }
    return res.json({ success:true, sections:results });
  } catch(e) {
    console.error("Script to videos error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});

// ── DELETE CLONED VOICE ──
app.post("/api/delete-cloned-voice", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { voiceId } = req.body;
    if(!voiceId) return res.status(400).json({ error:"Voice ID required" });
    // Get cloned voice data from Firestore
    const clonedSnap = await db.collection("users").doc(user.uid).collection("clonedVoices").where("voiceId","==",voiceId).limit(1).get();
    if(clonedSnap.empty) return res.status(404).json({ error:"Voice not found" });
    const clonedData = clonedSnap.docs[0].data();
    // Delete from Kokoro server if it's a Kokoro clone
    if(clonedData.provider === "kokoro" && process.env.KOKORO_TTS_URL){
      try {
        await axios.post(
          process.env.KOKORO_TTS_URL + "/delete-clone",
          { voiceId: voiceId },
          { headers: { "x-api-key": process.env.KOKORO_TTS_KEY, "Content-Type": "application/json" }, timeout: 10000 }
        );
        console.log("Deleted Kokoro clone:", voiceId);
      } catch(kokoroDelErr){
        console.warn("Kokoro delete failed (non-blocking):", kokoroDelErr.message);
      }
    } else {
      // Delete from MiniMax accounts
      const allApiKeys = {
        1: process.env.MINIMAX_API_KEY,
        2: process.env.MINIMAX_API_KEY_2 || process.env.MINIMAX_API_KEY,
        3: process.env.MINIMAX_API_KEY_3 || process.env.MINIMAX_API_KEY,
        4: process.env.MINIMAX_API_KEY_4 || process.env.MINIMAX_API_KEY
      };
      for(const accNum of [1,2,3,4]){
        try {
          await axios.post(`https://api.minimax.io/v1/delete_voice`, {
            voice_type: "voice_cloning",
            voice_id: voiceId
          }, {
            headers: { Authorization:`Bearer ${allApiKeys[accNum]}`, "Content-Type":"application/json" }
          });
          console.log("Deleted MiniMax voice from Account", accNum);
        } catch(delErr){
          console.warn("MiniMax delete failed on Account", accNum, ":", delErr.message);
        }
      }
    }
    // Delete from Firestore
    await db.collection("users").doc(user.uid).collection("clonedVoices").doc(clonedSnap.docs[0].id).delete();
    return res.json({ success:true });
  } catch(e){
    console.error("Delete cloned voice error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});

// ── ADMIN ADD CREDITS ──
app.post("/api/admin-add-credits", async (req,res) => {
  const adminPassword = req.headers["x-admin-password"] || "";
  if(adminPassword !== "(Oluwaseyi23)") return res.status(401).json({ error:"Unauthorized" });
  try {
    const { uid, credits } = req.body;
    if(!uid || !credits) return res.status(400).json({ error:"UID and credits required" });
    await db.collection("users").doc(uid).update({
      credits: admin.firestore.FieldValue.increment(parseInt(credits))
    });
    await db.collection("users").doc(uid).collection("transactions").add({
      type:"credit", amount:parseInt(credits),
      note:"Admin credit — "+parseInt(credits).toLocaleString()+" credits added",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ success:true });
  } catch(e){ return res.status(500).json({ error:e.message }); }
});

// ── ADMIN DEDUCT CREDITS ──
app.post("/api/admin-deduct-credits", async (req,res) => {
  const adminPassword = req.headers["x-admin-password"] || "";
  if(adminPassword !== "(Oluwaseyi23)") return res.status(401).json({ error:"Unauthorized" });
  try {
    const { uid, credits } = req.body;
    if(!uid || !credits) return res.status(400).json({ error:"UID and credits required" });
    await db.collection("users").doc(uid).update({
      credits: admin.firestore.FieldValue.increment(-parseInt(credits))
    });
    await db.collection("users").doc(uid).collection("transactions").add({
      type:"debit", amount:parseInt(credits),
      note:"Admin deduction — "+parseInt(credits).toLocaleString()+" credits removed",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ success:true });
  } catch(e){ return res.status(500).json({ error:e.message }); }
});

// ── ADMIN REVENUE CHART ──
app.get("/api/admin-revenue-chart", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const period = req.query.period || "7d";
    const statsDoc = await db.collection("stats").doc("revenue").get();
    const daily = statsDoc.exists ? (statsDoc.data().daily || {}) : {};
    const now = new Date();
    let days = period === "7d" ? 7 : period === "30d" ? 30 : 60;
    let labels = [];
    let values = [];
    for(let i = days-1; i >= 0; i--){
      var d = new Date(now);
      d.setDate(d.getDate() - i);
      var key = d.toISOString().split("T")[0];
      labels.push(key.slice(5));
      values.push(parseFloat((daily[key]||0).toFixed(2)));
    }
    return res.json({ success:true, labels, values });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── TRACK ONLINE USERS ──
app.post("/api/ping", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    await db.collection("onlineUsers").doc(user.uid).set({
      uid: user.uid,
      lastSeen: admin.firestore.FieldValue.serverTimestamp()
    }, {merge:true});
    return res.json({ success:true });
  } catch(e){ return res.json({ success:true }); }
});

// ── GET ONLINE USERS COUNT ──
app.get("/api/online-count", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    const snap = await db.collection("onlineUsers")
      .where("lastSeen", ">=", admin.firestore.Timestamp.fromDate(fiveMinutesAgo))
      .get();
    return res.json({ success:true, count: snap.size });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});


var minimaxQuotaCache = null;
var minimaxQuotaCacheTime = 0;

// ── MINIMAX QUOTA TRACKER ──
app.get("/api/minimax-quota", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  // Return cached result if less than 3 minutes old
  if(minimaxQuotaCache && (Date.now() - minimaxQuotaCacheTime) < 180000){
    return res.json(minimaxQuotaCache);
  }
  try {
    const accounts = [
      { name: "Account 1", email: "Demolaadyemo0@gmail.com", key: process.env.MINIMAX_API_KEY },
      { name: "Account 2", email: "Qivotec@gmail.com", key: process.env.MINIMAX_API_KEY_2 },
      { name: "Account 3", email: "Hiaudlabs@gmail.com", key: process.env.MINIMAX_API_KEY_3 },
      { name: "Account 4", email: "Demolaadeyemo1@gmail.com", key: process.env.MINIMAX_API_KEY_4 },
      { name: "Account 5", email: "Demolaadeyemo2@gmail.com", key: process.env.MINIMAX_API_KEY_5 },
      { name: "Account 6", email: "audlabsapi6@gmail.com", key: process.env.MINIMAX_API_KEY_7 },
      { name: "Account 7", email: "audlabsapi7@gmail.com", key: process.env.MINIMAX_API_KEY_6 },
      { name: "Account 8", email: "Demolaadeyemo3@gmail.com", key: process.env.MINIMAX_API_KEY_8 },
      { name: "Account 9", email: "audlabsapi9@gmail.com", key: process.env.MINIMAX_API_KEY_9 },
      { name: "Account 10", email: "audlabsapi10@gmail.com", key: process.env.MINIMAX_API_KEY_10 }
    ];



    const results = [];
    for(const acc of accounts){
      if(!acc.key) continue;
      try {
        const testRes = await axios.post(
          "https://api.minimax.io/v1/t2a_v2",
          {
            model: "speech-2.8-hd",
            text: "test",
            stream: false,
            voice_setting: { voice_id: "English_CaptivatingStoryteller", speed: 1.0, vol: 1.0, pitch: 0 },
            audio_setting: { sample_rate: 32000, bitrate: 128000, format: "mp3", channel: 1 },
            output_format: "hex"
          },
          { headers: { Authorization: `Bearer ${acc.key}`, "Content-Type": "application/json" }, timeout: 4000 }
        );
        const statusCode = testRes.data?.base_resp?.status_code;
        const statusMsg = testRes.data?.base_resp?.status_msg || "";
        console.log("QUOTA CHECK — "+acc.name+" ("+acc.email+"): status_code="+statusCode+" status_msg=\""+statusMsg+"\" has_audio="+!!testRes.data?.data?.audio);
        const isLimited = statusCode === 1002 || statusCode === 2056 || statusMsg.includes("limit") || statusMsg.includes("quota");
        results.push({
          name: acc.name,
          email: acc.email,
          status: isLimited ? "limited" : "active"
        });

      } catch(e){
        console.log("QUOTA CHECK ERROR — "+acc.name+" ("+acc.email+"): "+(e.response?.status)+" — "+(e.response?.data ? JSON.stringify(e.response.data) : e.message));
        results.push({
          name: acc.name,
          email: acc.email,
          status: e.response?.status === 429 ? "limited" : "error",
          statusMsg: e.message
        });
      }
    }

    var result = { success:true, accounts: results };
    minimaxQuotaCache = result;
    minimaxQuotaCacheTime = Date.now();
    return res.json(result);

  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});



// ── ADMIN TEAMS ──
app.get("/api/admin-teams", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const snap = await db.collection("teams").orderBy("createdAt","desc").get();
    const teams = snap.docs.map(function(d){ return { id:d.id, ...d.data() }; });
    return res.json({ success:true, teams });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── CLEAN HASPURCHASED ──
app.post("/api/clean-haspurchased", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const cardSnap = await db.collection("cardPayments").where("status","==","completed").get();
    const cryptoSnap = await db.collection("cryptoPayments").where("status","==","completed").get();
    const paidUids = new Set();
    cardSnap.docs.forEach(function(d){ if(d.data().uid) paidUids.add(d.data().uid); });
    cryptoSnap.docs.forEach(function(d){ if(d.data().uid) paidUids.add(d.data().uid); });
    // Scan user transactions for Paystack bank transfer payments
    const usersSnap = await db.collection("users").get();
    for(const doc of usersSnap.docs){
      const txSnap = await db.collection("users").doc(doc.id)
        .collection("transactions").where("type","==","credit").limit(10).get();
      for(const tx of txSnap.docs){
        const note = (tx.data().note||"").toLowerCase();
        if(note.includes("top-up") || note.includes("card top-up")){
          paidUids.add(doc.id);
          break;
        }
      }
    }
    console.log("Total paid UIDs found:", paidUids.size);
    // Set hasPurchased correctly for all users
    let fixed = 0;
    let cleaned = 0;
    for(const doc of usersSnap.docs){
      const hasPurchased = doc.data().hasPurchased || false;
      const shouldHave = paidUids.has(doc.id);
      if(shouldHave && !hasPurchased){
        await db.collection("users").doc(doc.id).update({ hasPurchased: true });
        fixed++;
      } else if(!shouldHave && hasPurchased){
        await db.collection("users").doc(doc.id).update({ hasPurchased: false });
        cleaned++;
      }
    }
    return res.json({ success:true, fixed, cleaned, totalPaid: paidUids.size });
  } catch(e){
    console.error("Clean error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});



// ── FIX HASPURCHASED ──
app.post("/api/fix-haspurchased", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    // Get all card payments
    const cardSnap = await db.collection("cardPayments").where("status","==","completed").get();
    const cryptoSnap = await db.collection("cryptoPayments").where("status","==","completed").get();
    
    // Collect all UIDs that have paid
    const paidUids = new Set();
    cardSnap.docs.forEach(function(d){ if(d.data().uid) paidUids.add(d.data().uid); });
    cryptoSnap.docs.forEach(function(d){ if(d.data().uid) paidUids.add(d.data().uid); });
    
    // Also check Paystack payments from transactions
    const usersSnap = await db.collection("users").get();
    let fixed = 0;
    for(const doc of usersSnap.docs){
      if(paidUids.has(doc.id) && !doc.data().hasPurchased){
        await db.collection("users").doc(doc.id).update({ hasPurchased: true });
        fixed++;
        console.log("Fixed:", doc.data().email);
      }
    }
    return res.json({ success:true, fixed: fixed });
  } catch(e){
    console.error("Fix error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});



// ── EXTRACT TRANSCRIPT ──
app.post("/api/extract-transcript", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    const { url } = req.body;
    if(!url) return res.status(400).json({ error:"URL required" });
    const videoIdMatch = url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})/);
    if(!videoIdMatch) return res.status(400).json({ error:"Invalid YouTube URL. Please paste a valid YouTube video link." });
    const videoId = videoIdMatch[1];
    const transcriptRes = await axios.get(
      `https://youtube-transcript.ai/transcript/${videoId}.txt?lang=en&format=text`,
      { timeout: 30000, headers: { 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/plain",
        "Cache-Control": "no-cache"
      }}
    );

        if(!transcriptRes.data) return res.status(404).json({ error:"No transcript found for this video." });
    let fullText = transcriptRes.data
      .replace(/&gt;/g, ">")
      .replace(/&lt;/g, "<")
      .replace(/&amp;/g, "&")
      .replace(/&#39;/g, "'")
      .replace(/&quot;/g, '"');
    let title = "Video Transcript";
    const titleMatch = fullText.match(/^# Transcript: (.+)$/m);
    if(titleMatch) title = titleMatch[1].trim();
    // Remove everything before ## Transcript section
    const sectionStart = fullText.indexOf("## Transcript");
    if(sectionStart > -1) fullText = fullText.slice(sectionStart + 13).trim();
    // Remove footer
    const footerIdx = fullText.indexOf("---");
    if(footerIdx > -1) fullText = fullText.slice(0, footerIdx).trim();
        // Process each timestamp block
    const blocks = fullText.split(/\n\n+/);
    const rawParts = [];
    for(const block of blocks){
      const text = block.replace(/^\[\d+:\d+\]\s*/gm, "").replace(/\n/g, " ").trim();
      if(text) rawParts.push(text);
    }
    let joined = rawParts.join(" ").replace(/\s+/g, " ").trim();
    // Word-level deduplication for rolling-caption overlap (e.g. "I am the" "am the dumbest" "the dumbest trader")
    const words = joined.split(" ");
    const dedupedWords = [];
    for(let i = 0; i < words.length; i++){
      // Check if the upcoming sequence of words (up to 12) repeats immediately after itself
            let repeatLen = 0;
      const maxCheck = Math.min(12, Math.floor((words.length - i) / 2));
      const normalize = function(s){ return s.toLowerCase().replace(/[.,!?;:]/g, ""); };
            for(let len = maxCheck; len >= 1; len--){
        const seq1 = normalize(words.slice(i, i + len).join(" "));
        const seq2 = normalize(words.slice(i + len, i + len * 2).join(" "));
        if(seq1 === seq2 && seq1.length > 0){
          repeatLen = len;
          break;
        }
      }
      if(repeatLen > 0){
        // Skip ahead past the duplicate occurrence(s), keep only one copy
        dedupedWords.push.apply(dedupedWords, words.slice(i, i + repeatLen));
        let j = i + repeatLen;
        while(j + repeatLen <= words.length && words.slice(j, j + repeatLen).join(" ").toLowerCase() === words.slice(i, i + repeatLen).join(" ").toLowerCase()){
          j += repeatLen;
        }
        i = j - 1;
      } else {
        dedupedWords.push(words[i]);
      }
    }
    fullText = dedupedWords.join(" ").replace(/\s+/g, " ").trim();


    return res.json({ success:true, transcript: fullText, title, videoId });
  } catch(e){
    console.error("Transcript error:", e.message);
    if(e.response?.status === 404){
      return res.status(404).json({ error:"No transcript found for this video. The video may not have captions available." });
    }
    return res.status(500).json({ error:"Failed to extract transcript. Please check the URL and try again." });
  }
});





// ── TRANSCRIPT PDF ──
app.post("/api/transcript-pdf", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    const { text, title } = req.body;
    if(!text) return res.status(400).json({ error:"Text required" });
    const PDFDocument = require("pdfkit");
    const chunks = [];
    const doc = new PDFDocument({ margin: 50, bufferPages: true });
    doc.on("data", function(chunk){ chunks.push(chunk); });
    doc.on("end", function(){
      const pdfBuffer = Buffer.concat(chunks);
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="transcript.pdf"`);
      res.setHeader("Content-Length", pdfBuffer.length);
      res.send(pdfBuffer);
    });
    doc.fontSize(18).font("Helvetica-Bold").text(title || "Video Transcript", { align: "center" });
    doc.moveDown();
    doc.fontSize(11).font("Helvetica").text(text, { align: "left", lineGap: 4 });
    doc.end();
  } catch(e){
    console.error("PDF error:", e.message);
    return res.status(500).json({ error:"PDF generation failed." });
  }
});


// ── CONTACT FORM ──
app.post("/api/contact-form", async (req,res) => {
  try {
    const { name, email, message } = req.body;
    if(!name || !email || !message) return res.status(400).json({ error:"All fields are required" });
    const ticketId = "AUD-" + Date.now().toString().slice(-8);
    try {
      await db.collection("supportTickets").doc(ticketId).set({
        ticketId: ticketId,
        name: name,
        email: email,
        status: "open",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        messages: [
          { from: "user", body: message, timestamp: new Date().toISOString() }
        ]
      });
    } catch(ticketSaveErr){ console.warn("Ticket save failed:", ticketSaveErr.message); }
    await audlabsTransporter.sendMail({
      from: 'AudLabs Contact Form <hello@audlabs.io>',
      to: 'demolaadeyemo0@gmail.com',
      replyTo: email,
      subject: `[${ticketId}] New contact form message from ${name}`,
      html: `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
<tr><td style="background:#0a1628;padding:24px 32px;text-align:left;">
<span style="font-size:22px;font-weight:700;color:#c9a84c;letter-spacing:1px;">AudLabs</span>
<span style="font-size:12px;color:rgba(255,255,255,0.5);margin-left:8px;">Contact Form</span>
</td></tr>
<tr><td style="padding:32px;">
<div style="background:#f8f9fa;border-left:4px solid #c9a84c;border-radius:4px;padding:16px 20px;margin-bottom:20px;">
<div style="font-size:13px;color:#888;margin-bottom:4px;">Ticket ID</div>
<div style="font-size:15px;font-weight:700;color:#c9a84c;font-family:'Courier New',monospace;">${ticketId}</div>
</div>
<div style="background:#f8f9fa;border-left:4px solid #c9a84c;border-radius:4px;padding:16px 20px;margin-bottom:20px;">
<div style="font-size:13px;color:#888;margin-bottom:4px;">From</div>
<div style="font-size:15px;font-weight:700;color:#1a1a1a;">${name} — ${email}</div>
</div>
<div style="font-size:14px;color:#333;line-height:1.7;white-space:pre-wrap;">${message.replace(/</g,"&lt;")}</div>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
    });
    try {
      await audlabsTransporter.sendMail({
        from: '"AudLabs Support" <hello@audlabs.io>',
        to: email,
        subject: `We've received your message [Ticket ${ticketId}]`,
        html: `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
<tr><td style="background:#0a1628;padding:24px 32px;text-align:left;">
<span style="font-size:22px;font-weight:700;color:#c9a84c;letter-spacing:1px;">AudLabs</span>
<span style="font-size:12px;color:rgba(255,255,255,0.5);margin-left:8px;">Support</span>
</td></tr>
<tr><td style="padding:32px;">
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 16px;">Hi ${name.split(" ")[0]},</p>
<p style="font-size:14px;color:#555;line-height:1.8;margin:0 0 16px;">Thanks for reaching out. We've received your message and a member of our team will get back to you as soon as possible.</p>
<div style="background:#fffdf7;border:1.5px solid #f0e5c0;border-radius:8px;padding:16px 20px;margin-bottom:20px;">
<div style="font-size:12px;color:#888;margin-bottom:4px;">Your Ticket ID</div>
<div style="font-size:18px;font-weight:700;color:#c9a84c;font-family:'Courier New',monospace;">${ticketId}</div>
</div>
<p style="font-size:14px;color:#555;line-height:1.8;margin:0 0 16px;">Please keep this ticket ID for reference. If you need to follow up on this message, simply reply to this email.</p>
<p style="font-size:14px;color:#555;line-height:1.7;margin:0 0 4px;">Regards,</p>
<p style="font-size:15px;color:#333;margin:0;"><strong>The AudLabs Team</strong></p>
</td></tr>
<tr><td style="padding:0 32px 24px;">
<table cellpadding="0" cellspacing="0"><tr>
<td style="padding-right:12px;"><a href="https://x.com/AudLabs"><img src="https://audlabs.io/x-icon.jpg" width="24" height="24" alt="X" style="display:block;border-radius:6px;"></a></td>
<td style="padding-right:12px;"><a href="https://t.me/audlabs"><img src="https://audlabs.io/telegram-icon.jpg" width="24" height="24" alt="Telegram" style="display:block;border-radius:6px;"></a></td>
<td><a href="https://youtube.com/@AudLabs"><img src="https://audlabs.io/youtube-icon.jpg" width="24" height="24" alt="YouTube" style="display:block;border-radius:6px;"></a></td>
</tr></table>
</td></tr>
<tr><td style="background:#f8f9fa;padding:16px 32px;border-top:1px solid #eee;">
<p style="font-size:11px;color:#bbb;margin:0;text-align:center;">AudLabs · audlabs.io</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
      });
    } catch(autoReplyErr){ console.warn("Auto-reply failed:", autoReplyErr.message); }
        return res.json({ success:true, ticketId: ticketId });
  } catch(e){
    console.error("Contact form error:", e.message);
    return res.status(500).json({ error:"Failed to send message. Please try again." });
  }
});
// ── ADMIN: LIST SUPPORT TICKETS ──
app.get("/api/admin/tickets-list", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const snap = await db.collection("supportTickets").orderBy("updatedAt","desc").limit(100).get();
    const tickets = snap.docs.map(function(d){
      const data = d.data();
      return {
        ticketId: data.ticketId,
        name: data.name,
        email: data.email,
        status: data.status || "open",
        messages: data.messages || [],
        createdAt: data.createdAt ? new Date(data.createdAt._seconds*1000).toISOString() : null,
        updatedAt: data.updatedAt ? new Date(data.updatedAt._seconds*1000).toISOString() : null
      };
    });
    return res.json({ success:true, tickets: tickets });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});
// ── ADMIN: REPLY TO SUPPORT TICKET ──
app.post("/api/admin/reply-ticket", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const { ticketId, replyBody, markResolved } = req.body;
    if(!ticketId || !replyBody) return res.status(400).json({ error:"ticketId and replyBody are required" });
    const ticketDoc = await db.collection("supportTickets").doc(ticketId).get();
    if(!ticketDoc.exists) return res.status(404).json({ error:"Ticket not found" });
    const ticket = ticketDoc.data();
    await audlabsTransporter.sendMail({
      from: '"AudLabs Support" <hello@audlabs.io>',
      to: ticket.email,
      subject: `Re: Your AudLabs support request [Ticket ${ticketId}]`,
      html: `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
<tr><td style="background:#0a1628;padding:24px 32px;text-align:left;">
<span style="font-size:22px;font-weight:700;color:#c9a84c;letter-spacing:1px;">AudLabs</span>
<span style="font-size:12px;color:rgba(255,255,255,0.5);margin-left:8px;">Support</span>
</td></tr>
<tr><td style="padding:32px;">
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 16px;">Hi ${ticket.name.split(" ")[0]},</p>
<div style="font-size:14px;color:#333;line-height:1.8;white-space:pre-wrap;margin:0 0 24px;">${replyBody.replace(/</g,"&lt;")}</div>
<div style="background:#fffdf7;border:1.5px solid #f0e5c0;border-radius:8px;padding:14px 18px;margin-bottom:20px;">
<div style="font-size:11px;color:#888;margin-bottom:2px;">Ticket ID</div>
<div style="font-size:14px;font-weight:700;color:#c9a84c;font-family:'Courier New',monospace;">${ticketId}</div>
</div>
<p style="font-size:13px;color:#888;line-height:1.7;margin:0;">If you need further help, just reply to this email.</p>
</td></tr>
<tr><td style="background:#f8f9fa;padding:16px 32px;border-top:1px solid #eee;">
<p style="font-size:11px;color:#bbb;margin:0;text-align:center;">AudLabs · audlabs.io</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
    });
    const updatedMessages = (ticket.messages || []).concat([{ from: "admin", body: replyBody, timestamp: new Date().toISOString() }]);
    await db.collection("supportTickets").doc(ticketId).update({
      messages: updatedMessages,
      status: markResolved ? "resolved" : "open",
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ success:true });
  } catch(e){
    console.error("Reply ticket error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});

// ── SEND NOTIFICATION ──
app.post("/api/send-notification", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const { title, message, targetUid } = req.body;
    if(!title || !message) return res.status(400).json({ error:"Title and message required" });
    if(targetUid){
      // Send to specific user
      await db.collection("notifications").add({
        title, message, targetUid,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        global: false
      });
      // Send email to user
      try {
        const userDoc = await db.collection("users").doc(targetUid).get();
        if(userDoc.exists){
          const userData = userDoc.data();
          const firstName = userData.displayName ? userData.displayName.split(" ")[0] : userData.email.split("@")[0];
          await sesTransporter.sendMail({
            from: 'Adeyemo from AudLabs <hello@audlabs.io>',
            to: userData.email,
            subject: title,
            html: `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
<tr><td style="background:#0a1628;padding:24px 32px;text-align:left;">
<span style="font-size:22px;font-weight:700;color:#c9a84c;letter-spacing:1px;">AudLabs</span>
<span style="font-size:12px;color:rgba(255,255,255,0.5);margin-left:8px;">Account Notice</span>
</td></tr>
<tr><td style="padding:32px;">
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 16px;">Hi ${firstName},</p>
<div style="background:#f8f9fa;border-left:4px solid #c9a84c;border-radius:4px;padding:16px 20px;margin-bottom:24px;">
<div style="font-size:14px;font-weight:700;color:#1a1a1a;margin-bottom:8px;">${title}</div>
<div style="font-size:14px;color:#555;line-height:1.7;">${message}</div>
</div>
<p style="font-size:13px;color:#888;line-height:1.7;margin:0 0 8px;">If you have any questions just reply to this email.</p>
<p style="font-size:15px;color:#333;margin:0;">Regards,<br><strong>Adeyemo Oluwaseyi</strong><br><span style="font-size:13px;color:#888;">Founder, AudLabs</span></p>
</td></tr>
<tr><td style="background:#f8f9fa;padding:16px 32px;border-top:1px solid #eee;">
<p style="font-size:11px;color:#bbb;margin:0;text-align:center;">You are receiving this because you have an account at audlabs.io.</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
          });
          console.log("Notification email sent to:", userData.email);
        }
      } catch(emailErr){ console.warn("Notification email failed:", emailErr.message); }
    } else {
      // Send to all users
      await db.collection("notifications").add({
        title, message,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        global: true
      });
    }
    return res.json({ success:true });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── GET NOTIFICATIONS ──
app.get("/api/notifications", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    // Get global notifications and user-specific ones
    const globalSnap = await db.collection("notifications")
      .where("global","==",true)
      .limit(20).get();
    const userSnap = await db.collection("notifications")
      .where("targetUid","==",user.uid)
      .limit(10).get();

    const notifications = [];
    globalSnap.docs.forEach(function(d){ notifications.push({ id:d.id, ...d.data() }); });
    userSnap.docs.forEach(function(d){ notifications.push({ id:d.id, ...d.data() }); });
    // Sort by date
    notifications.sort(function(a,b){ return (b.createdAt?._seconds||0) - (a.createdAt?._seconds||0); });
    // Get read notifications for this user
    const readSnap = await db.collection("users").doc(user.uid).collection("readNotifications").get();
    const readIds = new Set(readSnap.docs.map(function(d){ return d.id; }));
    const result = notifications.map(function(n){
      return { ...n, read: readIds.has(n.id), createdAt: n.createdAt?._seconds ? new Date(n.createdAt._seconds*1000).toISOString() : null };
    });
    return res.json({ success:true, notifications: result });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── MARK NOTIFICATION READ ──
app.post("/api/mark-notification-read", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;
  try {
    const { notificationId } = req.body;
    await db.collection("users").doc(user.uid).collection("readNotifications").doc(notificationId).set({ readAt: admin.firestore.FieldValue.serverTimestamp() });
    return res.json({ success:true });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});


// ── BLOG ENDPOINTS ──
app.get("/api/blog-posts", async (req,res) => {
  try {
    const snap = await db.collection("blogPosts")
      .where("published","==",true)
      .limit(20).get();
    const posts = snap.docs.map(function(d){ return { id:d.id, ...d.data() }; });
    posts.sort(function(a,b){ return (b.createdAt?._seconds||0) - (a.createdAt?._seconds||0); });
    return res.json({ success:true, posts });
  } catch(e){ return res.status(500).json({ error:e.message }); }
});

app.get("/api/blog-post/:slug", async (req,res) => {
  try {
    const snap = await db.collection("blogPosts").where("slug","==",req.params.slug).limit(1).get();
    if(snap.empty) return res.status(404).json({ error:"Post not found" });
    return res.json({ success:true, post:{ id:snap.docs[0].id, ...snap.docs[0].data() } });
  } catch(e){ return res.status(500).json({ error:e.message }); }
});


// ── SAVE BLOG POST ──
app.post("/api/save-blog-post", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const { title, slug, excerpt, content, tags, image } = req.body;
    if(!title || !slug || !content) return res.status(400).json({ error:"Title, slug and content required" });
    const docRef = await db.collection("blogPosts").add({
      title, slug, excerpt: excerpt||"", content, tags: tags||[],
      image: image || "",
      published: true,
      metaDescription: excerpt ? excerpt.slice(0,150) : title,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ success:true, id:docRef.id, slug });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});


app.post("/api/generate-blog-post", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const { topic } = req.body;
    if(!topic) return res.status(400).json({ error:"Topic required" });
    const claudeRes = await axios.post(
      "https://api.anthropic.com/v1/messages",
      {
        model: "claude-sonnet-4-6",
        max_tokens: 2000,
        messages: [{
          role: "user",
          content: `Write a detailed SEO-optimized blog article about: "${topic}"
          
The article is for AudLabs blog (audlabs.io) — an AI text-to-speech platform for YouTube creators.

Return ONLY valid JSON in this exact format with no other text:
{
  "title": "SEO optimized title",
  "slug": "url-friendly-slug-no-spaces",
  "metaDescription": "150 char meta description",
  "excerpt": "2 sentence preview",
  "content": "Full HTML article content with h2, h3, p, ul, li tags. Include a CTA to try AudLabs at the end.",
  "tags": ["tag1", "tag2", "tag3"]
}`
        }]
      },
      {
        headers: {
          "x-api-key": process.env.ANTHROPIC_API_KEY,
          "anthropic-version": "2023-06-01",
          "Content-Type": "application/json"
        },
        timeout: 60000
      }
    );
    const content = claudeRes.data?.content?.[0]?.text;
    if(!content) throw new Error("No content generated");
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if(!jsonMatch) throw new Error("Invalid response format");
    const article = JSON.parse(jsonMatch[0]);
    const docRef = await db.collection("blogPosts").add({
      ...article,
      published: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ success:true, id:docRef.id, slug:article.slug, title:article.title });
  } catch(e){
    console.error("Blog generate error:", JSON.stringify(e.response?.data));
    return res.status(500).json({ error:e.message });
  }
});

// ── DEVELOPER API RATE LIMITER ──
var apiRateLimiter = {};
function checkRateLimit(apiKey){
  var now = Date.now();
  if(!apiRateLimiter[apiKey]){
    apiRateLimiter[apiKey] = { requests: 1, windowStart: now };
    return true;
  }
  var limiter = apiRateLimiter[apiKey];
  // Reset window every minute
  if(now - limiter.windowStart > 60000){
    apiRateLimiter[apiKey] = { requests: 1, windowStart: now };
    return true;
  }
  if(limiter.requests >= 5){
    return false;
  }
  limiter.requests++;
  return true;
}

// ── DEVELOPER API MIDDLEWARE ──
async function verifyApiKey(req, res){
  const apiKey = req.headers["x-api-key"] || req.headers["authorization"]?.replace("Bearer ","");
  if(!apiKey){ res.status(401).json({ error:"API key required. Pass it as x-api-key header or Authorization: Bearer YOUR_KEY" }); return null; }
  // Check rate limit
  if(!checkRateLimit(apiKey)){
    res.status(429).json({ error:"Rate limit exceeded. Maximum 5 requests per minute per API key." });
    return null;
  }
  try {
    const snap = await db.collection("apiKeys").where("key","==",apiKey).where("active","==",true).limit(1).get();
    if(snap.empty){ res.status(401).json({ error:"Invalid or inactive API key" }); return null; }
    const keyData = snap.docs[0].data();
    const keyId = snap.docs[0].id;
    // Check if subscription is active
    if(keyData.subscriptionExpiry){
      const expiry = keyData.subscriptionExpiry.toDate ? keyData.subscriptionExpiry.toDate() : new Date(keyData.subscriptionExpiry);
      if(new Date() > expiry){
        res.status(402).json({ error:"Your subscription has expired. Please renew at platform.audlabs.io" });
        return null;
      }
    }
    // Check monthly credits
    if(!keyData.monthlyCredits || keyData.monthlyCredits <= 0){
      res.status(402).json({ error:"Monthly credit limit reached. Upgrade your plan at platform.audlabs.io" });
      return null;
    }
    return { ...keyData, keyId };
  } catch(e){
    res.status(500).json({ error:"API key verification failed" });
    return null;
  }
}


// ── DEVELOPER API — GENERATE VOICE ──
const DEV_PLAN_LIMITS = {
  starter: { weekly: 750000, fiveHour: 150000 },
  growth: { weekly: 2500000, fiveHour: 500000 },
  pro: { weekly: 5000000, fiveHour: 1000000 }
};
function getNextMondayReset(){
  const now = new Date();
  const nowWAT = new Date(now.getTime() + (60*60*1000)); // shift to WAT (UTC+1)
  const day = nowWAT.getUTCDay(); // 0=Sun,1=Mon...
  let daysUntilMonday = (1 - day + 7) % 7;
  if(daysUntilMonday === 0 && nowWAT.getUTCHours() >= 1) daysUntilMonday = 7;
  const nextMondayWAT = new Date(nowWAT);
  nextMondayWAT.setUTCDate(nowWAT.getUTCDate() + daysUntilMonday);
  nextMondayWAT.setUTCHours(1,0,0,0);
  return new Date(nextMondayWAT.getTime() - (60*60*1000)); // shift back to UTC
}
app.post("/api/v1/generate", async (req,res) => {
  const keyData = await verifyApiKey(req,res);
  if(!keyData) return;
  try {
    const { text, voice_id, speed, pitch, volume, format } = req.body;
    if(!text) return res.status(400).json({ error:"text is required" });
    if(!voice_id) return res.status(400).json({ error:"voice_id is required" });
    if(text.length > 50000) return res.status(400).json({ error:"text cannot exceed 50,000 characters" });
    const characters = text.length;
    // Check if enough monthly credits
    if(keyData.monthlyCredits < characters){
      return res.status(402).json({ error:"Insufficient monthly credits. You have "+keyData.monthlyCredits+" credits remaining. Upgrade at platform.audlabs.io" });
    }
    // Weekly & 5-hour limit checks
    const planLimits = DEV_PLAN_LIMITS[keyData.plan] || DEV_PLAN_LIMITS.starter;
    const nowTs = Date.now();
    let weeklyUsed = keyData.weeklyUsed || 0;
    let weeklyResetAt = keyData.weeklyResetAt ? (keyData.weeklyResetAt.toDate ? keyData.weeklyResetAt.toDate().getTime() : new Date(keyData.weeklyResetAt).getTime()) : 0;
    if(!weeklyResetAt || nowTs > weeklyResetAt){
      weeklyUsed = 0;
      weeklyResetAt = getNextMondayReset().getTime();
    }
    if(weeklyUsed + characters > planLimits.weekly){
      return res.status(429).json({ error:"Weekly usage limit reached. Resets "+new Date(weeklyResetAt).toISOString(), resetAt: new Date(weeklyResetAt).toISOString() });
    }
    let fiveHourUsed = keyData.fiveHourUsed || 0;
    let fiveHourWindowStart = keyData.fiveHourWindowStart ? (keyData.fiveHourWindowStart.toDate ? keyData.fiveHourWindowStart.toDate().getTime() : new Date(keyData.fiveHourWindowStart).getTime()) : 0;
    const FIVE_HOURS_MS = 5*60*60*1000;
    if(!fiveHourWindowStart || nowTs - fiveHourWindowStart > FIVE_HOURS_MS){
      fiveHourUsed = 0;
      fiveHourWindowStart = nowTs;
    }
    if(fiveHourUsed + characters > planLimits.fiveHour){
      const resetAt = new Date(fiveHourWindowStart + FIVE_HOURS_MS);
      return res.status(429).json({ error:"5-hour usage limit reached. Resets at "+resetAt.toISOString(), resetAt: resetAt.toISOString() });
    }

    // Generate with MiniMax
    const MK = process.env.MINIMAX_API_KEY;
    const MK2 = process.env.MINIMAX_API_KEY_2 || MK;
    const MK3 = process.env.MINIMAX_API_KEY_3 || MK;
    const MK4 = process.env.MINIMAX_API_KEY_4 || MK;
    const MK5 = process.env.MINIMAX_API_KEY_5 || MK;
    const MK6 = process.env.MINIMAX_API_KEY_6 || MK;
    const MK7 = process.env.MINIMAX_API_KEY_7 || MK;
    const MK8 = process.env.MINIMAX_API_KEY_8 || MK;
    const MK9 = process.env.MINIMAX_API_KEY_9 || MK;
    const MK10 = process.env.MINIMAX_API_KEY_10 || MK;
    let response;
    const requestBody = {


      model: "speech-2.8-hd",
      text: text,
      stream: false,
      voice_setting: { voice_id: voice_id, speed: parseFloat(speed)||1.0, vol: parseFloat(volume)||1.0, pitch: parseInt(pitch)||0 },

      audio_setting: { sample_rate: 32000, bitrate: 128000, format: format||"mp3", channel: 1 },
      output_format: "hex"
    };
    try {
      response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK}`, "Content-Type":"application/json" }});
      if(response.data?.base_resp?.status_code === 1002 || response.data?.base_resp?.status_code === 2056){ throw new Error("Rate limit"); }
    } catch(e1){
      try {
        response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK2}`, "Content-Type":"application/json" }});
        if(response.data?.base_resp?.status_code === 1002 || response.data?.base_resp?.status_code === 2056){ throw new Error("Rate limit"); }
      } catch(e2){
        try {
          response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK3}`, "Content-Type":"application/json" }});
        } catch(e3){
          try {
            response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK4}`, "Content-Type":"application/json" }});
          } catch(e4){
            try {
              response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK5}`, "Content-Type":"application/json" }});
            } catch(e5){
              try {
                response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK6}`, "Content-Type":"application/json" }});
              } catch(e6){
                try {
                  response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK7}`, "Content-Type":"application/json" }});
                } catch(e7){
                  try {
                    response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK8}`, "Content-Type":"application/json" }});
                  } catch(e8){
                    try {
                      response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK9}`, "Content-Type":"application/json" }});
                    } catch(e9){
                      response = await axios.post("https://api.minimax.io/v1/t2a_v2", requestBody, { headers:{ Authorization:`Bearer ${MK10}`, "Content-Type":"application/json" }});
                    }
                  }
                }

              }
            }

          }
        }
      }
    }
    if(!response?.data?.data?.audio){
      return res.status(503).json({ error:"Voice generation temporarily unavailable. Please try again." });
    }

        // Deduct monthly credits + update weekly/5-hour tracking
    await db.collection("apiKeys").doc(keyData.keyId).update({
      monthlyCredits: admin.firestore.FieldValue.increment(-characters),
      totalCharacters: admin.firestore.FieldValue.increment(characters),
      lastUsed: admin.firestore.FieldValue.serverTimestamp(),
      weeklyUsed: weeklyUsed + characters,
      weeklyResetAt: admin.firestore.Timestamp.fromDate(new Date(weeklyResetAt)),
      fiveHourUsed: fiveHourUsed + characters,
      fiveHourWindowStart: admin.firestore.Timestamp.fromDate(new Date(fiveHourWindowStart))
    });

    // Log usage
    await db.collection("apiKeys").doc(keyData.keyId).collection("usage").add({
      characters: characters,
      voice_id: voice_id,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    // Return audio
    const audioBuffer = Buffer.from(response.data.data.audio, "hex");
    res.set("Content-Type", "audio/mpeg");
    res.set("Content-Length", audioBuffer.length);
    res.set("X-Characters-Used", characters);
    res.set("X-Credits-Remaining", keyData.credits - characters);
    return res.send(audioBuffer);
  } catch(e){
    console.error("API generate error:", e.message);
    return res.status(500).json({ error:"Generation failed: " + e.message });
  }
});

// ── DEVELOPER API — LIST VOICES ──
const DEV_API_VOICES = [
{id:"English_CaptivatingStoryteller", name:"Booker", language:"English", gender:"male"},
{id:"English_Trustworth_Man", name:"Allan", language:"English", gender:"male"},
{id:"English_Gentle-voiced_man", name:"John", language:"English", gender:"male"},
{id:"English_MatureBoss", name:"Edna", language:"English", gender:"female"},
{id:"English_CalmWoman", name:"Gallegos", language:"English", gender:"female"},
{id:"English_captivating_female1", name:"Myrtle", language:"English", gender:"female"},
{id:"English_Friendly_Female_3", name:"Deana", language:"English", gender:"female"},
{id:"English_engaging_instructor_vv2", name:"Driskill", language:"English", gender:"male"},
{id:"English_expressive_host__vv1", name:"Maddox", language:"English", gender:"male"},
{id:"English_causual_podcast_vv1", name:"Evans", language:"English", gender:"male"},
{id:"Eglish_horror_movie_narrator_vv1", name:"Jerry", language:"English", gender:"male"},
{id:"English_Aussie_Bloke", name:"Aussie Bloke", language:"English", gender:"male"},
{id:"English_radiant_girl", name:"Andrea", language:"English", gender:"female"},
{id:"English_Upbeat_Woman", name:"Priscilla", language:"English", gender:"female"},
{id:"English_nursery_teacher_vv2", name:"Faith", language:"English", gender:"female"},
{id:"English_instructive_professor_vv1", name:"Helen", language:"English", gender:"female"},
{id:"movie_trailer_deep", name:"Austin", language:"English", gender:"male"},
{id:"English_Insightful_Speaker", name:"Alfred", language:"English", gender:"male"},
{id:"English_Lively_Male_11", name:"William", language:"English", gender:"male"},
{id:"English_FriendlyPerson", name:"Aaron", language:"English", gender:"male"},
{id:"English_Steady_Female_1", name:"Lillian", language:"English", gender:"female"},
{id:"socialmedia_female_1_v1", name:"Eleanor", language:"English", gender:"female"},
{id:"moss_audio_3efb9e96-6e80-11f1-b3de-deb486b97a4e", name:"Brian", language:"English", gender:"male"},
{id:"moss_audio_cedfd4d2-736d-11f0-99be-fe40dd2a5fe8", name:"Shell", language:"English", gender:"male"},
{id:"moss_audio_00b1d233-6182-11f1-88bd-f6b1c9bf6181", name:"Jackson", language:"English", gender:"male"},
{id:"moss_audio_c7f7edbb-6e87-11f1-8fdf-22f27a8feaff", name:"Adam", language:"English", gender:"male"},
{id:"moss_audio_6dc281eb-713c-11f0-a447-9613c873494c", name:"Diana", language:"English", gender:"female"},
{id:"moss_audio_076697ad-7144-11f0-a447-9613c873494c", name:"Joel", language:"English", gender:"male"},
{id:"moss_audio_7c7e7ae2-7356-11f0-9540-7ef9b4b62566", name:"Celia", language:"English", gender:"female"},
{id:"moss_audio_62ca20b0-7380-11f0-99be-fe40dd2a5fe8", name:"Nancy", language:"English", gender:"female"},
{id:"Afrikaans_male_1_v1", name:"Pieter", language:"Afrikaans", gender:"male"},
{id:"Afrikaans_female_1_v1", name:"Annelie", language:"Afrikaans", gender:"female"},
{id:"German_FriendlyMan", name:"Felix", language:"German", gender:"male"},
{id:"German_PlayfulMan", name:"Leon", language:"German", gender:"male"},
{id:"German_SweetLady", name:"Sophie", language:"German", gender:"female"},
{id:"Italian_Narrator", name:"Lorenzo", language:"Italian", gender:"male"},
{id:"Italian_ReliableMan", name:"Matteo", language:"Italian", gender:"male"},
{id:"Italian_AthleticStudent", name:"Marco", language:"Italian", gender:"male"},
{id:"Italian_BraveHeroine", name:"Valentina", language:"Italian", gender:"female"},
{id:"Italian_WanderingSorcerer", name:"Elena", language:"Italian", gender:"female"},
{id:"Italian_DiligentLeader", name:"Lucia", language:"Italian", gender:"female"},
{id:"Italian_ArrogantPrincess", name:"Bianca", language:"Italian", gender:"female"},
{id:"Russian_Engaging_Historian_v1", name:"Alexander", language:"Russian", gender:"male"},
{id:"Russian_Philosophical_Narrator_v1", name:"Ivan", language:"Russian", gender:"male"},
{id:"Russian_Overwhelmed_Vlogger_v1", name:"Mikhail", language:"Russian", gender:"male"},
{id:"Russian_Articulate_Tutor_v1", name:"Sergei", language:"Russian", gender:"male"},
{id:"Russian_Thoughtful_Analyst_v1", name:"Andrei", language:"Russian", gender:"male"},
{id:"Russian_Theatrical_Narrator_v1", name:"Alexei", language:"Russian", gender:"male"},
{id:"Russian_Heroic_Warrior_v1", name:"Pavel", language:"Russian", gender:"male"},
{id:"Russian_Professional_Broadcaster_v2", name:"Yuri", language:"Russian", gender:"male"},
{id:"Russian_Rugged_Storyteller_v1", name:"Viktor", language:"Russian", gender:"male"},
{id:"Russian_Serious_Journalist_v3", name:"Oleg", language:"Russian", gender:"male"},
{id:"Russian_Energetic_Streamer_v1", name:"Igor", language:"Russian", gender:"male"},
{id:"Russian_HandsomeChildhoodFriend", name:"Artem", language:"Russian", gender:"male"},
{id:"Russian_ReliableMan", name:"Roman", language:"Russian", gender:"male"},
{id:"Russian_AttractiveGuy", name:"Denis", language:"Russian", gender:"male"},
{id:"Russian_Bad-temperedBoy", name:"Vladimir", language:"Russian", gender:"male"},
{id:"Russian_Energetic_Boy_v2", name:"Nikolai", language:"Russian", gender:"male"},
{id:"Russian_Gentle_Storyteller_v3", name:"Maria", language:"Russian", gender:"female"},
{id:"Russian_Dramatic_Speaker_v1", name:"Anna", language:"Russian", gender:"female"},
{id:"Russian_Engaging_Podcaster_v1", name:"Irina", language:"Russian", gender:"female"},
{id:"Russian_Spirited_Narrator_v1", name:"Yulia", language:"Russian", gender:"female"},
{id:"Russian_Energetic_Tutor_v1", name:"Alina", language:"Russian", gender:"female"},
{id:"Russian_Wise_Mentor_v1", name:"Vera", language:"Russian", gender:"female"},
{id:"Russian_Energetic_Reporter_v2", name:"Daria", language:"Russian", gender:"female"},
{id:"Russian_Spirited_Schoolgirl_v1", name:"Olga", language:"Russian", gender:"female"},
{id:"Russian_BrightHeroine", name:"Ludmila", language:"Russian", gender:"female"},
{id:"Russian_AmbitiousWoman", name:"Natalia", language:"Russian", gender:"female"},
{id:"Russian_CrazyQueen", name:"Valeria", language:"Russian", gender:"female"},
{id:"Russian_PessimisticGirl", name:"Vera II", language:"Russian", gender:"female"},
{id:"Ukrainian_WiseScholar", name:"Taras", language:"Ukrainian", gender:"male"},
{id:"Ukrainian_CalmWoman", name:"Vika", language:"Ukrainian", gender:"female"},
{id:"French_Male_Speech_New", name:"Level-Headed Man", language:"French", gender:"male"},
{id:"French_CasualMan", name:"Casual Man", language:"French", gender:"male"},
{id:"French_MaleNarrator", name:"Male Narrator", language:"French", gender:"male"},
{id:"French_Female_News Anchor", name:"Patient Female Presenter", language:"French", gender:"female"},
{id:"French_MovieLeadFemale", name:"Movie Lead Female", language:"French", gender:"female"},
{id:"French_FemaleAnchor", name:"Female Anchor", language:"French", gender:"female"},
{id:"French_Female Journalist", name:"Fluent Female", language:"French", gender:"female"},
{id:"French_Female_Speech_New", name:"Persuasive Female", language:"French", gender:"female"},
{id:"Spanish_MaturePartner", name:"Mature Partner", language:"Spanish", gender:"male"},
{id:"Spanish_CaptivatingStoryteller", name:"Captivating Storyteller", language:"Spanish", gender:"male"},
{id:"Spanish_BossyLeader", name:"Bossy Leader", language:"Spanish", gender:"male"},
{id:"Spanish_RationalMan", name:"Rational Man", language:"Spanish", gender:"male"},
{id:"Spanish_Deep-tonedMan", name:"Deep-toned Man", language:"Spanish", gender:"male"},
{id:"Spanish_DeterminedManager", name:"Determined Manager", language:"Spanish", gender:"female"},
{id:"Spanish_SophisticatedLady", name:"Sophisticated Lady", language:"Spanish", gender:"female"},
{id:"Spanish_Fussyhostess", name:"Fussy Hostess", language:"Spanish", gender:"female"},
{id:"Spanish_FrankLady", name:"Frank Lady", language:"Spanish", gender:"female"},
{id:"Spanish_ToughBoss", name:"Tough Boss", language:"Spanish", gender:"female"},
{id:"Portuguese_BR_Engaging_Historian_v1", name:"Gabriel", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Philosophical_Narrator_v1", name:"Rafael", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Overwhelmed_Vlogger_v1", name:"Lucas", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Articulate_Tutor_v1", name:"Mateus", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Thoughtful_Analyst_v1", name:"Pedro", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Theatrical_Narrator_v1", name:"Henrique", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Heroic_Warrior_v1", name:"Eduardo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Professional_Broadcaster_v2", name:"Bruno", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Rugged_Storyteller_v1", name:"Thiago", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Serious_Journalist_v3", name:"Gustavo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Energetic_Streamer_v1", name:"Felipe", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Gentle_Storyteller_v3", name:"Diego", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Dramatic_Speaker_v1", name:"Vinicius", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Engaging_Podcaster_v1", name:"Rodrigo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Spirited_Narrator_v1", name:"Caio", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Energetic_Tutor_v1", name:"Leandro", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Wise_Mentor_v1", name:"Marcelo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Energetic_Reporter_v2", name:"Andre", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Spirited_Schoolgirl_v1", name:"Fabio", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Engaging_Historian_v2", name:"Renato", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Philosophical_Narrator_v2", name:"Sergio", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Overwhelmed_Vlogger_v2", name:"Marcos", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Articulate_Tutor_v2", name:"Leonardo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Thoughtful_Analyst_v2", name:"Alexandre", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Theatrical_Narrator_v2", name:"Antonio", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Heroic_Warrior_v2", name:"Carlos", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Professional_Broadcaster_v3", name:"Daniel", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Rugged_Storyteller_v2", name:"Fernando", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Serious_Journalist_v4", name:"Jose", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Energetic_Streamer_v2", name:"Paulo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Gentle_Storyteller_v4", name:"Roberto", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Dramatic_Speaker_v2", name:"Ricardo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Engaging_Podcaster_v2", name:"Victor", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Spirited_Narrator_v2", name:"Wanderson", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Energetic_Tutor_v2", name:"Guilherme", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Wise_Mentor_v2", name:"Claudio", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Energetic_Reporter_v3", name:"Cristiano", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Spirited_Schoolgirl_v2", name:"Danilo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Engaging_Historian_v3", name:"Edilson", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Philosophical_Narrator_v3", name:"Emerson", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Overwhelmed_Vlogger_v3", name:"Evandro", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Articulate_Tutor_v3", name:"Flavio", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Thoughtful_Analyst_v3", name:"Geovani", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Theatrical_Narrator_v3", name:"Gilberto", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Heroic_Warrior_v3", name:"Heitor", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Professional_Broadcaster_v4", name:"Hugo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Rugged_Storyteller_v3", name:"Iago", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Serious_Journalist_v5", name:"Icaro", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Energetic_Streamer_v3", name:"Italo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Gentle_Storyteller_v5", name:"Jadson", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Dramatic_Speaker_v3", name:"Jairo", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Engaging_Podcaster_v3", name:"Janio", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Spirited_Narrator_v3", name:"Jeferson", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Energetic_Tutor_v3", name:"Jessé", language:"Portuguese", gender:"male"},
{id:"Portuguese_BR_Female_Gentle_Storyteller_v1", name:"Ana", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Dramatic_Speaker_v1", name:"Beatriz", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Engaging_Podcaster_v1", name:"Camila", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Spirited_Narrator_v1", name:"Carolina", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Energetic_Tutor_v1", name:"Fernanda", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Wise_Mentor_v1", name:"Gabriela", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Energetic_Reporter_v1", name:"Isabella", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Spirited_Schoolgirl_v1", name:"Julia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Engaging_Historian_v1", name:"Laura", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Philosophical_Narrator_v1", name:"Leticia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Overwhelmed_Vlogger_v1", name:"Livia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Articulate_Tutor_v1", name:"Lucia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Thoughtful_Analyst_v1", name:"Luisa", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Theatrical_Narrator_v1", name:"Mariana", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Heroic_Warrior_v1", name:"Natalia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Professional_Broadcaster_v1", name:"Patricia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Rugged_Storyteller_v1", name:"Rafaela", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Serious_Journalist_v1", name:"Renata", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Energetic_Streamer_v1", name:"Sabrina", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Gentle_Storyteller_v2", name:"Silvia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Dramatic_Speaker_v2", name:"Simone", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Engaging_Podcaster_v2", name:"Tatiane", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Spirited_Narrator_v2", name:"Thais", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Energetic_Tutor_v2", name:"Vanessa", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Wise_Mentor_v2", name:"Veronica", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Energetic_Reporter_v2", name:"Viviane", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Spirited_Schoolgirl_v2", name:"Yasmin", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Engaging_Historian_v2", name:"Yolanda", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Philosophical_Narrator_v2", name:"Zuleide", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Overwhelmed_Vlogger_v2", name:"Adriana", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Articulate_Tutor_v2", name:"Alessandra", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Thoughtful_Analyst_v2", name:"Aline", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Theatrical_Narrator_v2", name:"Amanda", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Heroic_Warrior_v2", name:"Andreia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Professional_Broadcaster_v2", name:"Angela", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Rugged_Storyteller_v2", name:"Bruna", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Serious_Journalist_v2", name:"Claudia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Energetic_Streamer_v2", name:"Cristina", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Gentle_Storyteller_v3", name:"Debora", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Dramatic_Speaker_v3", name:"Denise", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Engaging_Podcaster_v3", name:"Edilaine", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Spirited_Narrator_v3", name:"Elaine", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Energetic_Tutor_v3", name:"Erica", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Wise_Mentor_v3", name:"Fatima", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Energetic_Reporter_v3", name:"Flavia", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Spirited_Schoolgirl_v3", name:"Gislaine", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Engaging_Historian_v3", name:"Iara", language:"Portuguese", gender:"female"},
{id:"Portuguese_BR_Female_Philosophical_Narrator_v3", name:"Ilana", language:"Portuguese", gender:"female"}
];
app.get("/api/v1/voices", async (req,res) => {
  const keyData = await verifyApiKey(req,res);
  if(!keyData) return;
  return res.json({ voices: DEV_API_VOICES, total: DEV_API_VOICES.length });
});

// ── DEVELOPER API — CHECK BALANCE ──
app.get("/api/v1/balance", async (req,res) => {
  const keyData = await verifyApiKey(req,res);
  if(!keyData) return;
  return res.json({
    success: true,
    credits: keyData.credits,
    totalCharacters: keyData.totalCharacters || 0,
    plan: keyData.plan || "starter",
    keyId: keyData.keyId
  });
});

// ── DEVELOPER PORTAL — SIGNUP ──
app.post("/api/developer/signup", async (req,res) => {
  try {
    const { email, password, name, company } = req.body;
    if(!email || !password || !name) return res.status(400).json({ error:"Name, email and password required" });
    // Check if user already exists in Firebase
    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(email);
      console.log("Existing Firebase user found:", userRecord.uid);
    } catch(notFound){
      // Create new Firebase user
      userRecord = await admin.auth().createUser({ email, password, displayName: name });
      console.log("New Firebase user created:", userRecord.uid);
    }
    // Check if API key already exists for this user
    const existingKey = await db.collection("apiKeys").where("uid","==",userRecord.uid).limit(1).get();
    if(!existingKey.empty){
      return res.status(400).json({ error:"An account already exists for this email. Please sign in instead." });
    }
    // Generate API key
    const apiKey = "aud_" + require("crypto").randomBytes(24).toString("hex");
    // Save to Firestore
    await db.collection("apiKeys").add({
      key: apiKey,
      uid: userRecord.uid,

      email: email,
      name: name,
      company: company || "",
      plan: "starter",
      credits: 0,
      totalCharacters: 0,
      active: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    await db.collection("developers").doc(userRecord.uid).set({
      email, name, company: company||"",
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ success:true, message:"Account created. Please log in at platform.audlabs.io" });
  } catch(e){
    if(e.code === "auth/email-already-exists") return res.status(400).json({ error:"Email already registered" });
    return res.status(500).json({ error:e.message });
  }
});

// ── DEVELOPER PLANS ──
const DEV_PLANS = {
  starter: { name:"Starter", price_usd:30, credits:3000000, label:"3M characters/month" },
  growth: { name:"Growth", price_usd:70, credits:10000000, label:"10M characters/month" },
  pro: { name:"Pro", price_usd:150, credits:20000000, label:"20M characters/month" }
};

// ── DEVELOPER PAYMENT — VIRTUAL ACCOUNT ──
app.post("/api/developer/create-virtual-account", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;


  try {
    const { plan } = req.body;
    const planData = DEV_PLANS[plan];
    if(!planData) return res.status(400).json({ error:"Invalid plan" });
    // Get live USD/NGN rate
    const rateRes = await axios.get("https://api.exchangerate-api.com/v4/latest/USD", { timeout:5000 });
    const rate = rateRes.data?.rates?.NGN || 1600;
    const amountNGN = Math.ceil(planData.price_usd * rate);
    // Get developer info
    const devDoc = await db.collection("developers").doc(user.uid).get();
    const devData = devDoc.exists ? devDoc.data() : {};
    // Create Paystack virtual account
    // Create Paystack customer first
    const devEmail = `dev-${Date.now()}@audlabs.io`;
    const custRes = await axios.post(`${PAYSTACK_BASE}/customer`, {
      email: devEmail,
      first_name: (devData.name||"Developer").split(" ")[0],
      last_name: (devData.name||"Developer").split(" ").slice(1).join(" ")||"User",
      phone: "+2340000000000",
      metadata: { uid: user.uid, plan: plan, type:"dev_payment" }
    }, { headers:{ Authorization:`Bearer ${PAYSTACK_SECRET}` }});
    const customerCode = custRes.data.data.customer_code;
    const paystackRes = await axios.post(
      `${PAYSTACK_BASE}/dedicated_account`,
      { customer: customerCode, preferred_bank: "wema-bank" },
      { headers:{ Authorization:`Bearer ${PAYSTACK_SECRET}` }, timeout:15000 }
    );

    if(!paystackRes.data?.status) throw new Error("Failed to create virtual account");
    const account = paystackRes.data.data;
    // Save pending payment
    const devAccount = paystackRes.data.data;
    await db.collection("devPaymentsPending").add({

      uid: user.uid,
      plan: plan,
      amountNGN: amountNGN,
      amountUSD: planData.price_usd,
      credits: planData.credits,
      accountNumber: devAccount.account_number,
      bankName: devAccount.bank?.name || "Wema Bank",
      accountName: devAccount.account_name,
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 24*60*60*1000))
    });
    // Save account mapping for webhook
    await db.collection("devAccountMap").doc(devAccount.account_number).set({
      uid: user.uid,
      plan: plan,
      amountNGN: amountNGN,
      credits: planData.credits,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });


    return res.json({
      success:true,
      accountNumber: devAccount.account_number,
      bankName: devAccount.bank?.name || "Wema Bank",
      accountName: devAccount.account_name,
      amountNGN: amountNGN,
      amountUSD: planData.price_usd,
      plan: planData.name
    });
  } catch(e){
    console.error("Dev virtual account error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});

// ── DEVELOPER PAYMENT — FLUTTERWAVE CARD ──
app.post("/api/developer/create-card-payment", async (req,res) => {
  const user = await verifyUser(req,res);
  if(!user) return;


  try {
    const { plan } = req.body;
    const planData = DEV_PLANS[plan];
    if(!planData) return res.status(400).json({ error:"Invalid plan" });
    const rateRes = await axios.get("https://api.exchangerate-api.com/v4/latest/USD", { timeout:5000 });
    const rate = rateRes.data?.rates?.NGN || 1600;
    const amountNGN = Math.ceil(planData.price_usd * rate);
    const devDoc = await db.collection("developers").doc(user.uid).get();
    const devData = devDoc.exists ? devDoc.data() : {};
    const txRef = "devplan_" + user.uid.slice(0,8) + "_" + Date.now();
    // Save pending
    await db.collection("devPaymentsPending").add({
      uid: user.uid,
      plan: plan,
      amountNGN: amountNGN,
      amountUSD: planData.price_usd,
      credits: planData.credits,
      txRef: txRef,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({
      success:true,
      paymentLink: `https://checkout.flutterwave.com/v3/hosted/pay`,
      txRef: txRef,
      amount: amountNGN,
      currency: "NGN",
      customerEmail: devData.email || user.email,
      customerName: devData.name || "Developer",
      plan: planData.name
    });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── DEVELOPER PAYMENT WEBHOOK ──
app.post("/api/developer/payment-webhook", async (req,res) => {
  try {
    const event = req.body;
    if(event.event === "charge.success" || event.event === "transfer.success"){
      const txRef = event.data?.tx_ref || event.data?.reference;
      if(!txRef || !txRef.startsWith("devplan_")) return res.sendStatus(200);
      // Find pending payment
      const pendingSnap = await db.collection("devPaymentsPending").where("txRef","==",txRef).limit(1).get();
      if(pendingSnap.empty) return res.sendStatus(200);
      const pending = pendingSnap.docs[0].data();
      // Activate subscription
      const now = new Date();
      const expiry = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days
      const keySnap = await db.collection("apiKeys").where("uid","==",pending.uid).limit(1).get();
      if(!keySnap.empty){
        await db.collection("apiKeys").doc(keySnap.docs[0].id).update({
          monthlyCredits: pending.credits,
          totalMonthlyCredits: pending.credits,
          plan: pending.plan,
          subscriptionExpiry: admin.firestore.Timestamp.fromDate(expiry),
          active: true
        });
      }
      // Delete pending
      await db.collection("devPaymentsPending").doc(pendingSnap.docs[0].id).delete();
      console.log("Developer subscription activated:", pending.uid, pending.plan);
    }
    return res.sendStatus(200);
  } catch(e){
    console.error("Dev webhook error:", e.message);
    return res.sendStatus(200);
  }
});

// ── DEVELOPER RENEWAL REMINDER CRON ──
app.get("/api/developer/renewal-reminder", async (req,res) => {
  const secret = req.headers["x-cron-secret"] || "";
  if(secret !== "audlabs-monthly-2026") return res.status(401).json({ error:"Unauthorized" });
  try {
    const snap = await db.collection("apiKeys").where("active","==",true).get();
    let sent = 0;
    const now = new Date();
    for(const doc of snap.docs){
      const data = doc.data();
      if(!data.subscriptionExpiry || !data.email) continue;
      const expiry = data.subscriptionExpiry.toDate ? data.subscriptionExpiry.toDate() : new Date(data.subscriptionExpiry);
      const daysLeft = Math.ceil((expiry - now) / (1000*60*60*24));
      // Send reminder when 2-3 days left, only once
      if(daysLeft === 3 && !data.renewalReminderSent){
        try {
          await audlabsTransporter.sendMail({
            from: 'AudLabs Platform <hello@audlabs.io>',
            to: data.email,
            subject: 'Your AudLabs API plan expires in 3 days',
            html: `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
<tr><td style="background:#0a1628;padding:24px 32px;text-align:left;">
<span style="font-size:22px;font-weight:700;color:#c9a84c;letter-spacing:1px;">AudLabs</span>
<span style="font-size:12px;color:rgba(255,255,255,0.5);margin-left:8px;">Platform</span>
</td></tr>
<tr><td style="padding:32px;">
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 16px;">Hi ${data.name||"Developer"},</p>
<div style="background:#f8f9fa;border-left:4px solid #c9a84c;border-radius:4px;padding:16px 20px;margin-bottom:24px;">
<div style="font-size:14px;font-weight:700;color:#1a1a1a;margin-bottom:8px;">Your ${data.plan||"API"} plan expires in 3 days</div>
<div style="font-size:14px;color:#555;line-height:1.7;">To keep your API integration running without interruption, renew your plan before it expires. Once expired, API requests using your key will be rejected until you renew.</div>
</div>
<div style="text-align:center;margin-bottom:24px;">
<a href="https://platform.audlabs.io" style="display:inline-block;background:linear-gradient(135deg,#c9a84c,#e8c97a);color:#111;font-weight:700;padding:12px 28px;border-radius:8px;text-decoration:none;font-size:14px;">Renew Your Plan →</a>
</div>
<p style="font-size:13px;color:#888;line-height:1.7;margin:0 0 8px;">If you have any questions, just reply to this email.</p>
<p style="font-size:15px;color:#333;margin:0;">Regards,<br><strong>The AudLabs Team</strong></p>
</td></tr>
<tr><td style="background:#f8f9fa;padding:16px 32px;border-top:1px solid #eee;">
<p style="font-size:11px;color:#bbb;margin:0;text-align:center;">You are receiving this because you have a developer account at platform.audlabs.io.</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
          });
          await doc.ref.update({ renewalReminderSent: true });
          sent++;
        } catch(emailErr){ console.warn("Renewal reminder email failed:", emailErr.message); }
      }
      // Reset the flag once renewed (expiry pushed forward past reminder window)
      if(daysLeft > 3 && data.renewalReminderSent){
        await doc.ref.update({ renewalReminderSent: false });
      }
    }
    return res.json({ success:true, sent });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});


// ── DEVELOPER MONTHLY RESET CRON ──
app.get("/api/developer/monthly-reset", async (req,res) => {
  const secret = req.headers["x-cron-secret"] || "";
  if(secret !== "audlabs-monthly-2026") return res.status(401).json({ error:"Unauthorized" });
  try {
    const snap = await db.collection("apiKeys").where("active","==",true).get();
    let reset = 0;
    for(const doc of snap.docs){
      const data = doc.data();
      if(!data.subscriptionExpiry) continue;
      const expiry = data.subscriptionExpiry.toDate ? data.subscriptionExpiry.toDate() : new Date(data.subscriptionExpiry);
      if(new Date() > expiry){
        // Subscription expired — deactivate
        await doc.ref.update({ monthlyCredits:0, active:false });
      } else {
        // Reset monthly credits
        const credits = data.totalMonthlyCredits || 0;
        await doc.ref.update({ monthlyCredits: credits });
        reset++;
      }
    }
    return res.json({ success:true, reset });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});


// ── DEVELOPER PORTAL — GET USAGE HISTORY ──
app.get("/api/developer/usage-history", async (req,res) => {
  const auth = req.headers.authorization;
  if(!auth?.startsWith("Bearer ")) return res.status(401).json({ error:"Unauthorized" });
  try {
    const decoded = await admin.auth().verifyIdToken(auth.split(" ")[1]);
    const keySnap = await db.collection("apiKeys").where("uid","==",decoded.uid).limit(1).get();
    if(keySnap.empty) return res.status(404).json({ error:"No API key found" });
    const keyId = keySnap.docs[0].id;
    const usageSnap = await db.collection("apiKeys").doc(keyId).collection("usage")
      .orderBy("createdAt","desc").limit(20).get();
    const usage = usageSnap.docs.map(function(d){
      const data = d.data();
      return {
        characters: data.characters,
        voice_id: data.voice_id,
        createdAt: data.createdAt ? new Date(data.createdAt._seconds*1000).toISOString() : null
      };
    });
    return res.json({ success:true, usage });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});


// ── DEVELOPER PORTAL — GET API KEY ──
app.get("/api/developer/key", async (req,res) => {
  const auth = req.headers.authorization;
  if(!auth?.startsWith("Bearer ")) return res.status(401).json({ error:"Unauthorized" });
  try {
    const decoded = await admin.auth().verifyIdToken(auth.split(" ")[1]);
    console.log("Developer key lookup for UID:", decoded.uid, "email:", decoded.email);
    const snap = await db.collection("apiKeys").where("uid","==",decoded.uid).limit(1).get();
    console.log("API key docs found:", snap.size);
    if(snap.empty) return res.status(404).json({ error:"No API key found. Please sign up at platform.audlabs.io" });

        const keyData = snap.docs[0].data();
    const planLimitsForKey = DEV_PLAN_LIMITS[keyData.plan] || DEV_PLAN_LIMITS.starter;
    const nowTsForKey = Date.now();
    let weeklyUsedForKey = keyData.weeklyUsed || 0;
    let weeklyResetAtForKey = keyData.weeklyResetAt ? (keyData.weeklyResetAt.toDate ? keyData.weeklyResetAt.toDate().getTime() : new Date(keyData.weeklyResetAt).getTime()) : 0;
    if(!weeklyResetAtForKey || nowTsForKey > weeklyResetAtForKey){
      weeklyUsedForKey = 0;
      weeklyResetAtForKey = getNextMondayReset().getTime();
    }
    let fiveHourUsedForKey = keyData.fiveHourUsed || 0;
    let fiveHourWindowStartForKey = keyData.fiveHourWindowStart ? (keyData.fiveHourWindowStart.toDate ? keyData.fiveHourWindowStart.toDate().getTime() : new Date(keyData.fiveHourWindowStart).getTime()) : 0;
    const FIVE_HOURS_MS_KEY = 5*60*60*1000;
    if(!fiveHourWindowStartForKey || nowTsForKey - fiveHourWindowStartForKey > FIVE_HOURS_MS_KEY){
      fiveHourUsedForKey = 0;
      fiveHourWindowStartForKey = nowTsForKey;
    }
    return res.json({
      success: true,
      key: keyData.key,
      monthlyCredits: keyData.monthlyCredits || 0,
      totalMonthlyCredits: keyData.totalMonthlyCredits || 0,
      credits: keyData.credits || 0,
      plan: keyData.plan || "none",
      totalCharacters: keyData.totalCharacters || 0,
      subscriptionExpiry: keyData.subscriptionExpiry || null,
      active: keyData.active || false,
      weeklyUsed: weeklyUsedForKey,
      weeklyLimit: planLimitsForKey.weekly,
      weeklyResetAt: new Date(weeklyResetAtForKey).toISOString(),
      fiveHourUsed: fiveHourUsedForKey,
      fiveHourLimit: planLimitsForKey.fiveHour,
      fiveHourResetAt: new Date(fiveHourWindowStartForKey + FIVE_HOURS_MS_KEY).toISOString()
    });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});


// ── ADMIN USER DETAIL ──
app.get("/api/admin-user-detail", async (req,res) => {
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const uid = req.query.uid;
    if(!uid) return res.status(400).json({ error:"UID required" });
    const doc = await db.collection("users").doc(uid).get();
    if(!doc.exists) return res.status(404).json({ error:"User not found" });
    const d = doc.data();
return res.json({ success:true, user:{ 
  id:doc.id,
  email: d.email||"",
  displayName: d.displayName||d.name||"",
  credits: d.credits||0,
  totalGenerations: d.totalGenerations||0,
  totalCharacters: d.totalCharacters||0,
  teamId: d.teamId||"",
  teamRole: d.teamRole||"",
  referredBy: d.referredBy||"",
  referralCount: d.referralCount||0,
  referralEarningsNGN: d.referralEarningsNGN||0,
  referralRate: d.referralRate||10,
    referralCode: d.referralCode||"",
  hasPurchased: d.hasPurchased||false,
  location: d.location || null,
  trafficSource: d.trafficSource || "",
  createdAt: d.createdAt ? d.createdAt.toMillis() : null
}});

  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── ADMIN DELETE USER ──
app.post("/api/admin-delete-user", async (req,res) => {
  const adminPassword = req.headers["x-admin-password"] || "";
  if(adminPassword !== "(Oluwaseyi23)") return res.status(401).json({ error:"Unauthorized" });
  try {
    const { uid } = req.body;
    if(!uid) return res.status(400).json({ error:"UID required" });
    await db.collection("users").doc(uid).delete();
    // Also delete from Firebase Authentication
    try {
      await admin.auth().deleteUser(uid);
    } catch(authErr){ console.warn("Auth delete failed:", authErr.message); }
    return res.json({ success:true });
  } catch(e){ return res.status(500).json({ error:e.message }); }
});
// ── ADMIN TRAFFIC INSIGHTS ──
app.get("/api/admin-traffic-insights", async (req,res) => {
  const adminPassword = req.headers["x-admin-password"] || req.headers["x-admin-secret"];
  if(adminPassword !== "(Oluwaseyi23)" && adminPassword !== "audlabs-admin-2026") return res.status(401).json({ error:"Unauthorized" });
  try {
    const usersSnap = await db.collection("users").get();
    const countryCount = {};
    const sourceCount = {};
    let trackedUsers = 0;
    usersSnap.docs.forEach(function(doc){
      const d = doc.data();
      if(d.location && d.location.country && d.location.country !== "Unknown"){
        countryCount[d.location.country] = (countryCount[d.location.country]||0) + 1;
        trackedUsers++;
      }
      if(d.trafficSource){
        sourceCount[d.trafficSource] = (sourceCount[d.trafficSource]||0) + 1;
      }
    });
    const topCountries = Object.keys(countryCount)
      .map(function(c){ return { country: c, count: countryCount[c] }; })
      .sort(function(a,b){ return b.count - a.count; })
      .slice(0, 5);
    const topSources = Object.keys(sourceCount)
      .map(function(s){ return { source: s, count: sourceCount[s] }; })
      .sort(function(a,b){ return b.count - a.count; })
      .slice(0, 6);
    return res.json({ success:true, topCountries, topSources, trackedUsers, totalUsers: usersSnap.size });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});
// ── ADMIN STATS ──
app.get("/api/admin-stats", async (req,res) => {
  const adminPassword = req.headers["x-admin-password"] || "";
  if(adminPassword !== "(Oluwaseyi23)"){
    return res.status(401).json({ error:"Unauthorized" });
  }
  try {
    const usersSnap = await db.collection("users").get();
    const totalUsers = usersSnap.size;
    let totalGenerations = 0;
    let totalCharacters = 0;
    let voiceCount = {};
    let recentUsers = [];
    let totalRevenue = 0;
    let totalCommissions = 0;
    usersSnap.docs.forEach(function(doc){
      const d = doc.data();
      totalGenerations += d.totalGenerations||0;
      totalCharacters += d.totalCharacters||0;
      totalCommissions += d.referralEarningsNGN||0;

      if(d.voiceCount){
        Object.keys(d.voiceCount).forEach(function(v){
          voiceCount[v] = (voiceCount[v]||0) + d.voiceCount[v];
        });
      }
      recentUsers.push({
        id: doc.id,
        email: d.email||"",
        displayName: d.displayName||"",
        credits: d.credits||0,
        totalGenerations: d.totalGenerations||0,
        totalCharacters: d.totalCharacters||0,
        teamId: d.teamId||"",
        teamRole: d.teamRole||"",
        referredBy: d.referredBy||"",
        referralCount: d.referralCount||0,
        referralEarningsNGN: d.referralEarningsNGN||0,
        referralRate: d.referralRate||10,
        hasPurchased: d.hasPurchased||false,
        createdAt: d.createdAt ? d.createdAt.toMillis() : null
      });

    });
    recentUsers.sort(function(a,b){
      if(!a.createdAt) return 1;
      if(!b.createdAt) return -1;
      return b.createdAt - a.createdAt;
    });
    // Get top voices
    const topVoices = Object.keys(voiceCount)
      .sort(function(a,b){ return voiceCount[b]-voiceCount[a]; })
      .slice(0,10)
      .map(function(v){ return {name:v, count:voiceCount[v]}; });
    // Get revenue from single summary document (only 1 Firestore read)
    const revenueDoc = await db.collection("stats").doc("revenue").get();
    let revenue24h = 0;
    let revenue7d = 0;
    let revenue30d = 0;
    if(revenueDoc.exists){
      totalRevenue = revenueDoc.data().totalUSD || 0;
      const allData = revenueDoc.data();
      const now = new Date();
      Object.keys(allData).forEach(function(key){
        if(key.startsWith("daily.")){
          const dateStr = key.replace("daily.", "");
          const date = new Date(dateStr);
          const diffDays = (now - date) / (1000 * 60 * 60 * 24);
          const amount = allData[key] || 0;
          if(diffDays <= 1) revenue24h += amount;
          if(diffDays <= 7) revenue7d += amount;
          if(diffDays <= 30) revenue30d += amount;
        }
      });
    }
    return res.json({
      success: true,
      totalUsers,
      totalGenerations,
      totalCharacters,
      topVoices,
      totalRevenue: totalRevenue.toFixed(2),
      revenue24h: revenue24h.toFixed(2),
      revenue7d: revenue7d.toFixed(2),
      revenue30d: revenue30d.toFixed(2),
      totalCommissions: totalCommissions,
      users: recentUsers
    });

  } catch(e) {
    console.error("Admin stats error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── CLEANUP UNVERIFIED ACCOUNTS ──
app.post("/api/cleanup-unverified", async (req,res) => {
  const secret = req.headers["x-cron-secret"] || "";
  const isVercelCron = req.headers["x-vercel-cron-schedule"] || req.headers["user-agent"]?.includes("vercel-cron");
  if(secret !== "audlabs-monthly-2026" && !isVercelCron){
    return res.status(401).json({ error:"Unauthorized" });
  }
  try {
    const now = new Date();
    const cutoff = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 24 hours ago
    // List all users from Firebase Auth
    let deleted = 0;
    let nextPageToken;
    do {
      const listResult = await admin.auth().listUsers(1000, nextPageToken);
      for(const user of listResult.users){
        if(!user.emailVerified && user.providerData[0]?.providerId === "password"){
          const createdAt = new Date(parseInt(user.metadata.creationTime));
          if(createdAt < cutoff){
            try {
              await admin.auth().deleteUser(user.uid);
              // Also delete from Firestore if exists
              await db.collection("users").doc(user.uid).delete();
              deleted++;
              console.log("Deleted unverified account:", user.email);
            } catch(delErr){
              console.warn("Failed to delete:", user.email, delErr.message);
            }
          }
        }
      }
      nextPageToken = listResult.pageToken;
    } while(nextPageToken);
    console.log("Cleanup done — deleted", deleted, "unverified accounts");
    return res.json({ success:true, deleted });
  } catch(e){
    console.error("Cleanup error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});
// ── DOWNLOAD AUDIO ──
app.get("/api/download-audio", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const url = req.query.url;
    if(!url) return res.status(400).json({ error:"URL required" });
    const response = await axios.get(url, { responseType:"arraybuffer" });
    res.set("Content-Type", "audio/mpeg");
    res.set("Content-Disposition", "attachment; filename=AudLabs_"+Date.now()+".mp3");
    return res.send(Buffer.from(response.data));
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── DELETE AUDIO FILE ──
app.post("/api/delete-audio", async (req,res) => {
  const user = await verifyUser(req,res);
  if (!user) return;
  try {
    const { filename, historyId } = req.body;
    if(filename){
      try {
        await bucket.file(filename).delete();
      } catch(e){ console.warn("Storage delete failed:", e.message); }
    }
    if(historyId){
      await db.collection("users").doc(user.uid).collection("history").doc(historyId).delete();
      await db.collection("audioFiles").where("uid","==",user.uid).where("filename","==",filename).get().then(function(snap){
        snap.forEach(function(doc){ doc.ref.delete(); });
      });
    }
    return res.json({ success:true });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── CLEANUP EXPIRED AUDIO ──
app.post("/api/cleanup-audio", async (req,res) => {
  const isVercelCron = req.headers["x-vercel-cron-schedule"] || req.headers["user-agent"]?.includes("vercel-cron");
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(!isVercelCron && !isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const now = admin.firestore.Timestamp.now();
    const expiredSnap = await db.collection("audioFiles")
      .where("expiresAt", "<", now)
      .limit(100)
      .get();
    let deleted = 0;
    for(const doc of expiredSnap.docs){
      const data = doc.data();
      try {
        await bucket.file(data.filename).delete();
      } catch(e){ console.warn("File delete failed:", e.message); }
      await doc.ref.delete();
      deleted++;
    }
    console.log("Cleaned up", deleted, "expired audio files");
    return res.json({ success:true, deleted });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── TEAM EXPIRY CHECK ──
app.all("/api/check-team-expiry", async (req,res) => {
  const secret = req.headers["x-cron-secret"] || "";
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  const isVercelCron = req.headers["x-vercel-cron-schedule"] !== "" || (req.headers["user-agent"]||"").includes("vercel-cron");
  if(secret !== "audlabs-monthly-2026" && !isVercelCron && !isAdmin) return res.status(401).json({ error:"Unauthorized" });
  try {
    const now = new Date();
    const threeDaysFromNow = new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000);
    const teamsSnap = await db.collection("teams").where("status","==","active").get();
    let expired = 0, warned = 0;
    for(const teamDoc of teamsSnap.docs){
      const team = teamDoc.data();
      const renewalField = team.nextRenewalAt || team.nextRenewal;
      if(!renewalField) continue;
      const renewalDate = renewalField.toDate();
      // Check if expired
      if(renewalDate < now){
        // Expire the team
        await db.collection("teams").doc(teamDoc.id).update({ status:"expired" });
        // Remove teamId from all members
        for(const member of (team.members || [])){
          try {
            await db.collection("users").doc(member.uid).update({
              teamId: admin.firestore.FieldValue.delete(),
              teamRole: admin.firestore.FieldValue.delete()
            });
          } catch(e){ console.warn("Member update failed:", e.message); }
        }
        // Send expiry email to admin
        try {
          var adminUserDoc = await db.collection("users").doc(team.adminUid).get();
          var adminEmail = adminUserDoc.data()?.email || team.adminEmail;
          var adminName = adminUserDoc.data()?.displayName?.split(" ")[0] || "Creator";
          await sesTransporter.sendMail({
            from: 'AudLabs <hello@audlabs.io>',
            to: adminEmail,
            subject: `Your AudLabs team plan has expired`,
            html: `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;">
<tr><td style="background:#0a1628;padding:24px 32px;">
<span style="font-size:22px;font-weight:700;color:#c9a84c;">AudLabs</span>
<span style="font-size:12px;color:rgba(255,255,255,0.5);margin-left:8px;">Team Account</span>
</td></tr>
<tr><td style="padding:32px;">
<div style="background:#fff3f3;border-left:4px solid #e74c3c;border-radius:4px;padding:16px 20px;margin-bottom:24px;">
<div style="font-size:11px;color:#888;text-transform:uppercase;margin-bottom:4px;">Account Notice</div>
<div style="font-size:15px;font-weight:600;color:#1a1a1a;">Your team plan has expired</div>
</div>
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 16px;">Hi ${adminName},</p>
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 24px;">Your AudLabs team plan <strong>${team.teamName}</strong> expired today. Your team members no longer have access to unlimited credits.</p>
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 24px;">Renew your team plan to restore access for all your members immediately.</p>
<table cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
<tr><td style="background:#c9a84c;border-radius:8px;padding:14px 32px;">
<a href="https://app.audlabs.io/team" style="color:#111;font-size:15px;font-weight:700;text-decoration:none;">Renew Team Plan →</a>
</td></tr>
</table>
<p style="font-size:13px;color:#888;">If you have any questions reply to this email.</p>
<p style="font-size:15px;color:#333;margin:0;">Regards,<br><strong>Adeyemo</strong><br><span style="font-size:13px;color:#888;">Founder, AudLabs</span></p>
</td></tr>
<tr><td style="background:#f8f9fa;padding:16px 32px;border-top:1px solid #eee;">
<p style="font-size:11px;color:#bbb;margin:0;text-align:center;">AudLabs — AI Voice Generation for Creators</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
          });
        } catch(emailErr){ console.warn("Expiry email failed:", emailErr.message); }
        expired++;
      }
      // Send 3 day warning
      else if(renewalDate < threeDaysFromNow && !team.warningSent){
        try {
          var adminUserDoc2 = await db.collection("users").doc(team.adminUid).get();
          var adminEmail2 = adminUserDoc2.data()?.email || team.adminEmail;
          var adminName2 = adminUserDoc2.data()?.displayName?.split(" ")[0] || "Creator";
          await sesTransporter.sendMail({
            from: 'AudLabs <hello@audlabs.io>',
            to: adminEmail2,
            subject: `Your AudLabs team plan expires in 3 days`,
            html: `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;">
<tr><td style="background:#0a1628;padding:24px 32px;">
<span style="font-size:22px;font-weight:700;color:#c9a84c;">AudLabs</span>
<span style="font-size:12px;color:rgba(255,255,255,0.5);margin-left:8px;">Team Account</span>
</td></tr>
<tr><td style="padding:32px;">
<div style="background:#fffdf7;border-left:4px solid #c9a84c;border-radius:4px;padding:16px 20px;margin-bottom:24px;">
<div style="font-size:11px;color:#888;text-transform:uppercase;margin-bottom:4px;">Renewal Reminder</div>
<div style="font-size:15px;font-weight:600;color:#1a1a1a;">Your team plan expires in 3 days</div>
</div>
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 16px;">Hi ${adminName2},</p>
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 24px;">Your AudLabs team plan <strong>team.teamName</strong>expireson<strong>{renewalDate.toLocaleDateString()}</strong>. Renew now to keep your team generating without interruption.</p>
<table cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
<tr><td style="background:#c9a84c;border-radius:8px;padding:14px 32px;">
<a href="https://app.audlabs.io/team" style="color:#111;font-size:15px;font-weight:700;text-decoration:none;">Renew Team Plan →</a>
</td></tr>
</table>
<p style="font-size:13px;color:#888;">If you have any questions reply to this email.</p>
<p style="font-size:15px;color:#333;margin:0;">Regards,<br><strong>Adeyemo</strong><br><span style="font-size:13px;color:#888;">Founder, AudLabs</span></p>
</td></tr>
<tr><td style="background:#f8f9fa;padding:16px 32px;border-top:1px solid #eee;">
<p style="font-size:11px;color:#bbb;margin:0;text-align:center;">AudLabs — AI Voice Generation for Creators</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
          });
          await db.collection("teams").doc(teamDoc.id).update({ warningSent: true });
        } catch(emailErr){ console.warn("Warning email failed:", emailErr.message); }
        warned++;
      }
    }
    return res.json({ success:true, expired, warned });
  } catch(e){
    return res.status(500).json({ error:e.message });
  }
});

// ── MONTHLY EMAILS ──
app.all("/api/monthly-emails", async (req,res) => {
  const secret = req.headers["x-cron-secret"] || "";
  const vercelCronSchedule = req.headers["x-vercel-cron-schedule"] || "";
  const vercelUserAgent = req.headers["user-agent"] || "";
  const isVercelCron = vercelCronSchedule !== "" || vercelUserAgent.includes("vercel-cron");
  const isAdmin = req.headers["x-admin-secret"] === "audlabs-admin-2026";
  if(secret !== "audlabs-monthly-2026" && !isVercelCron && !isAdmin){
    return res.status(401).json({ error:"Unauthorized" });
  }
  try {
    const usersSnap = await db.collection("users").get();
    let emailsSent = 0;
    let emailsFailed = 0;
    const maxEmailsPerRun = 500;
    for(const doc of usersSnap.docs){
      if(emailsSent >= maxEmailsPerRun) break;
      const userData = doc.data();
      if(!userData.email) continue;
      var firstName = userData.displayName ? userData.displayName.split(" ")[0] : userData.email.split("@")[0].replace(/[0-9._-]/g," ").trim().split(" ")[0];
      firstName = firstName.charAt(0).toUpperCase() + firstName.slice(1);
      if(!firstName) firstName = "Creator";
      try {
        await sesTransporter.sendMail({
          from: 'Adeyemo from AudLabs <hello@audlabs.io>',
          to: userData.email,
          subject: `Your free monthly credits are ready, ${firstName}`,
          html: `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
<tr><td style="background:#0a1628;padding:24px 32px;text-align:left;">
<span style="font-size:22px;font-weight:700;color:#c9a84c;letter-spacing:1px;">AudLabs</span>
<span style="font-size:12px;color:rgba(255,255,255,0.5);margin-left:8px;">Account Notification</span>
</td></tr>
<tr><td style="padding:32px;">
<div style="background:#f8f9fa;border-left:4px solid #c9a84c;border-radius:4px;padding:16px 20px;margin-bottom:24px;">
<div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:4px;">Account Update</div>
<div style="font-size:15px;font-weight:600;color:#1a1a1a;">5,000 free credits added to your account</div>
</div>
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 16px;">Hi ${firstName},</p>
<p style="font-size:15px;color:#333;line-height:1.7;margin:0 0 24px;">Your free monthly credits have just been added to your AudLabs account. Log in and start generating professional voiceovers right away.</p>
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f8f9fa;border-radius:8px;margin-bottom:24px;">
<tr><td style="padding:16px 20px;border-bottom:1px solid #eee;">
<span style="font-size:12px;color:#888;">Credits Added</span><br>
<span style="font-size:20px;color:#c9a84c;font-weight:700;">5,000 credits</span>
</td></tr>
<tr><td style="padding:16px 20px;">
<span style="font-size:12px;color:#888;">Account</span><br>
<span style="font-size:14px;color:#1a1a1a;font-weight:600;">${userData.email}</span>
</td></tr>
</table>
<table cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
<tr><td style="background:#c9a84c;border-radius:8px;padding:14px 32px;">
<a href="https://app.audlabs.io" style="color:#111;font-size:15px;font-weight:700;text-decoration:none;">Start Generating Now →</a>
</td></tr>
</table>
<p style="font-size:13px;color:#888;line-height:1.7;margin:0 0 8px;">If you have any questions simply reply to this email.</p>
<p style="font-size:15px;color:#333;margin:0;">Regards,<br><strong>Adeyemo</strong><br><span style="font-size:13px;color:#888;">Founder, AudLabs</span></p>
</td></tr>
<tr><td style="background:#f8f9fa;padding:16px 32px;border-top:1px solid #eee;">
<p style="font-size:11px;color:#bbb;margin:0;text-align:center;">You are receiving this because you created an account at audlabs.io. Reply to unsubscribe.</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`
        });
        emailsSent++;
        await new Promise(function(resolve){ setTimeout(resolve, 75); });
      } catch(emailErr){
        console.warn("Failed to send monthly email to:", userData.email, emailErr.message);
        emailsFailed++;
      }
    }
    console.log("✅ Monthly emails sent:", emailsSent, "failed:", emailsFailed);
    return res.json({ success:true, emailsSent, emailsFailed });
  } catch(e){
    console.error("Monthly emails error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});

// ── MONTHLY CREDITS ──
app.all("/api/monthly-credits", async (req,res) => {
  const secret = req.headers["x-cron-secret"] || "";
  const vercelCronSchedule = req.headers["x-vercel-cron-schedule"] || "";
  const vercelUserAgent = req.headers["user-agent"] || "";
  const isVercelCron = vercelCronSchedule !== "" || vercelUserAgent.includes("vercel-cron");
  if(secret !== "audlabs-monthly-2026" && !isVercelCron){
    return res.status(401).json({ error:"Unauthorized" });
  }

  try {
    const usersSnap = await db.collection("users").get();
    let count = 0;
    const batchSize = 10;
    const docs = usersSnap.docs;
    for(let i = 0; i < docs.length; i += batchSize){

      const batch = db.batch();
      const chunk = docs.slice(i, i + batchSize);
      for(const doc of chunk){
        const userRef = db.collection("users").doc(doc.id);
        batch.update(userRef, {
          credits: admin.firestore.FieldValue.increment(2000)
        });
        count++;
      }
      await batch.commit();

            // Add transactions
      for(const doc of chunk){
        await db.collection("users").doc(doc.id).collection("transactions").add({
          type:"credit", amount:2000,
          note:"🎁 Monthly Credits — 2,000 free credits for being an AudLabs User.",
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
    }
    console.log("✅ Monthly credits distributed to", count, "users");
    return res.json({ success:true, usersCredited:count, message:"Credits distributed successfully" });

  } catch(e){
    console.error("Monthly credits error:", e.message);
    return res.status(500).json({ error:e.message });
  }
});



const PORT = process.env.PORT || 3000;
app.get("*", (req,res) => {
  res.sendFile(path.join(__dirname, "public", "app.html"));
});
app.listen(PORT, () => console.log(`VoiceGen on port ${PORT}`));
