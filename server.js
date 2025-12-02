import express from "express";
import cors from "cors";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { v4 as uuid } from "uuid";
import { createHash, randomBytes } from "crypto";
import { spawn } from "child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 4000;
const dataDir = path.join(__dirname, "data");
const authFilePath = path.join(dataDir, "auth.json");
const jobsFilePath = path.join(dataDir, "email-jobs.json");
const ipRotationFilePath = path.join(dataDir, "ip-rotation.json");
const rateLimitFilePath = path.join(dataDir, "rate-limit.json");
const pythonExecutable = process.env.PYTHON_CMD || "python";

const sessions = new Map();
const ipRotationCache = new Map();
const rateLimitCache = new Map();

// Rate limiting configuration
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute in milliseconds
const RATE_LIMIT_MAX_REQUESTS = 30; // Max requests per minute per IP
const EMAIL_RATE_LIMIT = 10; // Max emails per minute per user

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

// Middleware for rate limiting
const rateLimitMiddleware = (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  // Clean old entries
  rateLimitCache.forEach((data, key) => {
    if (now - data.timestamp > RATE_LIMIT_WINDOW) {
      rateLimitCache.delete(key);
    }
  });
  
  const userData = rateLimitCache.get(ip);
  if (!userData) {
    rateLimitCache.set(ip, { count: 1, timestamp: now });
  } else {
    if (now - userData.timestamp > RATE_LIMIT_WINDOW) {
      rateLimitCache.set(ip, { count: 1, timestamp: now });
    } else if (userData.count >= RATE_LIMIT_MAX_REQUESTS) {
      return res.status(429).json({ 
        message: "Too many requests. Please try again later.",
        retryAfter: Math.ceil((RATE_LIMIT_WINDOW - (now - userData.timestamp)) / 1000)
      });
    } else {
      userData.count++;
    }
  }
  next();
};

app.use(rateLimitMiddleware);

const baseUserStore = { users: [] };
const baseJobStore = { jobs: [] };
const baseIPRotationStore = { proxies: [], currentIndex: 0 };
const baseRateLimitStore = { limits: {} };

async function ensureDataFiles() {
  await fs.mkdir(dataDir, { recursive: true });
  await readJson(authFilePath, baseUserStore);
  await readJson(jobsFilePath, baseJobStore);
  await readJson(ipRotationFilePath, baseIPRotationStore);
  await readJson(rateLimitFilePath, baseRateLimitStore);
}

async function readJson(filePath, fallback) {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw);
  } catch (error) {
    if (error.code === "ENOENT" && fallback) {
      await writeJson(filePath, fallback);
      return JSON.parse(JSON.stringify(fallback));
    }
    throw error;
  }
}

async function writeJson(filePath, value) {
  const payload = JSON.stringify(value, null, 2);
  await fs.writeFile(filePath, payload, "utf8");
}

// User management functions
async function readUsers() {
  const data = await readJson(authFilePath, baseUserStore);
  return data.users || [];
}

async function saveUsers(users) {
  await writeJson(authFilePath, { users });
}

async function readJobs() {
  const data = await readJson(jobsFilePath, baseJobStore);
  return data.jobs || [];
}

async function saveJobs(jobs) {
  await writeJson(jobsFilePath, { jobs });
}

async function readIPRotation() {
  const data = await readJson(ipRotationFilePath, baseIPRotationStore);
  return data;
}

async function saveIPRotation(data) {
  await writeJson(ipRotationFilePath, data);
}

async function readRateLimits() {
  const data = await readJson(rateLimitFilePath, baseRateLimitStore);
  return data;
}

async function saveRateLimits(data) {
  await writeJson(rateLimitFilePath, data);
}

function hashPassword(password, salt) {
  return createHash("sha256").update(`${salt}${password}`).digest("hex");
}

function generateSalt() {
  return randomBytes(16).toString("hex");
}

function normalizeRecipients(recipients = []) {
  if (Array.isArray(recipients)) {
    return recipients.map((value) => value.trim()).filter(Boolean);
  }
  if (typeof recipients === "string") {
    return recipients
      .split(/\r?\n|,|;/)
      .map((value) => value.trim())
      .filter(Boolean);
  }
  return [];
}

function getTokenFromRequest(req) {
  const header = req.headers.authorization || "";
  if (header.startsWith("Bearer ")) {
    return header.substring(7).trim();
  }
  if (req.body && typeof req.body.token === "string") {
    return req.body.token;
  }
  if (req.query && typeof req.query.token === "string") {
    return req.query.token;
  }
  return null;
}

function requireAuth(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) {
    return res.status(401).json({ message: "Missing authorization token" });
  }
  const session = sessions.get(token);
  if (!session) {
    return res.status(401).json({ message: "Session expired" });
  }
  req.user = { ...session, token };
  return next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
}

async function checkEmailRateLimit(username) {
  const now = Date.now();
  const rateLimits = await readRateLimits();
  
  if (!rateLimits.limits[username]) {
    rateLimits.limits[username] = [];
  }
  
  // Remove entries older than 1 minute
  rateLimits.limits[username] = rateLimits.limits[username].filter(
    timestamp => now - timestamp < RATE_LIMIT_WINDOW
  );
  
  if (rateLimits.limits[username].length >= EMAIL_RATE_LIMIT) {
    return false;
  }
  
  rateLimits.limits[username].push(now);
  await saveRateLimits(rateLimits);
  return true;
}

async function getNextProxy() {
  const ipData = await readIPRotation();
  if (!ipData.proxies || ipData.proxies.length === 0) {
    return null;
  }
  
  const proxy = ipData.proxies[ipData.currentIndex];
  ipData.currentIndex = (ipData.currentIndex + 1) % ipData.proxies.length;
  await saveIPRotation(ipData);
  
  return proxy;
}

async function addMailboxForUser(username, smtpUsername, smtpPassword) {
  const users = await readUsers();
  const existing = users.find((user) => user.username === username);
  if (!existing) {
    return [];
  }
  if (!Array.isArray(existing.mailboxes)) {
    existing.mailboxes = [];
  }
  const now = new Date().toISOString();
  const mailbox = existing.mailboxes.find((box) => box.smtpUsername === smtpUsername);
  if (mailbox) {
    mailbox.smtpPassword = smtpPassword;
    mailbox.updatedAt = now;
  } else {
    existing.mailboxes.push({
      id: uuid(),
      label: smtpUsername,
      smtpUsername,
      smtpPassword,
      createdAt: now,
      updatedAt: now,
    });
  }
  await saveUsers(users);
  return existing.mailboxes;
}

async function runPythonJob(job) {
  // Get proxy for IP rotation
  const proxy = await getNextProxy();
  
  const payload = {
    subject: job.subject,
    recipients: job.recipients,
    textBody: job.textBody,
    htmlBody: job.htmlBody,
    username: job.smtpUsername,
    password: job.smtpPassword,
    proxy: proxy
  };
  
  const payloadPath = path.join(dataDir, `payload-${job.id}-${Date.now()}.json`);
  await fs.writeFile(payloadPath, JSON.stringify(payload, null, 2), "utf8");
  
  return new Promise((resolve, reject) => {
    const pythonProcess = spawn(pythonExecutable, ["main.py", "--payload", payloadPath], {
      cwd: __dirname,
      shell: false,
    });
    
    let stdout = "";
    let stderr = "";
    
    pythonProcess.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    
    pythonProcess.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    
    pythonProcess.on("error", (error) => reject(error));
    pythonProcess.on("close", (code) => {
      if (code === 0) {
        resolve({ success: true, output: stdout });
      } else {
        reject(new Error(stderr || `Python process exited with code ${code}`));
      }
    });
  }).finally(async () => {
    try {
      await fs.unlink(payloadPath);
    } catch (error) {
      // Ignore cleanup errors
    }
  });
}

// Authentication endpoints
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }
  const users = await readUsers();
  const user = users.find((entry) => entry.username === username);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  const expected = hashPassword(password, user.salt);
  if (expected !== user.passwordHash) {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  
  // Check if user is active
  if (user.status === "suspended") {
    return res.status(403).json({ message: "Account suspended" });
  }
  
  const token = uuid();
  sessions.set(token, { 
    username: user.username, 
    role: user.role || "user",
    id: user.id 
  });
  
  return res.json({
    token,
    username: user.username,
    role: user.role || "user",
    mailboxes: user.mailboxes || [],
    status: user.status || "active"
  });
});

app.post("/auth/logout", requireAuth, (req, res) => {
  sessions.delete(req.user.token);
  return res.json({ message: "Logged out" });
});

app.get("/auth/me", requireAuth, async (req, res) => {
  const users = await readUsers();
  const user = users.find((entry) => entry.username === req.user.username);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  return res.json({ 
    username: user.username, 
    role: user.role || "user", 
    mailboxes: user.mailboxes || [],
    status: user.status || "active"
  });
});

// User management endpoints (Admin only)
app.post("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role = "user", status = "active" } = req.body || {};
  
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }
  
  const users = await readUsers();
  if (users.some(u => u.username === username)) {
    return res.status(409).json({ message: "Username already exists" });
  }
  
  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);
  
  const newUser = {
    id: uuid(),
    username,
    passwordHash,
    salt,
    role,
    status,
    mailboxes: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  
  users.push(newUser);
  await saveUsers(users);
  
  return res.status(201).json({ 
    message: "User created successfully",
    user: {
      id: newUser.id,
      username: newUser.username,
      role: newUser.role,
      status: newUser.status,
      createdAt: newUser.createdAt
    }
  });
});

app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const users = await readUsers();
  return res.json(users.map(user => ({
    id: user.id,
    username: user.username,
    role: user.role,
    status: user.status || "active",
    mailboxes: user.mailboxes || [],
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  })));
});

app.put("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { username, role, status } = req.body || {};
  
  const users = await readUsers();
  const userIndex = users.findIndex(u => u.id === id);
  
  if (userIndex === -1) {
    return res.status(404).json({ message: "User not found" });
  }
  
  if (username && username !== users[userIndex].username) {
    // Check if new username is already taken
    if (users.some(u => u.username === username && u.id !== id)) {
      return res.status(409).json({ message: "Username already exists" });
    }
    users[userIndex].username = username;
  }
  
  if (role) users[userIndex].role = role;
  if (status) users[userIndex].status = status;
  users[userIndex].updatedAt = new Date().toISOString();
  
  await saveUsers(users);
  
  return res.json({ 
    message: "User updated successfully",
    user: {
      id: users[userIndex].id,
      username: users[userIndex].username,
      role: users[userIndex].role,
      status: users[userIndex].status
    }
  });
});

app.delete("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  const users = await readUsers();
  const userIndex = users.findIndex(u => u.id === id);
  
  if (userIndex === -1) {
    return res.status(404).json({ message: "User not found" });
  }
  
  const deletedUser = users.splice(userIndex, 1)[0];
  await saveUsers(users);
  
  // Also delete user's sessions
  for (const [token, session] of sessions.entries()) {
    if (session.username === deletedUser.username) {
      sessions.delete(token);
    }
  }
  
  return res.json({ 
    message: "User deleted successfully",
    user: {
      username: deletedUser.username,
      role: deletedUser.role
    }
  });
});

app.post("/admin/users/:id/change-password", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body || {};
  
  if (!newPassword) {
    return res.status(400).json({ message: "New password is required" });
  }
  
  const users = await readUsers();
  const user = users.find(u => u.id === id);
  
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }
  
  const salt = generateSalt();
  const passwordHash = hashPassword(newPassword, salt);
  
  user.salt = salt;
  user.passwordHash = passwordHash;
  user.updatedAt = new Date().toISOString();
  
  await saveUsers(users);
  
  return res.json({ message: "Password updated successfully" });
});

// IP Rotation management
app.get("/admin/ip-rotation", requireAuth, requireAdmin, async (req, res) => {
  const ipData = await readIPRotation();
  return res.json(ipData);
});

app.post("/admin/ip-rotation", requireAuth, requireAdmin, async (req, res) => {
  const { proxies } = req.body || {};
  
  if (!Array.isArray(proxies)) {
    return res.status(400).json({ message: "Proxies must be an array" });
  }
  
  const ipData = {
    proxies: proxies.map(proxy => typeof proxy === 'string' ? proxy.trim() : proxy),
    currentIndex: 0,
    updatedAt: new Date().toISOString()
  };
  
  await saveIPRotation(ipData);
  ipRotationCache.clear();
  
  return res.json({ 
    message: "IP rotation configuration updated",
    proxies: ipData.proxies.length
  });
});

// Rate limit management
app.get("/admin/rate-limits", requireAuth, requireAdmin, async (req, res) => {
  const rateLimits = await readRateLimits();
  return res.json(rateLimits);
});

app.post("/admin/rate-limits/reset", requireAuth, requireAdmin, async (req, res) => {
  const { username } = req.body || {};
  
  const rateLimits = await readRateLimits();
  
  if (username) {
    delete rateLimits.limits[username];
  } else {
    rateLimits.limits = {};
  }
  
  await saveRateLimits(rateLimits);
  rateLimitCache.clear();
  
  return res.json({ message: "Rate limits reset successfully" });
});

// Job management endpoints
app.get("/api/jobs", requireAuth, async (req, res) => {
  const jobs = await readJobs();
  const filtered = req.user.role === "admin" 
    ? jobs 
    : jobs.filter((job) => job.owner === req.user.username);
  return res.json(filtered);
});

app.post("/api/jobs", requireAuth, async (req, res) => {
  const { subject, textBody = "", htmlBody = "", recipients, smtpUsername, smtpPassword } = req.body || {};
  
  if (!subject || !smtpUsername || !smtpPassword) {
    return res.status(400).json({ message: "subject, smtpUsername, and smtpPassword are required" });
  }
  
  const recipientList = normalizeRecipients(recipients);
  if (!recipientList.length) {
    return res.status(400).json({ message: "At least one recipient is required" });
  }
  
  // Check email rate limit
  const canSend = await checkEmailRateLimit(req.user.username);
  if (!canSend) {
    return res.status(429).json({ 
      message: `Email rate limit exceeded. Maximum ${EMAIL_RATE_LIMIT} emails per minute.`,
      retryAfter: 60
    });
  }
  
  const owner = req.user.role === "admin" && req.body.owner ? req.body.owner : req.user.username;
  const users = await readUsers();
  const ownerExists = users.some((entry) => entry.username === owner);
  
  if (!ownerExists) {
    return res.status(400).json({ message: `Unknown owner ${owner}` });
  }
  
  const jobs = await readJobs();
  const now = new Date().toISOString();
  const job = {
    id: uuid(),
    owner,
    subject,
    textBody,
    htmlBody,
    recipients: recipientList,
    smtpUsername,
    smtpPassword,
    status: "pending",
    createdAt: now,
    updatedAt: now,
  };
  
  jobs.push(job);
  await saveJobs(jobs);
  await addMailboxForUser(owner, smtpUsername, smtpPassword);
  
  return res.status(201).json(job);
});

app.delete("/api/jobs/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const jobs = await readJobs();
  
  const index = jobs.findIndex(job => 
    job.id === id && 
    (req.user.role === "admin" || job.owner === req.user.username)
  );
  
  if (index === -1) {
    return res.status(404).json({ message: "Job not found" });
  }
  
  const [removed] = jobs.splice(index, 1);
  await saveJobs(jobs);
  
  return res.json({ message: "Job deleted", job: removed });
});

app.post("/api/jobs/:id/send", requireAuth, async (req, res) => {
  const { id } = req.params;
  const jobs = await readJobs();
  const job = jobs.find((entry) => entry.id === id);
  
  if (!job) {
    return res.status(404).json({ message: "Job not found" });
  }
  
  if (req.user.role !== "admin" && job.owner !== req.user.username) {
    return res.status(403).json({ message: "You cannot trigger this job" });
  }
  
  // Check email rate limit
  const canSend = await checkEmailRateLimit(job.owner);
  if (!canSend) {
    return res.status(429).json({ 
      message: `Email rate limit exceeded. Maximum ${EMAIL_RATE_LIMIT} emails per minute.`,
      retryAfter: 60
    });
  }
  
  try {
    job.status = "sending";
    job.updatedAt = new Date().toISOString();
    await saveJobs(jobs);
    
    const result = await runPythonJob(job);
    
    job.status = "sent";
    job.lastSentAt = new Date().toISOString();
    job.updatedAt = new Date().toISOString();
    await saveJobs(jobs);
    
    return res.json({ 
      message: "Email dispatch complete", 
      job,
      output: result.output 
    });
  } catch (error) {
    job.status = "failed";
    job.error = error.message;
    job.updatedAt = new Date().toISOString();
    await saveJobs(jobs);
    
    return res.status(500).json({ 
      message: "Failed to send email", 
      details: error.message 
    });
  }
});

app.get("/admin/overview", requireAuth, requireAdmin, async (req, res) => {
  const [users, jobs, ipData, rateLimits] = await Promise.all([
    readUsers(),
    readJobs(),
    readIPRotation(),
    readRateLimits()
  ]);
  
  const stats = {
    totalUsers: users.length,
    activeUsers: users.filter(u => u.status === "active").length,
    suspendedUsers: users.filter(u => u.status === "suspended").length,
    totalJobs: jobs.length,
    pendingJobs: jobs.filter(j => j.status === "pending").length,
    sentJobs: jobs.filter(j => j.status === "sent").length,
    failedJobs: jobs.filter(j => j.status === "failed").length,
    proxyCount: ipData.proxies.length,
    activeRateLimits: Object.keys(rateLimits.limits || {}).length
  };
  
  return res.json({ users, jobs, ipRotation: ipData, rateLimits, stats });
});

app.get("/healthz", async (_req, res) => {
  try {
    await ensureDataFiles();
    res.json({ 
      status: "ok",
      timestamp: new Date().toISOString(),
      sessionCount: sessions.size
    });
  } catch (error) {
    res.status(500).json({ 
      status: "error", 
      details: error.message 
    });
  }
});

// Initialize server
ensureDataFiles()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Server listening on http://localhost:${PORT}`);
      console.log(`📁 Data directory: ${dataDir}`);
      console.log(`⚡ Rate limit: ${RATE_LIMIT_MAX_REQUESTS} requests/minute`);
      console.log(`📧 Email rate limit: ${EMAIL_RATE_LIMIT} emails/minute`);
    });
  })
  .catch((error) => {
    console.error("Failed to initialize storage", error);
    process.exit(1);
  });