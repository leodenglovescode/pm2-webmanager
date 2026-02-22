#!/usr/bin/env node
const express = require('express');
const pm2 = require('pm2');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { exec } = require('child_process');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const argon2 = require('argon2');
const otplib = require('otplib');
const { authenticator } = otplib;
const qrcode = require('qrcode');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3434;

// Dedicated config directory in user's home (essential for NPX/Global install)
const CONFIG_DIR = path.join(os.homedir(), '.pm2-webmanager');
if (!fs.existsSync(CONFIG_DIR)) fs.mkdirSync(CONFIG_DIR, { recursive: true });

const AUTH_FILE = path.join(CONFIG_DIR, 'auth.json');
const SESSION_SECRET = process.env.SESSION_SECRET || 'pm2-secret-key-123456789';

// Persistent SQLite session store (stored in home dir)
app.use(session({
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: CONFIG_DIR }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        httpOnly: true,
        sameSite: 'lax'
    }
}));

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to PM2
pm2.connect((err) => {
    if (err) {
        console.error(err);
        process.exit(2);
    }
});

// Authentication Middleware
const authGuard = (req, res, next) => {
    if (req.session.userId && (!req.session.needs2FA || req.session.isVerified2FA)) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized. Please log in.' });
};

// --- AUTH API ---

// App config check
app.get('/api/config', (req, res) => {
    const isRegistered = fs.existsSync(AUTH_FILE);
    res.json({ 
        isRegistered,
        isLoggedIn: !!req.session.userId,
        needs2FA: !!req.session.needs2FA && !req.session.isVerified2FA
    });
});

// One-time registration
app.post('/api/register', async (req, res) => {
    if (fs.existsSync(AUTH_FILE)) {
        return res.status(403).json({ error: 'Registration is already locked.' });
    }
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    try {
        const hash = await argon2.hash(password);
        const data = { username, passwordHash: hash, t2faEnabled: false };
        fs.writeFileSync(AUTH_FILE, JSON.stringify(data, null, 2));
        res.json({ success: true, message: 'Admin account created successfully. Please log in.' });
    } catch (err) {
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    if (!fs.existsSync(AUTH_FILE)) return res.status(404).json({ error: 'App not configured yet.' });
    const { username, password } = req.body;
    const authData = JSON.parse(fs.readFileSync(AUTH_FILE));

    if (username !== authData.username) return res.status(401).json({ error: 'Invalid credentials' });

    try {
        if (await argon2.verify(authData.passwordHash, password)) {
            req.session.userId = username;
            if (authData.t2faEnabled) {
                req.session.needs2FA = true;
                req.session.isVerified2FA = false;
                return res.json({ success: true, needs2FA: true });
            }
            req.session.isVerified2FA = false;
            res.json({ success: true, needs2FA: false });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Login error' });
    }
});

// Verify 2FA
app.post('/api/verify-otp', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Session expired' });
    const { token } = req.body;
    const authData = JSON.parse(fs.readFileSync(AUTH_FILE));
    
    if (!authData.t2faEnabled) return res.status(400).json({ error: '2FA not enabled' });
    
    const isValid = authenticator.check(token, authData.t2faSecret);
    if (isValid) {
        req.session.isVerified2FA = true;
        req.session.needs2FA = false;
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid verification code' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// 2FA Setup (Only accessible when logged in)
app.get('/api/2fa/setup', authGuard, async (req, res, next) => {
    try {
        const authData = JSON.parse(fs.readFileSync(AUTH_FILE));
        if (authData.t2faEnabled) return res.status(400).json({ error: '2FA already enabled' });
        
        // Ensure we have a valid secret and generator
        const secret = authenticator.generateSecret();
        const otpauth = authenticator.keyuri(authData.username, 'PM2 Monitor', secret);
        const qr = await qrcode.toDataURL(otpauth);
        
        // Temporarily store secret in session
        req.session.temp2FASecret = secret;
        res.json({ qr, secret });
    } catch (err) {
        next(err);
    }
});

app.post('/api/2fa/enable', authGuard, (req, res) => {
    const { token } = req.body;
    const secret = req.session.temp2FASecret;
    if (!secret) return res.status(400).json({ error: 'Setup 2FA first' });

    if (authenticator.check(token, secret)) {
        const authData = JSON.parse(fs.readFileSync(AUTH_FILE));
        authData.t2faEnabled = true;
        authData.t2faSecret = secret;
        fs.writeFileSync(AUTH_FILE, JSON.stringify(authData, null, 2));
        delete req.session.temp2FASecret;
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'Invalid token' });
    }
});

app.post('/api/2fa/disable', authGuard, (req, res) => {
    const authData = JSON.parse(fs.readFileSync(AUTH_FILE));
    authData.t2faEnabled = false;
    delete authData.t2faSecret;
    fs.writeFileSync(AUTH_FILE, JSON.stringify(authData, null, 2));
    res.json({ success: true });
});

// --- PROTECTED PM2 API ---

app.get('/api/list', authGuard, (req, res) => {
    pm2.list((err, list) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(list.map(p => ({
            id: p.pm_id,
            name: p.name,
            status: p.pm2_env.status,
            cpu: p.monit.cpu,
            memory: p.monit.memory,
            uptime: p.pm2_env.pm_uptime,
            restarts: p.pm2_env.restart_time,
            out: p.pm2_env.pm_out_log_path,
            err: p.pm2_env.pm_err_log_path
        })));
    });
});

app.get('/api/logs/:id', authGuard, (req, res) => {
    const id = req.params.id;
    const type = req.query.type || 'out';
    const limit = parseInt(req.query.limit) || 500;

    pm2.describe(id, (err, list) => {
        if (err || list.length === 0) return res.status(500).json({ error: 'Process not found' });
        const logPath = type === 'err' ? list[0].pm2_env.pm_err_log_path : list[0].pm2_env.pm_out_log_path;
        exec(`tail -n ${limit} ${logPath}`, (err, stdout) => {
            if (err) return res.status(500).json({ error: 'Failed to read logs' });
            res.json({ logs: stdout, type, limit });
        });
    });
});

app.post('/api/restart/:id', authGuard, (req, res) => {
    pm2.restart(req.params.id, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.post('/api/stop/:id', authGuard, (req, res) => {
    pm2.stop(req.params.id, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.post('/api/start/:id', authGuard, (req, res) => {
    pm2.start(req.params.id, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.post('/api/add', authGuard, (req, res) => {
    const { script, name } = req.body;
    
    // Security: Validate script and name to mitigate PM2 ReDoS vulnerability
    // We only allow alphanumeric, dots, slashes, underscores, and hyphens
    const safePattern = /^[a-zA-Z0-9.\/_-]+$/;
    if (!script || !safePattern.test(script)) {
        return res.status(400).json({ error: "Invalid script path. Only alphanumeric, dots, slashes, underscores, and hyphens allowed." });
    }
    if (name && !safePattern.test(name)) {
        return res.status(400).json({ error: "Invalid process name. Only alphanumeric, dots, slashes, underscores, and hyphens allowed." });
    }

    pm2.start({ script, name: name || path.basename(script) }, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// Final Error Handling (Prevents returning HTML when an error occurs)
app.use((err, req, res, next) => {
    console.error("Global Error Handler Catching Error:", err);
    res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
});

app.listen(PORT, () => {
    console.log(`PM2 Web Manager running on http://localhost:${PORT}`);
});
