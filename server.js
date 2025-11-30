import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import sqlite3 from 'sqlite3';
import argon2 from 'argon2';
import path from 'path';
import { fileURLToPath } from 'url';
import { body, validationResult } from 'express-validator';
import crypto from 'crypto';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import csurf from 'csurf';
import rateLimit from 'express-rate-limit';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const db = new sqlite3.Database('vault_secure.db');

const PORT = 7777;
const ENCRYPTION_ALGO = 'aes-256-gcm';

const SESSION_SECRET = process.env.SESSION_SECRET;

if (!SESSION_SECRET) {
    console.error("FATAL ERROR: SESSION_SECRET is missing. Create a .env file.");
    process.exit(1);
}

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https://www.w3.org"],
        },
    },
}));

app.use(rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: "Too many requests"
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 't1gs_session', 
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        maxAge: 60 * 60 * 1000
    }
}));

const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS vault (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        category TEXT DEFAULT 'web', 
        url TEXT NOT NULL,
        username TEXT NOT NULL,
        password_encrypted TEXT NOT NULL,
        iv TEXT NOT NULL,
        auth_tag TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);
});

function deriveCryptoKey(masterPassword) {
    return crypto.scryptSync(masterPassword, 't1gs-static-salt', 32);
}

function encryptData(text, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ENCRYPTION_ALGO, key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
        content: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64')
    };
}

function decryptData(encryptedObj, key) {
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGO, key, Buffer.from(encryptedObj.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(encryptedObj.tag, 'base64'));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedObj.content, 'base64')), decipher.final()]);
    return decrypted.toString('utf8');
}

function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    next();
}

app.get('/', (req, res) => res.redirect(req.session.userId ? '/vault' : '/login'));

app.get('/login', (req, res) => {
    try {
        const tpl = fs.readFileSync(path.join(__dirname, 'views', 'login.html'), 'utf8');
        res.send(tpl.replace('id="csrfInput"', `id="csrfInput" value="${req.csrfToken()}"`));
    } catch (e) { res.status(500).send("View error"); }
});

app.post('/login',
    body('username').trim().escape(),
    body('password').trim(),
    (req, res) => {
        const { username, password } = req.body;
        db.get('SELECT id, password_hash FROM users WHERE username = ?', [username], async (err, user) => {
            if (err || !user) return res.redirect('/login?error=Invalid Credentials');
            const valid = await argon2.verify(user.password_hash, password);
            if (!valid) return res.redirect('/login?error=Invalid Credentials');

            req.session.userId = user.id;
            req.session.username = username;
            req.session.encryptionKey = deriveCryptoKey(password).toString('hex');
            res.redirect('/vault');
        });
    }
);

app.get('/register', (req, res) => {
    try {
        const tpl = fs.readFileSync(path.join(__dirname, 'views', 'register.html'), 'utf8');
        res.send(tpl.replace('id="csrfInput"', `id="csrfInput" value="${req.csrfToken()}"`));
    } catch (e) { res.status(500).send("View error"); }
});

app.post('/register',
    body('username').trim().isLength({ min: 3 }).escape(),
    body('password').isLength({ min: 8 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.redirect('/register?error=Password too short');

        try {
            const hash = await argon2.hash(req.body.password);
            db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [req.body.username, hash], (err) => {
                if (err) return res.redirect('/register?error=Username taken');
                res.redirect('/login?success=Account Created');
            });
        } catch (e) { res.status(500).send('Error'); }
    }
);

app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/vault', requireAuth, (req, res) => {
    try {
        const tpl = fs.readFileSync(path.join(__dirname, 'views', 'vault.html'), 'utf8');
        res.send(tpl.replace('<!--CSRF-->', `<meta name="csrf-token" content="${req.csrfToken()}">`));
    } catch (e) { res.status(500).send("View error"); }
});

app.get('/api/vault', requireAuth, (req, res) => {
    db.all('SELECT id, category, url, username FROM vault WHERE user_id = ? ORDER BY id DESC', [req.session.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ items: rows, user: req.session.username });
    });
});

app.get('/api/vault/:id/password', requireAuth, (req, res) => {
    db.get('SELECT * FROM vault WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId], (err, row) => {
        if (!row) return res.status(404).json({ error: 'Not found' });
        try {
            const key = Buffer.from(req.session.encryptionKey, 'hex');
            const decrypted = decryptData({ content: row.password_encrypted, iv: row.iv, tag: row.auth_tag }, key);
            res.json({ password: decrypted });
        } catch (e) { res.status(500).json({ error: 'Decryption failed' }); }
    });
});

app.post('/api/vault', requireAuth, 
    body('url').trim(), 
    body('username').trim(), 
    body('password').notEmpty(),
    body('category').trim(),
    (req, res) => {
        const { url, username, password, category } = req.body;
        const key = Buffer.from(req.session.encryptionKey, 'hex');
        try {
            const enc = encryptData(password, key);
            db.run('INSERT INTO vault (user_id, category, url, username, password_encrypted, iv, auth_tag) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [req.session.userId, category || 'web', url, username, enc.content, enc.iv, enc.tag],
                function(err) {
                    if (err) return res.status(500).json({ error: 'DB Error' });
                    res.json({ success: true, id: this.lastID });
                }
            );
        } catch (e) { res.status(500).json({ error: 'Crypto Error' }); }
    }
);

app.put('/api/vault/:id', requireAuth,
    body('url').trim(),
    body('username').trim(),
    body('category').trim(),
    (req, res) => {
        const { url, username, password, category } = req.body;
        const id = req.params.id;
        const key = Buffer.from(req.session.encryptionKey, 'hex');

        if (password && password.length > 0) {
            try {
                const enc = encryptData(password, key);
                db.run('UPDATE vault SET category=?, url=?, username=?, password_encrypted=?, iv=?, auth_tag=? WHERE id=? AND user_id=?',
                    [category, url, username, enc.content, enc.iv, enc.tag, id, req.session.userId],
                    function(err) {
                        if (err) return res.status(500).json({ error: 'DB Error' });
                        res.json({ success: true });
                    }
                );
            } catch (e) { res.status(500).json({ error: 'Crypto Error' }); }
        } else {
            db.run('UPDATE vault SET category=?, url=?, username=? WHERE id=? AND user_id=?',
                [category, url, username, id, req.session.userId],
                function(err) {
                    if (err) return res.status(500).json({ error: 'DB Error' });
                    res.json({ success: true });
                }
            );
        }
    }
);

app.delete('/api/vault/:id', requireAuth, (req, res) => {
    db.run('DELETE FROM vault WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId], (err) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') return res.status(403).send('Invalid CSRF Token');
    res.status(500).send('Server Error');
});

app.listen(PORT, () => console.log(`T1GS Vault running on http://localhost:${PORT}`));