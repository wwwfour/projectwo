// server.js

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bodyParser = require('body-parser');
const passport = require('passport');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;
const sqlite3 = require('sqlite3').verbose();
const ejs = require('ejs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const flash = require('express-flash');

app.use(session({
    secret: 'your-secret-key',
    resave: true,
    saveUninitialized: true
}));

app.use(flash());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use(session({ secret: 'your-secret-key', resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

const db = new sqlite3.Database('mydatabase.db');

passport.use(new LocalStrategy(
    (username, password, done) => {
        const sql = 'SELECT * FROM users WHERE username = ? AND password = ?';
        db.get(sql, [username, password], (err, row) => {
            if (err) {
                return done(err);
            }

            if (!row) {
                return done(null, false, { message: 'Invalid username or password' });
            }

            return done(null, row);
        });
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    const sql = 'SELECT * FROM users WHERE id = ?';
    db.get(sql, [id], (err, row) => {
        if (err) {
            return done(err);
        }

        if (!row) {
            return done(null, false, { message: 'User not found' });
        }

        return done(null, row);
    });
});

const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
};

wss.on('connection', (ws) => {
    console.log('Yeni bir WebSocket bağlantısı kuruldu.');

    ws.on('message', (message) => {
        try {
            const parsedMessage = JSON.parse(message);

            // Kullanıcı adı ve içerik bilgilerini al
            const senderUsername = parsedMessage.username;
            const content = parsedMessage.content;

            // Gelen mesajı diğer bağlantılara gönder
            wss.clients.forEach((client) => {
                if (client !== ws && client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({ username: senderUsername, content: content }));
                }
            });
        } catch (error) {
            console.error('Hatalı mesaj formatı:', message);
        }
    });

    ws.on('close', () => {
        console.log('WebSocket bağlantısı kapatıldı.');
    });
});

const port = process.env.PORT || 3000;
server.listen(port, () => {
    console.log(`Sunucu ${port} portunda çalışıyor`);
});

app.post('/addUser', (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, password], (err) => {
        if (err) {
            console.error(err.message);
            res.status(500).send('Internal Server Error');
        } else {
            console.log('Kullanıcı başarıyla eklendi.');
            res.redirect('/');
        }
    });
});

app.post('/login',
    passport.authenticate('local', {
        successRedirect: '/chat',
        failureRedirect: '/login',
        failureFlash: true
    })
);

app.get('/', isAuthenticated, (req, res) => {
    res.render('layout', { title: 'Ana Sayfa', body: 'Ana sayfa içeriği buraya gelecek.', isAuthenticated: req.isAuthenticated(), user: req.user });
});

app.get('/chat', isAuthenticated, (req, res) => {
    res.render('chat', { title: 'Chat', isAuthenticated: req.isAuthenticated(), user: req.user });
});

app.get('/addUserForm', isAuthenticated, (req, res) => {
    res.render('addUserForm', { title: 'Kullanıcı Ekle', isAuthenticated: req.isAuthenticated(), user: req.user });
});

app.get('/users', isAuthenticated, (req, res) => {
    res.render('users', { title: 'Kullanıcılar', isAuthenticated: req.isAuthenticated(), user: req.user });
});

app.get('/login', (req, res) => {
    res.render('login', { title: 'Giriş Yap', isAuthenticated: req.isAuthenticated(), user: req.user });
});
