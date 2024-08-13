const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-secret-key';
const expiresIn = '1h';

// Função para criar um token JWT
function createToken(payload) {
    return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Função para verificar um token JWT
function verifyToken(token) {
    try {
        return jwt.verify(token, SECRET_KEY);
    } catch (err) {
        return false;
    }
}

// Função para verificar se o usuário existe no db.json
function isAuthenticated({ username, password }) {
    const db = JSON.parse(fs.readFileSync('db.json', 'UTF-8'));
    return db.username === username && db.password === password;
}

// Middleware para parsear JSON
app.use(bodyParser.json());

// Endpoint de login para autenticação
app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;

    if (isAuthenticated({ username, password })) {
        const token = createToken({ username });
        return res.status(200).json({ access_token: token });
    }

    return res.status(401).json({ message: 'Credenciais inválidas' });
});

// Middleware de autenticação JWT
app.use((req, res, next) => {
    if (req.path === '/auth/login') {
        next();
    } else {
        const authHeader = req.headers.authorization;
        if (!authHeader || authHeader.split(' ')[0] !== 'Bearer') {
            return res.status(401).json({ message: 'Token de acesso não fornecido ou inválido' });
        }
        const token = authHeader.split(' ')[1];
        const verified = verifyToken(token);
        if (!verified) {
            return res.status(401).json({ message: 'Token inválido' });
        }
        next();
    }
});

// Exemplo de um endpoint protegido
app.get('/protected', (req, res) => {
    res.status(200).json({ message: 'Você acessou um endpoint protegido!' });
});

// Inicia o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
