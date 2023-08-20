const fs = require('fs');
const jsonServer = require('json-server');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./database.json');
let userdb = JSON.parse(fs.readFileSync('./usuarios.json', 'UTF-8'));

server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = '123456789';

function createToken(payload, expiresIn = '12h') {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

function verifyToken(token) {
    return jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ? decode : err);
}

function isEmailExist(email) {
    return userdb.usuarios.findIndex(user => user.email === email) !== -1;
}

function isAuthenticated({ email, senha }) {
    return userdb.usuarios.findIndex(user => user.email === email && user.senha === senha) !== -1;
}

server.post('/auth/register', (req, res) => {
    const { email, senha } = req.body;

    if (isEmailExist(email) === true) {
        const status = 401;
        const message = 'Email já cadastrado!';
        res.status(status).json({ status, message });
        return;
    }

    fs.readFile('./usuarios.json', (err, data) => {
        if (err) {
            const status = 401;
            const message = err;
            res.status(status).json({ status, message });
            return;
        }

        const json = JSON.parse(data.toString());

        const last_item_id = json.usuarios.length ? json.usuarios[json.usuarios.length - 1].id : 0;

        json.usuarios.push({ id: last_item_id + 1, email: email, senha: senha });
        fs.writeFile('./usuarios.json', JSON.stringify(json), (err) => {
            if (err) {
                const status = 401;
                const message = err;
                res.status(status).json({ status, message });
                return;
            }
        });
        userdb = json;
    });

    const access_token = createToken({ email, senha });
    const message = 'Usuário cadastrado com sucesso!';
    res.status(200).json({ access_token, message });

});

server.post('/auth/login', (req, res) => {
    const { email, senha } = req.body;
    if (!isAuthenticated({ email, senha })) {
        const status = 401;
        const message = 'Email ou senha inválidos!';
        res.status(status).json({ status, message });
        return;
    }
    const access_token = createToken({ email, senha });
    let usuario = { ...userdb.usuarios.find(user => user.email === email && user.senha === senha) };
    delete usuario.senha;
    res.status(200).json({ access_token, usuario });
});

server.get('/auth/validate', (res) => {
    res.status(200).json([
        {
            "id": 1,
            "nome": "Administrador",
            "email": "maken@teste.com"
        }
    ]);
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
    if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
        const status = 401;
        const message = 'Token inválido!';
        res.status(status).json({ status, message });
        return;
    }
    try {
        let verifyTokenResult;
        verifyTokenResult = verifyToken(req.headers.authorization.split(' ')[1]);
        if (verifyTokenResult instanceof Error) {
            const status = 401;
            const message = 'Token de acesso não encontrado!';
            res.status(status).json({ status, message });
            return;
        }
        next();
    } catch (err) {
        const status = 401;
        const message = 'Token de acesso recusado!';
        res.status(status).json({ status, message });
    }
});

server.use(router);

server.listen(8000, () => {
    console.log('Servidor rodando em http://localhost:8000');
});
