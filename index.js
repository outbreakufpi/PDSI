import express from 'express'
import pkg from 'pg'
import dotenv from 'dotenv'
import cors from 'cors'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import swaggerUi from 'swagger-ui-express'
import { specs } from './swagger.js'
import expressLayouts from 'express-ejs-layouts'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcryptjs'
import cookieParser from 'cookie-parser'
import session from 'express-session'
import nodemailer from 'nodemailer'

const { Pool } = pkg
const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

// Carregar variáveis de ambiente
dotenv.config()

const app = express()
const port = process.env.PORT || 3001

// Configuração do banco de dados
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
})

// Configuração do EJS
app.set('view engine', 'ejs')
app.set('views', join(__dirname, 'views'))
app.use(expressLayouts)
app.set('layout', 'layout')

// Middleware
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))
app.use(cookieParser())
app.use(session({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000 // 24 horas
  }
}))

// Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs))

// Configuração do nodemailer para envio de e-mails
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Rota inicial
app.get('/', (req, res) => {
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1]
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET)
      res.redirect('/dashboard')
    } catch (error) {
      res.redirect('/login')
    }
  } else {
    res.redirect('/login')
  }
})

// Rota de logout
app.get('/logout', (req, res) => {
    // Limpar a sessão
    req.session.destroy((err) => {
        if (err) {
            console.error('Erro ao fazer logout:', err);
        }
        // Limpar o cookie
        res.clearCookie('token');
        // Redirecionar para a página de login
        res.redirect('/login');
    });
});

// Middleware para verificar autenticação em todas as rotas protegidas
app.use(async (req, res, next) => {
    // Rotas públicas que não precisam de autenticação
    const publicRoutes = [
        '/login',
        '/registro',
        '/esqueci-senha',
        '/redefinir-senha',
        '/api/auth/login',
        '/api/auth/registro',
        '/api/auth/recuperar-senha',
        '/api/auth/redefinir-senha'
    ];

    if (publicRoutes.includes(req.path)) {
        return next();
    }

    const token = req.session?.token || req.headers.authorization?.split(' ')[1] || req.cookies?.token;
    
    if (!token) {
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ error: 'Não autorizado' });
        }
        return res.redirect('/login');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Buscar informações do usuário no banco de dados
        const userResult = await pool.query(
            'SELECT id, nome, matricula, email, tipo_usuario FROM usuarios WHERE id = $1',
            [decoded.id]
        );
        
        if (userResult.rows.length === 0) {
            if (req.path.startsWith('/api/')) {
                return res.status(401).json({ error: 'Usuário não encontrado' });
            }
            return res.redirect('/login');
        }

        // Adicionar o usuário ao objeto de requisição
        req.user = {
            id: userResult.rows[0].id,
            nome: userResult.rows[0].nome,
            matricula: userResult.rows[0].matricula,
            email: userResult.rows[0].email,
            tipo: userResult.rows[0].tipo_usuario
        };

        // Passar o usuário para todas as views
        res.locals.user = req.user;
        
        next();
    } catch (error) {
        console.error('Erro ao verificar token:', error);
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ error: 'Token inválido' });
        }
        return res.redirect('/login');
    }
});

// Rotas de autenticação
app.post('/api/auth/login', async (req, res) => {
  const { matricula, senha } = req.body
  try {
    console.log('Tentativa de login:', { matricula })
    
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE matricula = $1',
      [matricula]
    )
    
    console.log('Resultado da busca:', result.rows[0])
    
    if (result.rows.length === 0) {
      console.log('Usuário não encontrado')
      return res.status(401).json({ error: 'Credenciais inválidas' })
    }
    
    const user = result.rows[0]
    console.log('Senha fornecida:', senha)
    console.log('Hash armazenado:', user.senha)
    
    const senhaValida = await bcrypt.compare(senha, user.senha)
    console.log('Senha válida:', senhaValida)
    
    if (!senhaValida) {
      console.log('Senha inválida')
      return res.status(401).json({ error: 'Credenciais inválidas' })
    }

    const token = jwt.sign(
      { id: user.id, tipo: user.tipo_usuario },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    )

    // Configurar sessão
    req.session.user = {
      id: user.id,
      tipo: user.tipo_usuario,
      nome: user.nome
    }
    req.session.token = token

    // Configurar cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000 // 24 horas
    })

    console.log('Tipo de usuário:', user.tipo_usuario) // Debug

    res.json({ 
      token, 
      user: { 
        id: user.id, 
        tipo: user.tipo_usuario,
        nome: user.nome
      } 
    })
  } catch (error) {
    console.error('Erro no login:', error)
    res.status(500).json({ error: 'Erro ao fazer login' })
  }
})

app.get('/registro', (req, res) => {
  res.render('registro', { title: 'Registro' })
})

app.get('/esqueci-senha', (req, res) => {
  res.render('esqueci-senha', { title: 'Recuperar Senha' })
})

app.post('/api/auth/registro', async (req, res) => {
  const { matricula, nome, email, senha } = req.body
  try {
    // Verificar se matrícula ou email já existem
    const userExists = await pool.query(
      'SELECT * FROM usuarios WHERE matricula = $1 OR email = $2',
      [matricula, email]
    )
    
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Matrícula ou email já cadastrados' })
    }

    // Hash da senha
    const salt = await bcrypt.genSalt(10)
    const senhaHash = await bcrypt.hash(senha, salt)

    // Criar novo usuário (por padrão é tipo 'usuario')
    const result = await pool.query(
      'INSERT INTO usuarios (matricula, nome, email, senha, tipo_usuario) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [matricula, nome, email, senhaHash, 'usuario']
    )
    
    res.status(201).json({ message: 'Usuário criado com sucesso' })
  } catch (error) {
    console.error('Erro ao criar usuário:', error)
    res.status(500).json({ error: 'Erro ao criar usuário' })
  }
})

app.post('/api/auth/recuperar-senha', async (req, res) => {
    try {
        const { matricula, email } = req.body;
        
        // Buscar usuário no banco de dados
        const result = await pool.query(
            'SELECT * FROM usuarios WHERE matricula = $1 AND email = $2',
            [matricula, email]
        );
        
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Usuário não encontrado' });
        }

        const user = result.rows[0];

        // Gerar token de recuperação
        const token = jwt.sign(
            { id: user.id },
            process.env.JWT_SECRET || 'chave_secreta_temporaria',
            { expiresIn: '1h' }
        );

        // Criar link de recuperação
        const resetLink = `${process.env.BASE_URL || 'http://localhost:3001'}/redefinir-senha?token=${token}`;

        // Configurar e-mail
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Recuperação de Senha - Sistema de Reservas',
            html: `
                <h1>Recuperação de Senha</h1>
                <p>Olá ${user.nome},</p>
                <p>Você solicitou a recuperação de senha. Clique no link abaixo para redefinir sua senha:</p>
                <p><a href="${resetLink}">Redefinir Senha</a></p>
                <p>Este link expira em 1 hora.</p>
                <p>Se você não solicitou esta recuperação, ignore este e-mail.</p>
            `
        };

        // Enviar e-mail
        await transporter.sendMail(mailOptions);
        console.log('E-mail de recuperação enviado com sucesso');

        res.json({ message: 'E-mail de recuperação enviado com sucesso' });
    } catch (error) {
        console.error('Erro ao processar recuperação de senha:', error);
        res.status(500).json({ error: 'Erro ao processar recuperação de senha' });
    }
});

// Rota para exibir a página de redefinição de senha
app.get('/redefinir-senha', (req, res) => {
    const { token } = req.query;
    if (!token) {
        return res.redirect('/esqueci-senha');
    }
    res.render('redefinir-senha', { token });
});

// Rota para processar a redefinição de senha
app.post('/api/auth/redefinir-senha', async (req, res) => {
    try {
        const { token, novaSenha } = req.body;

        // Verificar token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Hash da nova senha
        const hashedPassword = await bcrypt.hash(novaSenha, 10);

        // Atualizar senha no banco de dados
        const result = await pool.query(
            'UPDATE usuarios SET senha = $1 WHERE id = $2 RETURNING *',
            [hashedPassword, decoded.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Token inválido ou expirado' });
        }

        res.json({ message: 'Senha redefinida com sucesso' });
    } catch (error) {
        console.error('Erro ao redefinir senha:', error);
        res.status(400).json({ error: 'Token inválido ou expirado' });
    }
});

// Rotas da aplicação
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login' })
})

app.get('/dashboard', async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT id, nome, matricula, email, tipo_usuario FROM usuarios WHERE id = $1',
      [req.user.id]
    )
    
    if (userResult.rows.length === 0) {
      return res.redirect('/login')
    }
    
    const user = {
      id: userResult.rows[0].id,
      nome: userResult.rows[0].nome,
      matricula: userResult.rows[0].matricula,
      email: userResult.rows[0].email,
      tipo: userResult.rows[0].tipo_usuario
    };

    res.render('dashboard', { 
      title: 'Dashboard', 
      user,
      error: null
    })
  } catch (error) {
    console.error('Erro ao carregar dashboard:', error)
    res.render('dashboard', { 
      title: 'Dashboard', 
      user: req.session.user,
      error: 'Erro ao carregar dados do usuário'
    })
  }
})

// Rotas protegidas para admin
app.get('/admin/salas', async (req, res) => {
  if (!req.user || req.user.tipo !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  try {
    const result = await pool.query('SELECT * FROM salas ORDER BY nome');
    res.render('admin/salas', { 
      title: 'Gerenciar Salas', 
      salas: result.rows,
      user: req.user
    });
  } catch (error) {
    console.error('Erro ao carregar salas:', error);
    res.status(500).render('admin/salas', { 
      title: 'Gerenciar Salas', 
      salas: [],
      error: 'Erro ao carregar salas',
      user: req.user
    });
  }
});

app.get('/admin/reservas', async (req, res) => {
  if (!req.user || req.user.tipo !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado' });
  }
  try {
    const result = await pool.query(`
      SELECT r.*, s.nome as sala_nome, u.nome as usuario_nome 
      FROM reservas r 
      JOIN salas s ON r.sala_id = s.id 
      JOIN usuarios u ON r.usuario_id = u.id 
      ORDER BY r.data_inicio DESC
    `);
    res.render('admin/reservas', { 
      title: 'Gerenciar Reservas', 
      reservas: result.rows,
      user: req.user 
    });
  } catch (error) {
    console.error('Erro ao carregar reservas:', error);
    res.status(500).json({ error: 'Erro ao carregar reservas' });
  }
});

// Rota para a página de gerenciamento de feedbacks (apenas admin)
app.get('/admin/feedbacks', async (req, res) => {
    if (!req.user || req.user.tipo !== 'admin') {
        return res.status(403).render('error', { message: 'Acesso negado. Apenas administradores podem acessar esta página.' });
    }
    try {
        // A página JS fará a chamada à API /api/feedbacks para buscar os dados
        res.render('admin/feedbacks', {
            title: 'Gerenciar Feedbacks',
            userType: req.user.tipo,
            userName: req.user.nome
        });
    } catch (error) {
        console.error('Erro ao carregar página de feedbacks:', error);
        res.status(500).render('error', { message: 'Erro ao carregar a página de feedbacks.' });
    }
});

// Rotas para usuários comuns
app.get('/minhas-reservas', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.*, s.nome as sala_nome 
      FROM reservas r 
      JOIN salas s ON r.sala_id = s.id 
      WHERE r.usuario_id = $1 
      ORDER BY r.data_inicio DESC
    `, [req.user.id]);
    
    res.render('minhas-reservas', { 
      title: 'Minhas Reservas', 
      reservas: result.rows,
      user: req.user,
      userType: req.user.tipo
    });
  } catch (error) {
    console.error('Erro ao carregar reservas:', error);
    res.status(500).json({ error: 'Erro ao carregar reservas' });
  }
});

// Rotas das Views
app.get('/salas', async (req, res) => {
  try {
    const salas = await pool.query('SELECT * FROM salas')
    res.render('pages/sala/index', { 
      salas: salas.rows,
      title: 'Salas Disponíveis',
      user: req.user
    })
  } catch (error) {
    console.error('Erro:', error)
    res.status(500).send('Erro ao carregar a página')
  }
})

app.get('/reservas', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.*, s.nome as sala_nome, u.nome as usuario_nome 
      FROM reservas r 
      JOIN salas s ON r.sala_id = s.id 
      JOIN usuarios u ON r.usuario_id = u.id
      ORDER BY r.data_inicio DESC
    `)
    res.render('reservas', { 
      title: 'Reservas',
      reservas: result.rows,
      user: {
        id: req.user.id,
        tipo: req.user.tipo,
        nome: req.session?.user?.nome || ''
      }
    })
  } catch (error) {
    console.error('Erro:', error)
    res.status(500).send('Erro ao carregar reservas')
  }
})

app.get('/nova-reserva', async (req, res) => {
  try {
    const salas = await pool.query('SELECT * FROM salas')
    res.render('nova-reserva', { 
      salas: salas.rows,
      title: 'Nova Reserva',
      request: req
    })
  } catch (error) {
    console.error('Erro:', error)
    res.status(500).send('Erro ao carregar formulário')
  }
})

/**
 * @swagger
 * components:
 *   schemas:
 *     Usuario:
 *       type: object
 *       properties:
 *         id:
 *           type: integer
 *         nome:
 *           type: string
 *         email:
 *           type: string
 *         tipo:
 *           type: string
 *           enum: [admin, usuario]
 *     Sala:
 *       type: object
 *       properties:
 *         id:
 *           type: integer
 *         nome:
 *           type: string
 *         capacidade:
 *           type: integer
 *         recursos:
 *           type: array
 *           items:
 *             type: string
 *     Reserva:
 *       type: object
 *       properties:
 *         id:
 *           type: integer
 *         sala_id:
 *           type: integer
 *         usuario_id:
 *           type: integer
 *         data:
 *           type: string
 *           format: date
 *         horario_inicio:
 *           type: string
 *         horario_fim:
 *           type: string
 *         status:
 *           type: string
 *           enum: [pendente, confirmada, cancelada]
 *         observacoes:
 *           type: string
 */

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Realiza login no sistema
 *     tags: [Autenticação]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - senha
 *             properties:
 *               email:
 *                 type: string
 *               senha:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login realizado com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 user:
 *                   $ref: '#/components/schemas/Usuario'
 *       401:
 *         description: Credenciais inválidas
 */

/**
 * @swagger
 * /api/salas:
 *   get:
 *     summary: Lista todas as salas
 *     tags: [Salas]
 *     responses:
 *       200:
 *         description: Lista de salas
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Sala'
 */
app.get('/api/salas', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM salas ORDER BY nome');
        console.log('Salas encontradas:', result.rows); // Debug
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao listar salas:', error);
        res.status(500).json({ error: 'Erro ao listar salas' });
    }
});

/**
 * @swagger
 * /api/salas:
 *   post:
 *     summary: Cria uma nova sala
 *     tags: [Salas]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - nome
 *               - capacidade
 *             properties:
 *               nome:
 *                 type: string
 *               capacidade:
 *                 type: integer
 *               descricao:
 *                 type: string
 *     responses:
 *       201:
 *         description: Sala criada com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Sala'
 */
app.post('/api/salas', async (req, res) => {
    try {
        const { nome, capacidade, recursos } = req.body;
        console.log('Dados recebidos:', { nome, capacidade, recursos }); // Debug
        
        if (!nome || !capacidade) {
            return res.status(400).json({ error: 'Nome e capacidade são obrigatórios' });
        }
        
        console.log('Executando query de inserção...'); // Debug
        const result = await pool.query(
            'INSERT INTO salas (nome, capacidade, recursos) VALUES ($1, $2, $3) RETURNING *',
            [nome, capacidade, JSON.stringify(recursos)] // Convertendo array para JSON
        );
        console.log('Resultado da inserção:', result.rows[0]); // Debug
        
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Erro detalhado ao criar sala:', error); // Debug
        res.status(500).json({ error: 'Erro ao criar sala: ' + error.message });
    }
});

/**
 * @swagger
 * /api/reservas:
 *   get:
 *     summary: Lista todas as reservas
 *     tags: [Reservas]
 *     responses:
 *       200:
 *         description: Lista de reservas
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Reserva'
 */
app.get('/api/reservas', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.*, s.nome as sala_nome, u.nome as usuario_nome 
      FROM reservas r 
      JOIN salas s ON r.sala_id = s.id 
      JOIN usuarios u ON r.usuario_id = u.id
    `)
    res.json(result.rows)
  } catch (error) {
    console.error('Erro ao buscar reservas:', error)
    res.status(500).json({ error: 'Erro interno do servidor' })
  }
})

app.get('/api/reservas/minhas', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT r.*, s.nome as sala_nome 
            FROM reservas r 
            JOIN salas s ON r.sala_id = s.id 
            WHERE r.usuario_id = $1 
            ORDER BY r.data_inicio DESC
        `, [req.user.id]);
        
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao listar reservas do usuário:', error);
        res.status(500).json({ error: 'Erro ao listar reservas' });
    }
});

/**
 * @swagger
 * /api/reservas:
 *   post:
 *     summary: Cria uma nova reserva
 *     tags: [Reservas]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - sala_id
 *               - usuario_id
 *               - data_inicio
 *               - data_fim
 *               - motivo
 *             properties:
 *               sala_id:
 *                 type: integer
 *               usuario_id:
 *                 type: integer
 *               data_inicio:
 *                 type: string
 *                 format: date-time
 *               data_fim:
 *                 type: string
 *                 format: date-time
 *               motivo:
 *                 type: string
 *     responses:
 *       201:
 *         description: Reserva criada com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Reserva'
 *       400:
 *         description: Sala já está reservada neste período
 */
app.post('/api/reservas', async (req, res) => {
  const { sala_id, data_inicio, data_fim, motivo } = req.body;
  console.log('Requisição POST /api/reservas recebida. Dados:', req.body); // Log 1: Dados recebidos
  console.log('ID do usuário autenticado (req.user.id):', req.user ? req.user.id : 'Não autenticado'); // Log 2: ID do usuário

  try {
    // Validar se a data de início e fim são do mesmo dia
    const inicio = new Date(data_inicio);
    const fim = new Date(data_fim);
    
    console.log('Início (Date):', inicio, 'Fim (Date):', fim); // Log 3: Objetos Date

    if (inicio.toDateString() !== fim.toDateString()) {
      console.log('Erro de validação: A reserva deve ser feita para o mesmo dia.'); // Log 4: Erro de validação
      return res.status(400).json({ error: 'A reserva deve ser feita para o mesmo dia' });
    }

    // Validar horário comercial (8h às 18h)
    const horaInicio = inicio.getHours();
    const horaFim = fim.getHours();
    
    console.log('Hora Início:', horaInicio, 'Hora Fim:', horaFim); // Log 5: Horas extraídas

    if (horaInicio < 8 || horaInicio >= 18 || horaFim <= 8 || horaFim > 18) {
      console.log('Erro de validação: Fora do horário comercial.'); // Log 6: Erro de validação
      return res.status(400).json({ error: 'As reservas devem ser feitas entre 08:00 e 18:00' });
    }

    // Formatar as datas para o formato aceito pelo PostgreSQL
    // As variáveis dataFormatada, horaInicioFormatada, horaFimFormatada não são mais usadas na inserção direta, mas mantidas por contexto.
    const dataFormatada = inicio.toISOString().split('T')[0];
    const horaInicioFormatada = inicio.toTimeString().split(' ')[0];
    const horaFimFormatada = fim.toTimeString().split(' ')[0];
    console.log('Datas e Horas formatadas (não usadas na inserção direta):', { dataFormatada, horaInicioFormatada, horaFimFormatada }); // Log 7

    // Verificar se já existe reserva para o mesmo horário usando timestamps completos
    console.log('Verificando disponibilidade de sala para sala_id:', sala_id, 'de:', data_inicio, 'até:', data_fim); // Log 8: Antes da consulta de disponibilidade
    const verificarDisponibilidade = await pool.query(
      `SELECT * FROM reservas 
       WHERE sala_id = $1 
       AND status != 'cancelada'
       AND (data_inicio < $3::timestamp AND $2::timestamp < data_fim)
      `,
      [sala_id, data_inicio, data_fim] // Passa os timestamps completos diretamente
    );
    console.log('Resultado da verificação de disponibilidade (rows.length):', verificarDisponibilidade.rows.length); // Log 9: Resultado da disponibilidade

    if (verificarDisponibilidade.rows.length > 0) {
      console.log('Erro de validação: Sala já está reservada neste horário.'); // Log 10: Conflito de reserva
      return res.status(400).json({ error: 'Sala já está reservada neste horário' });
    }

    // Criar a reserva
    const valoresInsercao = [sala_id, req.user.id, data_inicio, data_fim, motivo, 'confirmada']; // Log 11: Valores para inserção
    console.log('Valores para inserção:', valoresInsercao); 
    const result = await pool.query(
      'INSERT INTO reservas (sala_id, usuario_id, data_inicio, data_fim, motivo, status) VALUES ($1, $2, $3::timestamp, $4::timestamp, $5, $6) RETURNING *',
      valoresInsercao
    );
    
    console.log('Reserva criada com sucesso. Dados da reserva:', result.rows[0]); // Log 12: Reserva criada
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao criar reserva (detalhes):', error); // Log 13: Erro detalhado no catch
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

/**
 * @swagger
 * /api/reservas/{id}/cancelar:
 *   put:
 *     summary: Cancela uma reserva
 *     tags: [Reservas]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID da reserva
 *     responses:
 *       200:
 *         description: Reserva cancelada com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Reserva'
 *       404:
 *         description: Reserva não encontrada
 */
app.put('/api/reservas/:id/cancelar', async (req, res) => {
  const { id } = req.params
  try {
    console.log('Tentando cancelar reserva:', id);
    console.log('Usuário atual:', req.user);

    // Verifica se a reserva existe
    const verificarReserva = await pool.query(
      'SELECT * FROM reservas WHERE id = $1',
      [id]
    )

    if (verificarReserva.rows.length === 0) {
      console.log('Reserva não encontrada');
      return res.status(404).json({ error: 'Reserva não encontrada' })
    }

    // Se o usuário não for admin, verifica se é o dono da reserva
    if (req.user.tipo !== 'admin') {
      if (verificarReserva.rows[0].usuario_id !== req.user.id) {
        console.log('Usuário não tem permissão para cancelar esta reserva');
        return res.status(403).json({ error: 'Você não tem permissão para cancelar esta reserva' })
      }
    }

    // Cancela a reserva
    const result = await pool.query(
      'UPDATE reservas SET status = $1 WHERE id = $2 RETURNING *',
      ['cancelada', id]
    )
    
    console.log('Reserva cancelada com sucesso:', result.rows[0]);
    res.json(result.rows[0])
  } catch (error) {
    console.error('Erro detalhado ao cancelar reserva:', error);
    res.status(500).json({ error: 'Erro ao cancelar reserva: ' + error.message })
  }
})

app.put('/api/salas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { nome, capacidade, recursos } = req.body;
        
        console.log('Dados recebidos para atualização:', { id, nome, capacidade, recursos }); // Debug
        
        if (!nome || !capacidade) {
            return res.status(400).json({ error: 'Nome e capacidade são obrigatórios' });
        }
        
        // Verificar se a sala existe
        const salaExistente = await pool.query('SELECT * FROM salas WHERE id = $1', [id]);
        if (salaExistente.rows.length === 0) {
            return res.status(404).json({ error: 'Sala não encontrada' });
        }
        
        // Converter recursos para JSON se for array
        const recursosJson = Array.isArray(recursos) ? JSON.stringify(recursos) : recursos;
        
        const result = await pool.query(
            'UPDATE salas SET nome = $1, capacidade = $2, recursos = $3 WHERE id = $4 RETURNING *',
            [nome, capacidade, recursosJson, id]
        );
        
        console.log('Resultado da atualização:', result.rows[0]); // Debug
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Erro ao atualizar sala:', error);
        res.status(500).json({ error: 'Erro ao atualizar sala: ' + error.message });
    }
});

app.delete('/api/salas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('DELETE FROM salas WHERE id = $1 RETURNING *', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Sala não encontrada' });
        }
        
        res.json({ message: 'Sala excluída com sucesso' });
    } catch (error) {
        console.error('Erro ao excluir sala:', error);
        res.status(500).json({ error: 'Erro ao excluir sala' });
    }
});

app.get('/api/salas/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT * FROM salas WHERE id = $1', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Sala não encontrada' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Erro ao buscar sala:', error);
        res.status(500).json({ error: 'Erro ao buscar sala' });
    }
});

app.get('/api/reservas/:id', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT r.*, s.nome as sala_nome, u.nome as usuario_nome 
             FROM reservas r 
             JOIN salas s ON r.sala_id = s.id 
             JOIN usuarios u ON r.usuario_id = u.id 
             WHERE r.id = $1`,
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Reserva não encontrada' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Erro ao buscar detalhes da reserva:', error);
        res.status(500).json({ error: 'Erro ao buscar detalhes da reserva' });
    }
});

/**
 * @swagger
 * /api/reservas/minhas:
 *   get:
 *     summary: Lista as reservas do usuário autenticado
 *     tags: [Reservas]
 *     responses:
 *       200:
 *         description: Lista de reservas do usuário
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Reserva'
 */

/**
 * @swagger
 * /api/salas/{id}:
 *   put:
 *     summary: Atualiza uma sala existente
 *     tags: [Salas]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID da sala
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - nome
 *               - capacidade
 *             properties:
 *               nome:
 *                 type: string
 *               capacidade:
 *                 type: integer
 *               recursos:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Sala atualizada com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Sala'
 *       404:
 *         description: Sala não encontrada
 */

/**
 * @swagger
 * /api/salas/{id}:
 *   delete:
 *     summary: Remove uma sala
 *     tags: [Salas]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID da sala
 *     responses:
 *       200:
 *         description: Sala removida com sucesso
 *       404:
 *         description: Sala não encontrada
 */

/**
 * @swagger
 * /api/salas/{id}:
 *   get:
 *     summary: Obtém detalhes de uma sala específica
 *     tags: [Salas]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID da sala
 *     responses:
 *       200:
 *         description: Detalhes da sala
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Sala'
 *       404:
 *         description: Sala não encontrada
 */

/**
 * @swagger
 * /api/reservas/{id}:
 *   get:
 *     summary: Obtém detalhes de uma reserva específica
 *     tags: [Reservas]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID da reserva
 *     responses:
 *       200:
 *         description: Detalhes da reserva
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Reserva'
 *       404:
 *         description: Reserva não encontrada
 */

// Endpoints do Dashboard
/**
 * @swagger
 * /api/dashboard/stats:
 *   get:
 *     summary: Retorna estatísticas do dashboard
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Estatísticas retornadas com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 totalReservas:
 *                   type: integer
 *                   description: Total de reservas do usuário
 *                 totalSalas:
 *                   type: integer
 *                   description: Total de salas no sistema
 *       401:
 *         description: Não autorizado
 *       500:
 *         description: Erro interno do servidor
 */
app.get('/api/dashboard/stats', async (req, res) => {
    try {
        let reservasQuery;
        if (req.user.tipo === 'admin') {
            // Se for admin, conta todas as reservas
            reservasQuery = 'SELECT COUNT(*) FROM reservas';
        } else {
            // Se for usuário comum, conta apenas suas reservas
            reservasQuery = 'SELECT COUNT(*) FROM reservas WHERE usuario_id = $1';
        }

        // Buscar total de reservas
        const reservasResult = await pool.query(
            reservasQuery,
            req.user.tipo === 'admin' ? [] : [req.user.id]
        );

        // Buscar total de salas
        const salasResult = await pool.query(
            'SELECT COUNT(*) FROM salas'
        );

        res.json({
            totalReservas: parseInt(reservasResult.rows[0].count),
            totalSalas: parseInt(salasResult.rows[0].count)
        });
    } catch (error) {
        console.error('Erro ao buscar estatísticas:', error);
        res.status(500).json({ error: 'Erro ao buscar estatísticas' });
    }
});

/**
 * @swagger
 * /api/dashboard/ultimas-reservas:
 *   get:
 *     summary: Retorna as últimas reservas do usuário
 *     tags: [Dashboard]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Últimas reservas retornadas com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reservas:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                       sala_nome:
 *                         type: string
 *                       data_inicio:
 *                         type: string
 *                         format: date-time
 *                       data_fim:
 *                         type: string
 *                         format: date-time
 *                       motivo:
 *                         type: string
 *                       status:
 *                         type: string
 *       401:
 *         description: Não autorizado
 *       500:
 *         description: Erro interno do servidor
 */
app.get('/api/dashboard/ultimas-reservas', async (req, res) => {
    try {
        // Buscar as 5 últimas reservas do usuário
        const result = await pool.query(
            `SELECT r.*, s.nome as sala_nome 
             FROM reservas r 
             JOIN salas s ON r.sala_id = s.id 
             WHERE r.usuario_id = $1 
             ORDER BY r.data_inicio DESC 
             LIMIT 5`,
            [req.user.id]
        );

        res.json({
            reservas: result.rows
        });
    } catch (error) {
        console.error('Erro ao buscar últimas reservas:', error);
        res.status(500).json({ error: 'Erro ao buscar últimas reservas' });
    }
});

/**
 * @swagger
 * /api/feedbacks:
 *   post:
 *     summary: Envia um novo feedback para uma reserva
 *     tags: [Feedbacks]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - reserva_id
 *               - avaliacao
 *               - comentario
 *             properties:
 *               reserva_id:
 *                 type: integer
 *               avaliacao:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 5
 *               comentario:
 *                 type: string
 *     responses:
 *       201:
 *         description: Feedback enviado com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Feedback'
 *       400:
 *         description: Erro de validação ou reserva inválida
 *       403:
 *         description: Acesso negado, você não tem permissão para enviar feedback para esta reserva
 *       404:
 *         description: Reserva não encontrada ou ainda não concluída
 *       500:
 *         description: Erro interno do servidor
 */
app.post('/api/feedbacks', async (req, res) => {
  const { reserva_id, avaliacao, comentario } = req.body;
  const usuario_id = req.user.id; // ID do usuário logado

  console.log('Requisição POST /api/feedbacks recebida. Dados:', req.body);
  console.log('Usuário logado (ID):', usuario_id);

  try {
    // 1. Verificar se a reserva existe e pertence ao usuário logado
    const reservaResult = await pool.query(
      `SELECT * FROM reservas WHERE id = $1 AND usuario_id = $2`,
      [reserva_id, usuario_id]
    );

    if (reservaResult.rows.length === 0) {
      console.log('Feedback: Reserva não encontrada ou não pertence ao usuário.');
      return res.status(404).json({ error: 'Reserva não encontrada ou você não tem permissão para avaliá-la.' });
    }

    const reserva = reservaResult.rows[0];

    // 2. Verificar se a reserva já foi concluída (data_fim < agora)
    if (new Date(reserva.data_fim) >= new Date()) {
      console.log('Feedback: Reserva ainda não concluída.');
      return res.status(400).json({ error: 'Você só pode enviar feedback para reservas que já foram concluídas.' });
    }

    // 3. Verificar se já existe feedback para esta reserva
    const feedbackExistente = await pool.query(
      `SELECT * FROM feedbacks WHERE reserva_id = $1`,
      [reserva_id]
    );

    if (feedbackExistente.rows.length > 0) {
      console.log('Feedback: Já existe feedback para esta reserva.');
      return res.status(400).json({ error: 'Você já enviou feedback para esta reserva.' });
    }

    // 4. Inserir o feedback
    const result = await pool.query(
      'INSERT INTO feedbacks (reserva_id, usuario_id, sala_id, avaliacao, comentario) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [reserva_id, usuario_id, reserva.sala_id, avaliacao, comentario]
    );

    console.log('Feedback enviado com sucesso:', result.rows[0]);
    res.status(201).json(result.rows[0]);

  } catch (error) {
    console.error('Erro ao enviar feedback:', error);
    res.status(500).json({ error: 'Erro interno do servidor ao enviar feedback.' });
  }
});

/**
 * @swagger
 * /api/feedbacks:
 *   get:
 *     summary: Retorna todos os feedbacks de salas (apenas para administradores)
 *     tags: [Feedbacks]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de feedbacks retornada com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   reserva_id:
 *                     type: integer
 *                   usuario_id:
 *                     type: integer
 *                   sala_id:
 *                     type: integer
 *                   avaliacao:
 *                     type: integer
 *                   comentario:
 *                     type: string
 *                   data_feedback:
 *                     type: string
 *                     format: date-time
 *                   usuario_nome:
 *                     type: string
 *                   sala_nome:
 *                     type: string
 *       401:
 *         description: Não autorizado
 *       403:
 *         description: Acesso negado (não é administrador)
 *       500:
 *         description: Erro interno do servidor
 */
app.get('/api/feedbacks', async (req, res) => {
    // Apenas administradores podem acessar esta rota
    if (!req.user || req.user.tipo !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado. Apenas administradores podem visualizar feedbacks.' });
    }

    try {
        const result = await pool.query(
            `SELECT 
                f.id, 
                f.reserva_id, 
                f.usuario_id, 
                f.sala_id, 
                f.avaliacao, 
                f.comentario, 
                f.data_feedback,
                u.nome as usuario_nome,
                s.nome as sala_nome
             FROM feedbacks f
             JOIN usuarios u ON f.usuario_id = u.id
             JOIN salas s ON f.sala_id = s.id
             ORDER BY f.data_feedback DESC`
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar feedbacks:', error);
        res.status(500).json({ error: 'Erro interno do servidor ao buscar feedbacks.' });
    }
});

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`)
  console.log(`Documentação Swagger disponível em http://localhost:${port}/api-docs`)
})
