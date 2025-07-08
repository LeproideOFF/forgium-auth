require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const mongoose = require('mongoose');
const cors = require('cors');

const authRoutes = require('./routes/auth');
const { authenticateToken } = require('./middleware/authMiddleware');

const app = express();

// Middleware de parsing JSON (doit être avant le logger de body)
app.use(express.json());

// Logger des requêtes et du body (body est maintenant parsé)
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url} - Body:`, req.body);
  next();
});

// Configuration CORS unique (attention à process.env.CLIENT_URL)
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://192.168.1.33:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
}));

app.use(helmet());
app.use(morgan('dev'));

// Connexion MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connecté Auth Service'))
  .catch(err => {
    console.error('Erreur MongoDB:', err);
    process.exit(1);
  });

// Routes
app.use('/api/auth', authRoutes);

app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Accès autorisé', user: req.user });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => console.log(`Auth Service démarré sur le port ${PORT}`));
