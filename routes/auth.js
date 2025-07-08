const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const { sendVerificationEmail, sendResetPasswordEmail } = require('../utils/email');
const { generateAccessToken, generateRefreshToken } = require('../middleware/authMiddleware');

const router = express.Router();


// ========================= SIGNUP =========================
router.post('/signup', async (req, res) => {
  console.log('Requête signup reçue:', req.body);

  const { email, password } = req.body;

  try {
    // Vérifier si utilisateur existe déjà
    const existingUser = await User.findOne({ email });
    console.log('Recherche utilisateur existant:', existingUser);
    if (existingUser) return res.status(400).json({ message: 'Utilisateur déjà existant' });

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Mot de passe hashé:', hashedPassword);

    // Générer un token unique pour confirmation email
    const emailVerificationToken = crypto.randomBytes(20).toString('hex');
    console.log('Token généré pour confirmation email:', emailVerificationToken);

    // Créer l'utilisateur
    const user = new User({
      email,
      password: hashedPassword,
      isConfirmed: false,
      emailVerificationToken
    });

    await user.save();
    console.log('Utilisateur sauvegardé en base:', user);

    // Construire le lien de confirmation
    const url = `${process.env.CLIENT_URL}/confirm/${emailVerificationToken}`;
    console.log('Lien complet pour email:', url);

    await sendVerificationEmail(email, url);
    console.log('Email de vérification envoyé à:', email);

    res.status(201).json({ message: 'Compte créé. Vérifie ton email pour valider ton compte.' });
  } catch (err) {
    console.error('Erreur dans /signup:', err);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});


// ========================= VERIFY EMAIL =========================
router.get('/verify-email', async (req, res) => {
  console.log('Requête de vérification email reçue:', req.query);

  const { token } = req.query;
  console.log('Token reçu pour vérification:', token);

  try {
    const user = await User.findOne({ emailVerificationToken: token });
    console.log('Utilisateur trouvé pour ce token:', user);

    if (!user) {
      console.log('Aucun utilisateur trouvé pour ce token.');
      return res.status(404).json({ message: 'Token invalide' });
    }

    user.isConfirmed = true;
    user.emailVerificationToken = undefined;
    await user.save();

    console.log('Email confirmé pour utilisateur:', user.email);
    res.json({ message: 'Email vérifié avec succès' });
  } catch (err) {
    console.error('Erreur vérification email:', err);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});


// ========================= LOGIN =========================
router.post('/login',
  body('email').isEmail(),
  body('password').exists(),
  async (req, res) => {
    console.log('Requête login reçue:', req.body);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Validation échouée:', errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      console.log('Résultat recherche utilisateur login:', user);

      if (!user) {
        console.log('Aucun utilisateur trouvé avec cet email.');
        return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
      }

      if (!user.isConfirmed) {
        console.log('Utilisateur non confirmé:', user.email);
        return res.status(400).json({ message: 'Confirmez votre email avant de vous connecter' });
      }

      const match = await bcrypt.compare(password, user.password);
      console.log('Résultat comparaison password:', match);

      if (!match) {
        console.log('Mot de passe incorrect pour:', user.email);
        return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
      }

      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);

      console.log('Tokens générés pour', user.email, '=> access:', accessToken, 'refresh:', refreshToken);

      res.json({ accessToken, refreshToken });
    } catch (err) {
      console.error('Erreur dans /login:', err);
      res.status(500).json({ message: 'Erreur serveur' });
    }
  }
);


// ========================= REFRESH TOKEN =========================
router.post('/token', async (req, res) => {
  console.log('Requête /token reçue:', req.body);

  const { token } = req.body;
  if (!token) {
    console.log('Token manquant');
    return res.status(401).json({ message: 'Token manquant' });
  }

  jwt.verify(token, process.env.JWT_REFRESH_SECRET, (err, user) => {
    if (err) {
      console.log('Token refresh invalide:', err);
      return res.status(403).json({ message: 'Token invalide' });
    }

    const accessToken = generateAccessToken({ id: user.id, role: user.role });
    console.log('Nouveau accessToken généré:', accessToken);
    res.json({ accessToken });
  });
});


// ========================= FORGOT PASSWORD =========================
router.post('/forgot-password',
  body('email').isEmail(),
  async (req, res) => {
    console.log('Requête forgot-password reçue:', req.body);

    try {
      const { email } = req.body;
      const user = await User.findOne({ email });
      console.log('Recherche utilisateur pour reset:', user);

      if (!user) {
        console.log('Aucun utilisateur trouvé avec cet email');
        return res.status(400).json({ message: 'Aucun utilisateur trouvé avec cet email' });
      }

      const resetToken = crypto.randomBytes(20).toString('hex');
      user.resetPasswordToken = resetToken;
      user.resetPasswordExpires = Date.now() + 3600000; // 1h
      await user.save();

      console.log('Reset token généré:', resetToken);
      await sendResetPasswordEmail(email, resetToken);
      console.log('Email de reset envoyé à:', email);

      res.json({ message: 'Email de réinitialisation envoyé' });
    } catch (err) {
      console.error('Erreur dans /forgot-password:', err);
      res.status(500).json({ message: 'Erreur serveur' });
    }
  }
);


// ========================= RESET PASSWORD =========================
router.post('/reset-password/:token',
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    console.log('Requête reset-password reçue:', req.params, req.body);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.log('Validation échouée:', errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() }
      });
      console.log('Utilisateur trouvé pour reset password:', user);

      if (!user) {
        console.log('Token invalide ou expiré pour reset.');
        return res.status(400).json({ message: 'Token invalide ou expiré' });
      }

      user.password = await bcrypt.hash(req.body.password, 10);
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      console.log('Mot de passe réinitialisé pour:', user.email);
      res.json({ message: 'Mot de passe réinitialisé avec succès' });
    } catch (err) {
      console.error('Erreur dans /reset-password:', err);
      res.status(500).json({ message: 'Erreur serveur' });
    }
  }
);

module.exports = router;
