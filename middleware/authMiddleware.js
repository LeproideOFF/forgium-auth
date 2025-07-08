const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if(!token) return res.status(401).json({ message: 'Token manquant' });

  jwt.verify(token, process.env.JWT_ACCESS_SECRET, (err, user) => {
    if(err) return res.status(403).json({ message: 'Token invalide' });
    req.user = user;
    next();
  });
}

function generateAccessToken(user) {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' });
}

function generateRefreshToken(user) {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
}

module.exports = {
  authenticateToken,
  generateAccessToken,
  generateRefreshToken
};
