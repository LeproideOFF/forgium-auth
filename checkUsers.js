require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User'); // adapte si ton modèle est ailleurs

(async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connecté à MongoDB');

    const users = await User.find();
    console.log('Utilisateurs dans la base:');
    console.dir(users, { depth: null });

    process.exit(0);
  } catch (err) {
    console.error('Erreur MongoDB:', err);
    process.exit(1);
  }
})();
