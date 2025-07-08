const nodemailer = require('nodemailer');

async function sendVerificationEmail(toEmail, url) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,      // ton email
      pass: process.env.EMAIL_PASSWORD,  // ton mot de passe ou app password
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: toEmail,
    subject: 'Confirme ton adresse email',
    html: `<p>Merci de confirmer ton email en cliquant sur le lien ci-dessous :</p>
           <a href="${url}">${url}</a>`,
  };

  await transporter.sendMail(mailOptions);
}

module.exports = { sendVerificationEmail };
