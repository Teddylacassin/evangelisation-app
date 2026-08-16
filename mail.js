// Petit module d'envoi d'email via l'API Resend (service gratuit, pas de dependance a installer
// au-dela de fetch qui est deja integre a Node). Si la cle RESEND_API_KEY n'est pas configuree
// (en local par exemple), on se contente d'afficher le mail dans la console au lieu de l'envoyer,
// pour ne jamais bloquer l'application.
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const MAIL_FROM = process.env.MAIL_FROM || 'Semeurs <onboarding@resend.dev>';

async function sendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) {
    console.log(`[email non envoyé - RESEND_API_KEY absent] À: ${to} | Sujet: ${subject}`);
    return { skipped: true };
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, html })
    });
    if (!res.ok) {
      const text = await res.text();
      console.error('Erreur envoi email Resend:', res.status, text);
    }
    return res;
  } catch (err) {
    console.error('Erreur envoi email Resend:', err);
    return { error: err };
  }
}

module.exports = { sendEmail };
