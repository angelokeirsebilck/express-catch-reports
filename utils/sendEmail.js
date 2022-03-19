const sgMail = require('@sendgrid/mail');

const sendEmail = async ({ to, subject, html }) => {
  sgMail.setApiKey(process.env.SENDGRID_API);
  const msg = {
    to, // Change to your recipient
    from: 'info@angelokeirsebilck.be',
    subject,
    html,
  };
  const info = await sgMail.send(msg);
  console.log(info);
  return info;
};

module.exports = sendEmail;
