const User = require('../models/User');
const sgMail = require('@sendgrid/mail');

const ADMIN_EMAIL = User.getPrimaryAdminEmail();
const DEFAULT_SENDGRID_FROM = `MicroSOC <${ADMIN_EMAIL}>`;

function getEmailFrom() {
  return (
    process.env.SENDGRID_FROM_EMAIL ||
    process.env.APPROVAL_EMAIL_FROM ||
    process.env.EMAIL_FROM ||
    DEFAULT_SENDGRID_FROM
  );
}

function getReplyTo() {
  return process.env.APPROVAL_REPLY_TO || process.env.EMAIL_REPLY_TO || '';
}

function getBaseUrl(req) {
  if (process.env.BACKEND_PUBLIC_URL) {
    return process.env.BACKEND_PUBLIC_URL.replace(/\/$/, '');
  }

  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${protocol}://${host}`;
}

function buildApprovalLinks(req, token) {
  const baseUrl = getBaseUrl(req);
  return {
    approveUrl: `${baseUrl}/api/auth/approve/${token}`,
    rejectUrl: `${baseUrl}/api/auth/reject/${token}`
  };
}

async function sendWithSendGrid({ to, subject, html, text }) {
  if (!process.env.SENDGRID_API_KEY) {
    return { skipped: true, reason: 'SENDGRID_API_KEY is not configured' };
  }

  const from = getEmailFrom();
  const replyTo = getReplyTo();
  const recipients = Array.isArray(to) ? to : [to].filter(Boolean);
  const payload = { from, to: recipients, subject, html, text };

  if (replyTo) {
    payload.replyTo = replyTo;
  }

  sgMail.setApiKey(process.env.SENDGRID_API_KEY);

  try {
    const [response] = await sgMail.send(payload);
    return {
      sent: true,
      provider: 'sendgrid',
      from,
      to: recipients,
      response: JSON.stringify({
        statusCode: response.statusCode,
        headers: response.headers
      })
    };
  } catch (error) {
    const responseBody = error?.response?.body
      ? JSON.stringify(error.response.body)
      : error.message;
    const sendgridVerificationHint = /validation_error|verified sender|authenticate a domain|from address/i.test(responseBody)
      ? ' Make sure SENDGRID_FROM_EMAIL / APPROVAL_EMAIL_FROM is a SendGrid-verified sender email or authenticated domain, then restart the backend.'
      : '';
    const providerHint = from === DEFAULT_SENDGRID_FROM
      ? ' Set APPROVAL_EMAIL_FROM or SENDGRID_FROM_EMAIL to a verified sender email.'
      : sendgridVerificationHint;
    throw new Error(`SendGrid email failed: ${responseBody}.${providerHint}`);
  }
}

async function sendEmailOrLog({ to, subject, html, text, fallbackLog }) {
  try {
    const result = await sendWithSendGrid({ to, subject, html, text });

    if (result.skipped) {
      console.warn(`⚠️ Email skipped: ${result.reason}`);
      if (fallbackLog) fallbackLog();
    }

    return { sent: !result.skipped, ...result };
  } catch (error) {
    console.error('❌ Email error:', error.message);
    if (fallbackLog) fallbackLog();
    return { sent: false, error: error.message };
  }
}

async function sendApprovalRequestEmail({ req, user, token }) {
  const { approveUrl, rejectUrl } = buildApprovalLinks(req, token);
  const subject = `MicroSOC access request: ${user.name}`;
  const text = [
    `New MicroSOC signup request`,
    `Name: ${user.name}`,
    `Email: ${user.email}`,
    `Role: ${user.role}`,
    ``,
    `Approve: ${approveUrl}`,
    `Reject: ${rejectUrl}`
  ].join('\n');
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.5;color:#111827">
      <h2>MicroSOC Access Request</h2>
      <p>A new user wants access to your MicroSOC dashboard.</p>
      <ul>
        <li><strong>Name:</strong> ${user.name}</li>
        <li><strong>Email:</strong> ${user.email}</li>
        <li><strong>Role:</strong> ${user.role}</li>
      </ul>
      <p>
        <a href="${approveUrl}" style="display:inline-block;padding:10px 14px;background:#16a34a;color:white;text-decoration:none;border-radius:6px">Approve</a>
        <a href="${rejectUrl}" style="display:inline-block;padding:10px 14px;background:#dc2626;color:white;text-decoration:none;border-radius:6px;margin-left:8px">Reject</a>
      </p>
    </div>
  `;

  const result = await sendEmailOrLog({
    to: ADMIN_EMAIL,
    subject,
    html,
    text,
    fallbackLog: () => {
      console.warn(`Approve ${user.email}: ${approveUrl}`);
      console.warn(`Reject ${user.email}: ${rejectUrl}`);
    }
  });

  return { ...result, approveUrl, rejectUrl };
}

async function sendPasswordResetOtpEmail({ user, otp }) {
  const subject = 'MicroSOC password reset OTP';
  const text = [
    `Your MicroSOC password reset OTP is: ${otp}`,
    ``,
    `This OTP expires in 10 minutes.`,
    `If you did not request this, ignore this email.`
  ].join('\n');
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.5;color:#111827">
      <h2>MicroSOC Password Reset</h2>
      <p>Use this OTP to change your password:</p>
      <div style="font-size:28px;font-weight:700;letter-spacing:6px;background:#f3f4f6;padding:14px 18px;display:inline-block;border-radius:8px">${otp}</div>
      <p>This OTP expires in 10 minutes.</p>
      <p>If you did not request this, you can safely ignore this email.</p>
    </div>
  `;

  return sendEmailOrLog({
    to: user.email,
    subject,
    html,
    text,
    fallbackLog: () => console.warn(`Password reset OTP for ${user.email}: ${otp}`)
  });
}

module.exports = {
  sendApprovalRequestEmail,
  sendPasswordResetOtpEmail
};
