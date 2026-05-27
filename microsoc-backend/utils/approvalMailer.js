const User = require('../models/User');

const ADMIN_EMAIL = User.getPrimaryAdminEmail();

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

async function sendWithResend({ to, subject, html, text }) {
  if (!process.env.RESEND_API_KEY) {
    return { skipped: true, reason: 'RESEND_API_KEY is not configured' };
  }

  const from = process.env.APPROVAL_EMAIL_FROM || 'MicroSOC <onboarding@resend.dev>';
  const replyTo = process.env.APPROVAL_REPLY_TO;
  const payload = { from, to, subject, html, text };
  if (replyTo) {
    payload.reply_to = replyTo;
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Resend email failed: ${response.status} ${errorBody}`);
  }

  return response.json();
}

async function sendEmailOrLog({ to, subject, html, text, fallbackLog }) {
  try {
    const result = await sendWithResend({ to, subject, html, text });

    if (result.skipped) {
      console.warn(`⚠️ Email skipped: ${result.reason}`);
      if (fallbackLog) fallbackLog();
    }

    return { sent: !result.skipped };
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
