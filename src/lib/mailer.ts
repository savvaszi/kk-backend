import nodemailer from 'nodemailer';

export const transporter = nodemailer.createTransport({
  host: 'mail.krypto-knight.com',
  port: 465,
  secure: true,          // SSL on port 465
  auth: {
    user: 'support@krypto-knight.com',
    pass: '$#LoW8!3,&B3VTU8',
  },
  tls: {
    rejectUnauthorized: false, // Allow self-signed certs on the mail server
  },
});

export const RECIPIENT = 'info@krypto-knight.com';
export const FROM = '"Krypto Knight" <support@krypto-knight.com>';
