/**
 * Public routes (no auth required):
 *   POST /public/contact          – Contact form
 *   POST /public/apply/personal   – Personal account application
 *   POST /public/apply/business   – Business account application
 *
 * All submissions are emailed to info@krypto-knight.com via SMTP.
 * File uploads (ID docs, address proofs) are attached to the email.
 */

import { Router, Request, Response } from 'express';
import multer from 'multer';
import { transporter, RECIPIENT, FROM } from '../lib/mailer.js';

const router = Router();

// Store uploads in memory so we can attach them directly to the email
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB per file
});

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build an HTML table from a flat key→value record */
function htmlTable(rows: [string, string][]): string {
  const body = rows
    .filter(([, v]) => v && v.trim())
    .map(
      ([k, v]) =>
        `<tr>
           <td style="padding:6px 12px;font-weight:600;color:#555;white-space:nowrap;border-bottom:1px solid #eee">${k}</td>
           <td style="padding:6px 12px;color:#222;border-bottom:1px solid #eee">${v.replace(/\n/g, '<br>')}</td>
         </tr>`
    )
    .join('');
  return `<table style="border-collapse:collapse;width:100%;font-family:sans-serif;font-size:14px">${body}</table>`;
}

function emailWrapper(title: string, content: string): string {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f4f4">
  <div style="max-width:680px;margin:32px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)">
    <div style="background:#0d1117;padding:24px 32px;display:flex;align-items:center;gap:12px">
      <span style="color:#00FF9C;font-size:20px;font-weight:700;letter-spacing:1px">KRYPTO KNIGHT</span>
    </div>
    <div style="padding:32px">
      <h2 style="margin:0 0 24px;color:#0d1117;font-family:sans-serif">${title}</h2>
      ${content}
    </div>
    <div style="background:#f9f9f9;padding:16px 32px;font-size:12px;color:#999;font-family:sans-serif">
      This email was generated automatically by the Krypto Knight website. Do not reply to this message.
    </div>
  </div>
</body>
</html>`;
}

/** Convert multer file to nodemailer attachment object */
function toAttachment(file: Express.Multer.File) {
  return {
    filename: file.originalname,
    content: file.buffer,
    contentType: file.mimetype,
  };
}

// ── Contact form ──────────────────────────────────────────────────────────────

router.post('/contact', async (req: Request, res: Response) => {
  try {
    const { firstName, lastName, email, subject, message } = req.body as Record<string, string>;

    if (!email || !message) {
      res.status(400).json({ success: false, error: 'Email and message are required.' });
      return;
    }

    const rows: [string, string][] = [
      ['Name', `${firstName ?? ''} ${lastName ?? ''}`.trim()],
      ['Email', email],
      ['Subject', subject ?? '(no subject)'],
      ['Message', message],
      ['Submitted at', new Date().toUTCString()],
    ];

    await transporter.sendMail({
      from: FROM,
      to: RECIPIENT,
      replyTo: email,
      subject: `Contact Form: ${subject || 'New message'} — ${firstName ?? ''} ${lastName ?? ''}`.trim(),
      html: emailWrapper('New Contact Form Submission', htmlTable(rows)),
    });

    res.json({ success: true });
  } catch (err: any) {
    console.error('[contact] mail error:', err?.message);
    res.status(500).json({ success: false, error: 'Failed to send message. Please try again.' });
  }
});

// ── Personal account application ──────────────────────────────────────────────

const personalUpload = upload.fields([
  { name: 'idDocument', maxCount: 1 },
  { name: 'addressProof', maxCount: 1 },
]);

router.post('/apply/personal', personalUpload as any, async (req: Request, res: Response) => {
  try {
    const f = req.body as Record<string, string>;
    const files = req.files as Record<string, Express.Multer.File[]> | undefined;

    const rows: [string, string][] = [
      // Identity
      ['— PERSONAL INFORMATION —', ''],
      ['First Name', f.firstName ?? ''],
      ['Middle Name', f.middleName ?? ''],
      ['Last Name', f.lastName ?? ''],
      ['Date of Birth', f.dateOfBirth ?? ''],
      ['Place of Birth', f.placeOfBirth ?? ''],
      // Tax
      ['— TAX INFORMATION —', ''],
      ['Has Tax ID?', f.hasTaxId ?? ''],
      ['Tax Identification Number', f.taxId ?? ''],
      ['Reason (no TIN)', f.noTaxIdReason ?? ''],
      ['Tax Country', f.taxCountry ?? ''],
      // Citizenship
      ['— CITIZENSHIP —', ''],
      ['Nationality', f.nationality ?? ''],
      ['Citizenship', f.citizenship ?? ''],
      ['ID / Passport No', f.passportNo ?? ''],
      ['Issuing Authority', f.issuingAuthority ?? ''],
      ['Date of Issue', f.dateOfIssue ?? ''],
      ['Date of Expiry', f.dateOfExpiry ?? ''],
      ['Dual Citizenship?', f.hasDualCitizenship ?? ''],
      ['Second Nationality', f.secondNationality ?? ''],
      // Address
      ['— RESIDENTIAL ADDRESS —', ''],
      ['Street', f.street ?? ''],
      ['City', f.city ?? ''],
      ['State / Region', f.state ?? ''],
      ['Postal Code', f.zip ?? ''],
      ['Country', f.country ?? ''],
      ['Different Mailing Address?', f.differentMailing ?? ''],
      ['Mailing Street', f.mailingStreet ?? ''],
      ['Mailing City', f.mailingCity ?? ''],
      ['Mailing State', f.mailingState ?? ''],
      ['Mailing ZIP', f.mailingZip ?? ''],
      ['Mailing Country', f.mailingCountry ?? ''],
      // Contact
      ['— CONTACT —', ''],
      ['Phone', f.phone ?? ''],
      ['Email', f.email ?? ''],
      ['Facebook', f.facebook ?? ''],
      ['LinkedIn', f.linkedin ?? ''],
      ['Other Social', f.other ?? ''],
      // Meta
      ['Submitted at', new Date().toUTCString()],
    ];

    const attachments: any[] = [];
    if (files?.idDocument?.[0]) attachments.push(toAttachment(files.idDocument[0]));
    if (files?.addressProof?.[0]) attachments.push(toAttachment(files.addressProof[0]));

    const name = `${f.firstName ?? ''} ${f.lastName ?? ''}`.trim();

    await transporter.sendMail({
      from: FROM,
      to: RECIPIENT,
      replyTo: f.email || undefined,
      subject: `Personal Account Application — ${name}`,
      html: emailWrapper('Personal Account Application', htmlTable(rows)),
      attachments,
    });

    res.json({ success: true });
  } catch (err: any) {
    console.error('[apply/personal] mail error:', err?.message);
    res.status(500).json({ success: false, error: 'Failed to submit application. Please try again.' });
  }
});

// ── Business account application ──────────────────────────────────────────────

const businessUpload = upload.fields([
  { name: 'incorporationDoc', maxCount: 1 },
  { name: 'additionalDoc', maxCount: 1 },
  { name: 'addressProof', maxCount: 1 },
]);

router.post('/apply/business', businessUpload as any, async (req: Request, res: Response) => {
  try {
    const f = req.body as Record<string, string>;
    const files = req.files as Record<string, Express.Multer.File[]> | undefined;

    const rows: [string, string][] = [
      ['— COMPANY INFORMATION —', ''],
      ["Legal Name", f.legalName ?? ''],
      ['Trading Name', f.tradingName ?? ''],
      ['Country of Incorporation', f.countryOfIncorporation ?? ''],
      ['Incorporation Date', f.incorporationDate ?? ''],
      ['Registration Number', f.registrationNumber ?? ''],
      ['— TAX INFORMATION —', ''],
      ['Has Tax ID?', f.hasTaxId ?? ''],
      ['Tax Identification Number', f.taxId ?? ''],
      ['Reason (no TIN)', f.noTaxIdReason ?? ''],
      ['— BUSINESS PROFILE —', ''],
      ['Business Activities', f.businessActivities ?? ''],
      ['Years of Operation', f.yearsOfOperation ?? ''],
      ['Number of Employees', f.numberOfEmployees ?? ''],
      ['Annual Income', f.annualIncome ?? ''],
      ['Part of a Group?', f.partOfGroup ?? ''],
      ['Group Details', f.groupDetails ?? ''],
      ['Regulated Entity?', f.isRegulated ?? ''],
      ['License Number', f.licenseNumber ?? ''],
      ['Issuing Authority / Regulator', f.issuingRegulator ?? ''],
      ['— REGISTERED ADDRESS —', ''],
      ['Street', f.regStreet ?? ''],
      ['City', f.regCity ?? ''],
      ['State / Region', f.regState ?? ''],
      ['Postal Code', f.regZip ?? ''],
      ['Country', f.regCountry ?? ''],
      ['Same as Business Location?', f.sameAsBusiness ?? ''],
      ['Business Street', f.bizStreet ?? ''],
      ['Business City', f.bizCity ?? ''],
      ['Business State', f.bizState ?? ''],
      ['Business ZIP', f.bizZip ?? ''],
      ['Business Country', f.bizCountry ?? ''],
      ['— CONTACT —', ''],
      ['Phone', f.phone ?? ''],
      ['Email', f.email ?? ''],
      ['Website', f.website ?? ''],
      ['Submitted at', new Date().toUTCString()],
    ];

    const attachments: any[] = [];
    if (files?.incorporationDoc?.[0]) attachments.push(toAttachment(files.incorporationDoc[0]));
    if (files?.additionalDoc?.[0]) attachments.push(toAttachment(files.additionalDoc[0]));
    if (files?.addressProof?.[0]) attachments.push(toAttachment(files.addressProof[0]));

    await transporter.sendMail({
      from: FROM,
      to: RECIPIENT,
      replyTo: f.email || undefined,
      subject: `Business Account Application — ${f.legalName ?? 'Unknown Company'}`,
      html: emailWrapper('Business Account Application', htmlTable(rows)),
      attachments,
    });

    res.json({ success: true });
  } catch (err: any) {
    console.error('[apply/business] mail error:', err?.message);
    res.status(500).json({ success: false, error: 'Failed to submit application. Please try again.' });
  }
});

export default router;
