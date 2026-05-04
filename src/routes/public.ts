/**
 * Public routes (no auth required):
 *   POST /public/contact          – Contact form
 *   POST /public/apply/personal   – Personal account application
 *   POST /public/apply/business   – Business account application
 *
 * On form submission:
 *   1. Find existing user by email, or create a pending account with a temp password.
 *   2. Store the full application (text fields + uploaded files as base64) in the DB.
 *   3. Set kycStatus = 'pending' on the user.
 *   4. Email admin notification + welcome email to applicant (new accounts only).
 */

import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import multer from 'multer';
import { db } from '../db/index.js';
import { users, applications } from '../db/schema.js';
import { eq } from 'drizzle-orm';
import { hashPassword } from '../lib/password.js';
import { sendMail, getRecipient } from '../lib/mailer.js';

const router = Router();

// Store uploads in memory so we can attach them to the email and persist to DB
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

/** Convert multer file to DB document record */
function toDocumentRecord(file: Express.Multer.File) {
  return {
    name: file.originalname,
    mimetype: file.mimetype,
    size: file.size,
    data: file.buffer.toString('base64'),
  };
}

/** Generate a random temp password like KK-abc123 */
function generateTempPassword(): string {
  return 'KK-' + crypto.randomBytes(4).toString('hex');
}

/** Derive a username from an email (take part before @, lowercase, strip non-alphanum/underscore) */
function usernameFromEmail(email: string): string {
  return email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '_').slice(0, 30);
}

/**
 * Find user by email or create a new pending account.
 * Returns { user, isNew, tempPassword? }
 */
async function findOrCreateUser(email: string, firstName?: string, lastName?: string) {
  const [existing] = await db
    .select()
    .from(users)
    .where(eq(users.email, email.toLowerCase()))
    .limit(1);

  if (existing) {
    // Update kycStatus to pending if not already reviewed
    if (existing.kycStatus === 'none') {
      await db
        .update(users)
        .set({ kycStatus: 'pending', updatedAt: new Date() })
        .where(eq(users.id, existing.id));
    }
    return { user: { ...existing, kycStatus: 'pending' }, isNew: false };
  }

  // Create new user
  const tempPassword = generateTempPassword();
  const passwordHash = await hashPassword(tempPassword);
  let username = usernameFromEmail(email);

  // Ensure username uniqueness
  const [byUsername] = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.username, username))
    .limit(1);
  if (byUsername) {
    username = username + '_' + crypto.randomBytes(2).toString('hex');
  }

  const [user] = await db
    .insert(users)
    .values({
      email: email.toLowerCase(),
      username,
      passwordHash,
      firstName: firstName ?? null,
      lastName: lastName ?? null,
      status: 'active',
      kycStatus: 'pending',
      emailVerified: false,
    })
    .returning();

  return { user, isNew: true, tempPassword };
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

    await sendMail({
      to: await getRecipient(),
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

    if (!f.email) {
      res.status(400).json({ success: false, error: 'Email is required.' });
      return;
    }

    // 1. Find or create user
    const { user, isNew, tempPassword } = await findOrCreateUser(
      f.email,
      f.firstName,
      f.lastName
    );

    // 2. Build document records for DB storage
    const documents: Array<{ name: string; mimetype: string; size: number; data: string }> = [];
    if (files?.idDocument?.[0]) documents.push(toDocumentRecord(files.idDocument[0]));
    if (files?.addressProof?.[0]) documents.push(toDocumentRecord(files.addressProof[0]));

    // 3. Store application in DB
    await db.insert(applications).values({
      userId: user.id,
      type: 'personal',
      data: f,
      documents,
    });

    // 4. Build rows for admin email
    const rows: [string, string][] = [
      ['— PERSONAL INFORMATION —', ''],
      ['First Name', f.firstName ?? ''],
      ['Middle Name', f.middleName ?? ''],
      ['Last Name', f.lastName ?? ''],
      ['Date of Birth', f.dateOfBirth ?? ''],
      ['Place of Birth', f.placeOfBirth ?? ''],
      ['— TAX INFORMATION —', ''],
      ['Has Tax ID?', f.hasTaxId ?? ''],
      ['Tax Identification Number', f.taxId ?? ''],
      ['Reason (no TIN)', f.noTaxIdReason ?? ''],
      ['Tax Country', f.taxCountry ?? ''],
      ['— CITIZENSHIP —', ''],
      ['Nationality', f.nationality ?? ''],
      ['Citizenship', f.citizenship ?? ''],
      ['ID / Passport No', f.passportNo ?? ''],
      ['Issuing Authority', f.issuingAuthority ?? ''],
      ['Date of Issue', f.dateOfIssue ?? ''],
      ['Date of Expiry', f.dateOfExpiry ?? ''],
      ['Dual Citizenship?', f.hasDualCitizenship ?? ''],
      ['Second Nationality', f.secondNationality ?? ''],
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
      ['— CONTACT —', ''],
      ['Phone', f.phone ?? ''],
      ['Email', f.email ?? ''],
      ['Facebook', f.facebook ?? ''],
      ['LinkedIn', f.linkedin ?? ''],
      ['Other Social', f.other ?? ''],
      ['— ACCOUNT —', ''],
      ['User ID', user.id],
      ['New Account Created', isNew ? 'Yes' : 'No'],
      ['Submitted at', new Date().toUTCString()],
    ];

    const attachments: any[] = [];
    if (files?.idDocument?.[0]) attachments.push(toAttachment(files.idDocument[0]));
    if (files?.addressProof?.[0]) attachments.push(toAttachment(files.addressProof[0]));

    const name = `${f.firstName ?? ''} ${f.lastName ?? ''}`.trim();

    // 5. Send admin notification (non-blocking — email failure must not fail the submission)
    sendMail({
      to: await getRecipient(),
      replyTo: f.email || undefined,
      subject: `Personal Account Application — ${name}`,
      html: emailWrapper('Personal Account Application', htmlTable(rows)),
      attachments,
    }).catch(err => console.error('[apply/personal] admin email error:', err?.message));

    // 6. Send welcome email to applicant if new account was created (non-blocking)
    if (isNew && tempPassword) {
      const welcomeRows: [string, string][] = [
        ['Your Email', f.email],
        ['Your Username', user.username],
        ['Temporary Password', tempPassword],
      ];
      sendMail({
        to: f.email,
        subject: 'Your Krypto Knight Application Has Been Received',
        html: emailWrapper(
          'Application Received',
          `<p style="font-family:sans-serif;font-size:14px;color:#333;margin-bottom:20px">
            Thank you, ${name || 'Applicant'}. Your personal account application has been received and is now under review.
            Our team will verify your documents and contact you within 1–3 business days.
          </p>
          <p style="font-family:sans-serif;font-size:14px;color:#333;margin-bottom:12px">
            A platform account has been created for you with the credentials below.
            Please change your password after your first login.
          </p>
          ${htmlTable(welcomeRows)}
          <p style="font-family:sans-serif;font-size:12px;color:#999;margin-top:20px">
            Login at: <a href="https://krypto-knight.com/login">krypto-knight.com/login</a>
          </p>`
        ),
      }).catch(err => console.error('[apply/personal] welcome email error:', err?.message));
    }

    res.json({ success: true });
  } catch (err: any) {
    console.error('[apply/personal] error:', err?.message);
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

    if (!f.email) {
      res.status(400).json({ success: false, error: 'Email is required.' });
      return;
    }

    // 1. Find or create user
    const { user, isNew, tempPassword } = await findOrCreateUser(f.email);

    // 2. Build document records for DB storage
    const documents: Array<{ name: string; mimetype: string; size: number; data: string }> = [];
    if (files?.incorporationDoc?.[0]) documents.push(toDocumentRecord(files.incorporationDoc[0]));
    if (files?.additionalDoc?.[0]) documents.push(toDocumentRecord(files.additionalDoc[0]));
    if (files?.addressProof?.[0]) documents.push(toDocumentRecord(files.addressProof[0]));

    // 3. Store application in DB
    await db.insert(applications).values({
      userId: user.id,
      type: 'business',
      data: f,
      documents,
    });

    // 4. Build rows for admin email
    const rows: [string, string][] = [
      ['— COMPANY INFORMATION —', ''],
      ['Legal Name', f.legalName ?? ''],
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
      ['— ACCOUNT —', ''],
      ['User ID', user.id],
      ['New Account Created', isNew ? 'Yes' : 'No'],
      ['Submitted at', new Date().toUTCString()],
    ];

    const attachments: any[] = [];
    if (files?.incorporationDoc?.[0]) attachments.push(toAttachment(files.incorporationDoc[0]));
    if (files?.additionalDoc?.[0]) attachments.push(toAttachment(files.additionalDoc[0]));
    if (files?.addressProof?.[0]) attachments.push(toAttachment(files.addressProof[0]));

    // 5. Send admin notification (non-blocking — email failure must not fail the submission)
    sendMail({
      to: await getRecipient(),
      replyTo: f.email || undefined,
      subject: `Business Account Application — ${f.legalName ?? 'Unknown Company'}`,
      html: emailWrapper('Business Account Application', htmlTable(rows)),
      attachments,
    }).catch(err => console.error('[apply/business] admin email error:', err?.message));

    // 6. Send welcome email to applicant if new account was created (non-blocking)
    if (isNew && tempPassword) {
      const welcomeRows: [string, string][] = [
        ['Your Email', f.email],
        ['Your Username', user.username],
        ['Temporary Password', tempPassword],
      ];
      sendMail({
        to: f.email,
        subject: 'Your Krypto Knight Application Has Been Received',
        html: emailWrapper(
          'Application Received',
          `<p style="font-family:sans-serif;font-size:14px;color:#333;margin-bottom:20px">
            Thank you for submitting your business account application. Our team will review your
            documents and contact you within 1–3 business days.
          </p>
          <p style="font-family:sans-serif;font-size:14px;color:#333;margin-bottom:12px">
            A platform account has been created for you with the credentials below.
            Please change your password after your first login.
          </p>
          ${htmlTable(welcomeRows)}
          <p style="font-family:sans-serif;font-size:12px;color:#999;margin-top:20px">
            Login at: <a href="https://krypto-knight.com/login">krypto-knight.com/login</a>
          </p>`
        ),
      }).catch(err => console.error('[apply/business] welcome email error:', err?.message));
    }

    res.json({ success: true });
  } catch (err: any) {
    console.error('[apply/business] error:', err?.message);
    res.status(500).json({ success: false, error: 'Failed to submit application. Please try again.' });
  }
});

export default router;
