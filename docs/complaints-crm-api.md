# Complaints CRM API

The Complaints CRM API is a read-only HTTPS integration for approved service providers that need to import formal complaints into a CRM.

## Provision access

1. Sign in as a full administrator with 2FA enabled.
2. Open **Complaints** in the admin dashboard.
3. Under **CRM integration API**, select **Generate CRM API key**.
4. Copy the key immediately. It is displayed once.
5. Transfer it to the approved provider using the organisation's secure secret-sharing process.

The credential can be revoked at any time under **API Keys**. It has only the `complaints:read` permission.

## Authentication

Send the generated key as a bearer token:

```http
Authorization: Bearer kk_live_KEY_ID.SECRET
```

Never place the key in a URL, browser-side application, ticket, email, or source repository.

## List and incrementally poll complaints

```http
GET https://api.krypto-knight.com/public/integrations/complaints?updated_since=2026-07-01T00:00:00.000Z&limit=100
```

The response is ordered by `updated_at` and complaint ID. Store both `meta.nextUpdatedSince` and `meta.nextAfterId`, then send them as `updated_since` and `after_id` on the next request. This prevents skipped records when multiple complaints have the same update timestamp. The maximum page size is 200 records. A sensible polling interval is five minutes.

Example:

```bash
curl --fail --silent \
  -H "Authorization: Bearer $KK_COMPLAINTS_API_KEY" \
  "https://api.krypto-knight.com/public/integrations/complaints?updated_since=2026-07-01T00:00:00.000Z&limit=100"
```

## Complaint detail

```http
GET https://api.krypto-knight.com/public/integrations/complaints/{complaint_id}
```

The detail response includes attachment metadata. It intentionally excludes Compliance's internal notes.

## Download an attachment

```http
GET https://api.krypto-knight.com/public/integrations/complaints/{complaint_id}/attachments/{attachment_id}
```

Use the same bearer key. The response body is the original file and the response headers provide its MIME type and filename.

## Operational and security behavior

- Read-only: the integration cannot change complaint status, classification, assignment, notes, or resolution.
- Rate limit: 60 requests per minute per source IP.
- Every list, detail, and attachment access is written to the Krypto Knight audit log.
- Revoked or invalid keys receive HTTP 401.
- Complaint data contains personal information and must be handled under the applicable processor agreement, access controls, retention requirements, and GDPR safeguards.
