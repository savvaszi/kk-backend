import { db } from '../db/index.js';
import { auditLogs, adminNotifications } from '../db/schema.js';

interface AuditEntry {
  userId?: string | null;
  userName?: string | null;
  action: string;
  detail?: string;
  type: 'auth' | 'user' | 'api' | 'security' | 'wallet' | 'admin' | 'webhook';
  severity: 'info' | 'warning' | 'danger' | 'success';
  ipAddress?: string;
  metadata?: Record<string, unknown>;
  notify?: boolean;
}

export async function logAudit(entry: AuditEntry) {
  await db.insert(auditLogs).values({
    userId: entry.userId ?? null,
    userName: entry.userName ?? null,
    action: entry.action,
    detail: entry.detail ?? null,
    type: entry.type,
    severity: entry.severity,
    ipAddress: entry.ipAddress ?? null,
    metadata: entry.metadata ?? null,
  });

  if (entry.notify) {
    const typeMap = { danger: 'danger', warning: 'warning', info: 'info', success: 'success' } as const;
    await db.insert(adminNotifications).values({
      title: entry.action,
      body: entry.detail ?? entry.action,
      type: typeMap[entry.severity],
    });
  }
}
