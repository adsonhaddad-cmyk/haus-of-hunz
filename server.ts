import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import path from 'node:path';
import dotenv from 'dotenv';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import type webpushTypes from 'web-push';
import { WebSocketServer, WebSocket } from 'ws';

const require = createRequire(import.meta.url);
const webpush = require('web-push') as typeof webpushTypes;
import {
  createInitialHouseholdState,
  DEFAULT_HOUSEHOLD_ID,
} from './src/data/seedData.ts';
import type {
  AuthUserSummary,
  AvatarConfig,
  HouseActivityLog,
  HouseholdState,
  HouseholdTask,
  HouseStyle,
  PenaltySettings,
  ShadeIntensity,
  ShoppingCategory,
  ShoppingUnit,
  TaskCategory,
  TaskFrequency,
  TaskPriority,
} from './src/types/household.ts';
import { computeDueAtIso, getTodayYMD } from './src/utils/dates.ts';
import {
  applyTaskCompletion,
  buildShadeMessage,
  checkPokeEligibility,
} from './src/utils/gameEngine.ts';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.cwd(), 'data');
const STORE_PATH = path.join(DATA_DIR, 'house-of-chores-store.json');
const VAPID_PATH = path.join(DATA_DIR, 'vapid-keys.json');
const SECRET_PATH = path.join(DATA_DIR, 'session-secret.txt');

interface StoredUser {
  userId: string;
  residentId: string;
  householdId: string;
  email: string;
  handle: string;
  name: string;
  passwordSalt: string;
  passwordHash: string;
  createdAt: string;
}

const firebaseAppletConfig = JSON.parse(
  fs.readFileSync(path.resolve(process.cwd(), 'firebase-applet-config.json'), 'utf8')
) as { projectId: string };
const FIREBASE_PROJECT_ID = firebaseAppletConfig.projectId;

interface StoredPushSub {
  id: string;
  uid?: string;
  residentId: string;
  householdId: string;
  subscription: {
    endpoint: string;
    expirationTime?: number | null;
    keys?: {
      p256dh: string;
      auth: string;
    };
  };
  userAgent?: string;
  createdAt: string;
}

interface ServerStore {
  users: StoredUser[];
  households: Record<string, HouseholdState>;
  inviteCodes: Record<string, string>;
  pushSubscriptions: StoredPushSub[];
}

interface SessionPayload {
  userId: string;
  residentId: string;
  householdId: string;
  exp: number;
}

interface AuthedRequest extends Request {
  authUser?: AuthUserSummary;
}

let cachedGoogleCerts: { certs: Record<string, string>; expiresAt: number } | null = null;

async function getGooglePublicCerts(): Promise<Record<string, string>> {
  if (cachedGoogleCerts && Date.now() < cachedGoogleCerts.expiresAt) {
    return cachedGoogleCerts.certs;
  }
  const resp = await fetch(
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'
  );
  if (!resp.ok) {
    throw new Error(`Failed to fetch Google x509 certs (${resp.status})`);
  }
  const cacheControl = resp.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/);
  const maxAgeSec = maxAgeMatch ? Number(maxAgeMatch[1]) : 3600;
  const certs = (await resp.json()) as Record<string, string>;
  cachedGoogleCerts = {
    certs,
    expiresAt: Date.now() + Math.max(60, maxAgeSec) * 1000,
  };
  return certs;
}

async function verifyFirebaseIdToken(
  idToken: string
): Promise<{ uid: string; email: string; name: string } | null> {
  try {
    const parts = idToken.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, sigB64] = parts;
    const header = JSON.parse(
      Buffer.from(headerB64, 'base64url').toString('utf8')
    ) as { alg?: string; kid?: string };
    if (header.alg !== 'RS256' || !header.kid) return null;

    const certs = await getGooglePublicCerts();
    const certPem = certs[header.kid];
    if (!certPem) return null;

    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();
    const sigBuf = Buffer.from(sigB64, 'base64url');
    if (!verifier.verify(certPem, sigBuf)) return null;

    const payload = JSON.parse(
      Buffer.from(payloadB64, 'base64url').toString('utf8')
    ) as {
      aud?: string;
      iss?: string;
      sub?: string;
      exp?: number;
      email?: string;
      email_verified?: boolean;
      name?: string;
    };

    const nowSec = Math.floor(Date.now() / 1000);
    if (
      payload.aud !== FIREBASE_PROJECT_ID ||
      payload.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}` ||
      !payload.sub ||
      typeof payload.exp !== 'number' ||
      payload.exp <= nowSec ||
      payload.email_verified !== true
    ) {
      return null;
    }

    return {
      uid: payload.sub,
      email: payload.email || '',
      name: payload.name || payload.email || 'Icon',
    };
  } catch {
    return null;
  }
}

fs.mkdirSync(DATA_DIR, { recursive: true });

function loadOrCreateSessionSecret(): string {
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16) {
    return process.env.SESSION_SECRET;
  }
  if (fs.existsSync(SECRET_PATH)) {
    const existing = fs.readFileSync(SECRET_PATH, 'utf8').trim();
    if (existing.length >= 16) return existing;
  }
  const generated = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_PATH, generated, 'utf8');
  return generated;
}

const SESSION_SECRET = loadOrCreateSessionSecret();

function loadOrCreateVapidKeys(): { publicKey: string; privateKey: string } {
  if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
    return {
      publicKey: process.env.VAPID_PUBLIC_KEY,
      privateKey: process.env.VAPID_PRIVATE_KEY,
    };
  }
  if (fs.existsSync(VAPID_PATH)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(VAPID_PATH, 'utf8')) as {
        publicKey?: string;
        privateKey?: string;
      };
      if (parsed.publicKey && parsed.privateKey) {
        return { publicKey: parsed.publicKey, privateKey: parsed.privateKey };
      }
    } catch {
      // Regenerate below
    }
  }
  const keys = webpush.generateVAPIDKeys();
  fs.writeFileSync(VAPID_PATH, JSON.stringify(keys, null, 2), 'utf8');
  return keys;
}

const VAPID_KEYS = loadOrCreateVapidKeys();
const VAPID_SUBJECT =
  process.env.VAPID_SUBJECT || 'mailto:haus@hausofhunz.app';
webpush.setVapidDetails(
  VAPID_SUBJECT,
  VAPID_KEYS.publicKey,
  VAPID_KEYS.privateKey
);

function hashPassword(password: string, salt?: string): {
  salt: string;
  hash: string;
} {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, actualSalt, 64).toString('hex');
  return { salt: actualSalt, hash };
}

function verifyPassword(
  password: string,
  salt: string,
  expectedHash: string
): boolean {
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(derived, 'hex');
  const b = Buffer.from(expectedHash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function createId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
}

function createInitialStore(): ServerStore {
  const initialHousehold = createInitialHouseholdState(new Date());
  const adsonPass = hashPassword('house-adson');
  const artyPass = hashPassword('house-arty');

  return {
    users: [
      {
        userId: 'user-adson',
        residentId: 'res-adson',
        householdId: DEFAULT_HOUSEHOLD_ID,
        email: 'adson@hausofhunz.app',
        handle: 'adson',
        name: 'Adson',
        passwordSalt: adsonPass.salt,
        passwordHash: adsonPass.hash,
        createdAt: new Date().toISOString(),
      },
      {
        userId: 'user-arty',
        residentId: 'res-arty',
        householdId: DEFAULT_HOUSEHOLD_ID,
        email: 'arty@hausofhunz.app',
        handle: 'arty',
        name: 'Arty',
        passwordSalt: artyPass.salt,
        passwordHash: artyPass.hash,
        createdAt: new Date().toISOString(),
      },
    ],
    households: {
      [DEFAULT_HOUSEHOLD_ID]: initialHousehold,
    },
    inviteCodes: {
      'HOUSE-TENS': DEFAULT_HOUSEHOLD_ID,
    },
    pushSubscriptions: [],
  };
}

function loadStore(): ServerStore {
  if (!fs.existsSync(STORE_PATH)) {
    const fresh = createInitialStore();
    fs.writeFileSync(STORE_PATH, JSON.stringify(fresh, null, 2), 'utf8');
    return fresh;
  }
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf8');
    const parsed = JSON.parse(raw) as Partial<ServerStore>;
    if (
      parsed &&
      Array.isArray(parsed.users) &&
      parsed.households &&
      typeof parsed.households === 'object'
    ) {
      return {
        users: parsed.users,
        households: parsed.households,
        inviteCodes: parsed.inviteCodes || {
          'HOUSE-TENS': DEFAULT_HOUSEHOLD_ID,
        },
        pushSubscriptions: Array.isArray(parsed.pushSubscriptions)
          ? parsed.pushSubscriptions
          : [],
      };
    }
  } catch (err) {
    console.error('Failed to read store file, recreating initial store:', err);
  }
  const fresh = createInitialStore();
  fs.writeFileSync(STORE_PATH, JSON.stringify(fresh, null, 2), 'utf8');
  return fresh;
}

let store: ServerStore = loadStore();
let writeChain: Promise<void> = Promise.resolve();

function persistStore(): Promise<void> {
  const snapshot = JSON.stringify(store, null, 2);
  writeChain = writeChain.then(async () => {
    const tmpPath = `${STORE_PATH}.tmp`;
    await fs.promises.writeFile(tmpPath, snapshot, 'utf8');
    await fs.promises.rename(tmpPath, STORE_PATH);
  });
  return writeChain;
}

function signSessionToken(payload: SessionPayload): string {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString(
    'base64url'
  );
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(body)
    .digest('base64url');
  return `${body}.${sig}`;
}

function verifySessionToken(token: string): SessionPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [body, sig] = parts;
    const expectedSig = crypto
      .createHmac('sha256', SESSION_SECRET)
      .update(body)
      .digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const decoded = JSON.parse(
      Buffer.from(body, 'base64url').toString('utf8')
    ) as SessionPayload;
    if (!decoded.userId || !decoded.householdId || decoded.exp < Date.now()) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const result: Record<string, string> = {};
  if (!cookieHeader) return result;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    result[key] = val;
  }
  return result;
}

function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const cookies = parseCookies(req.headers.cookie);
  return cookies.hoc_session || null;
}

function resolveAuthUser(token: string | null): AuthUserSummary | null {
  if (!token) return null;
  const payload = verifySessionToken(token);
  if (!payload) return null;
  const user = store.users.find((u) => u.userId === payload.userId);
  if (!user) return null;
  const household = store.households[user.householdId];
  if (!household) return null;
  const isMember = household.residents.some((r) => r.id === user.residentId);
  if (!isMember) return null;
  return {
    userId: user.userId,
    residentId: user.residentId,
    householdId: user.householdId,
    name: user.name,
    email: user.email,
    handle: user.handle,
  };
}

function prependActivity(
  logs: HouseActivityLog[],
  entry: Omit<HouseActivityLog, 'id' | 'createdAt'>
): HouseActivityLog[] {
  return [
    {
      ...entry,
      id: createId('log'),
      createdAt: new Date().toISOString(),
    },
    ...logs,
  ].slice(0, 60);
}

// WebSocket Connection Registry per household
interface WsClient {
  ws: WebSocket;
  userId: string;
  residentId: string;
  householdId: string;
}

const wsClients = new Set<WsClient>();

function getHouseholdOnlineResidents(householdId: string): string[] {
  const online = new Set<string>();
  for (const client of wsClients) {
    if (
      client.householdId === householdId &&
      client.ws.readyState === WebSocket.OPEN
    ) {
      online.add(client.residentId);
    }
  }
  return Array.from(online);
}

function broadcastHouseholdEvent(
  householdId: string,
  eventType: string,
  payload: Record<string, unknown>
): void {
  const msg = JSON.stringify({ type: eventType, payload });
  for (const client of wsClients) {
    if (
      client.householdId === householdId &&
      client.ws.readyState === WebSocket.OPEN
    ) {
      client.ws.send(msg);
    }
  }
}

async function dispatchWebPushToResident(
  residentId: string,
  householdId: string,
  payload: { title: string; body: string; tag?: string; url?: string }
): Promise<{ sent: number; failed: number; lastError?: string }> {
  const subs = store.pushSubscriptions.filter(
    (s) => s.residentId === residentId && s.householdId === householdId
  );
  if (subs.length === 0) {
    return { sent: 0, failed: 0 };
  }

  let sent = 0;
  let failed = 0;
  let lastError: string | undefined;
  const expiredIds = new Set<string>();

  await Promise.all(
    subs.map(async (sub) => {
      try {
        await webpush.sendNotification(
          sub.subscription as webpushTypes.PushSubscription,
          JSON.stringify(payload)
        );
        sent++;
      } catch (err: unknown) {
        failed++;
        const statusCode =
          typeof err === 'object' && err !== null && 'statusCode' in err
            ? Number((err as { statusCode?: number }).statusCode)
            : 0;
        lastError = err instanceof Error ? err.message : String(err);
        if (statusCode === 404 || statusCode === 410) {
          expiredIds.add(sub.id);
        }
      }
    })
  );

  if (expiredIds.size > 0) {
    store.pushSubscriptions = store.pushSubscriptions.filter(
      (s) => !expiredIds.has(s.id)
    );
    await persistStore();
  }

  return { sent, failed, lastError };
}

async function requireAuth(
  req: AuthedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  const token = extractToken(req);
  const legacyUser = resolveAuthUser(token);
  if (legacyUser) {
    req.authUser = legacyUser;
    next();
    return;
  }

  if (token) {
    const fbUser = await verifyFirebaseIdToken(token);
    if (fbUser) {
      const residentId = String(
        req.headers['x-resident-id'] ||
          req.body?.residentId ||
          req.query?.residentId ||
          fbUser.uid
      );
      const householdId = String(
        req.headers['x-household-id'] ||
          req.body?.householdId ||
          req.query?.householdId ||
          DEFAULT_HOUSEHOLD_ID
      );
      req.authUser = {
        userId: fbUser.uid,
        residentId,
        householdId,
        name: fbUser.name,
        email: fbUser.email,
        handle: (fbUser.email.split('@')[0] || 'icon').toLowerCase(),
      };
      next();
      return;
    }
  }

  res.status(401).json({ error: 'Authentication required' });
}

function getHouseholdForUser(authUser: AuthUserSummary): HouseholdState | null {
  const household = store.households[authUser.householdId];
  if (!household) return null;
  if (!household.residents.some((r) => r.id === authUser.residentId)) {
    return null;
  }
  return household;
}

function buildRuntimeMeta(householdId: string) {
  return {
    mode: 'express-realtime' as const,
    persistenceLabel: 'Express Server Store + Realtime WebSocket',
    persistentCloudConfigured: false,
    vapidConfigured: Boolean(VAPID_KEYS.publicKey && VAPID_KEYS.privateKey),
    vapidPublicKey: VAPID_KEYS.publicKey,
    onlineResidentIds: getHouseholdOnlineResidents(householdId),
    activeConnections: Array.from(wsClients).filter(
      (c) => c.householdId === householdId
    ).length,
  };
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  // Auth Routes
  app.get('/api/auth/me', (req: Request, res: Response) => {
    const authUser = resolveAuthUser(extractToken(req));
    if (!authUser) {
      res.status(200).json({ authenticated: false, user: null });
      return;
    }
    res.status(200).json({ authenticated: true, user: authUser });
  });

  app.post('/api/auth/login', (req: Request, res: Response) => {
    const identifier = String(req.body?.identifier || '')
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || '');

    const user = store.users.find(
      (u) =>
        u.email.toLowerCase() === identifier ||
        u.handle.toLowerCase() === identifier
    );

    if (!user || !verifyPassword(password, user.passwordSalt, user.passwordHash)) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const household = store.households[user.householdId];
    if (
      !household ||
      !household.residents.some((r) => r.id === user.residentId)
    ) {
      res.status(403).json({ error: 'Not a member of this household' });
      return;
    }

    const token = signSessionToken({
      userId: user.userId,
      residentId: user.residentId,
      householdId: user.householdId,
      exp: Date.now() + 30 * 24 * 3600 * 1000,
    });

    res.cookie('hoc_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 30 * 24 * 3600 * 1000,
    });

    res.status(200).json({
      token,
      user: {
        userId: user.userId,
        residentId: user.residentId,
        householdId: user.householdId,
        name: user.name,
        email: user.email,
        handle: user.handle,
      },
    });
  });

  app.post('/api/auth/register', async (req: Request, res: Response) => {
    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '')
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || '');
    const inviteCode = String(req.body?.inviteCode || '')
      .trim()
      .toUpperCase();

    if (!name || !email || password.length < 6) {
      res.status(400).json({
        error: 'Name, valid email, and password (6+ chars) are required',
      });
      return;
    }

    const targetHouseholdId = store.inviteCodes[inviteCode];
    if (!targetHouseholdId || !store.households[targetHouseholdId]) {
      res.status(403).json({ error: 'Invalid household invite code' });
      return;
    }

    if (store.users.some((u) => u.email.toLowerCase() === email)) {
      res.status(409).json({ error: 'Email already registered' });
      return;
    }

    const household = store.households[targetHouseholdId];
    const handle = name.toLowerCase().replace(/[^a-z0-9]/g, '') || 'icon';
    const residentId = createId('res');
    const userId = createId('user');
    const pass = hashPassword(password);

    const newUser: StoredUser = {
      userId,
      residentId,
      householdId: targetHouseholdId,
      email,
      handle,
      name,
      passwordSalt: pass.salt,
      passwordHash: pass.hash,
      createdAt: new Date().toISOString(),
    };

    store.users.push(newUser);
    household.residents.push({
      id: residentId,
      name,
      handle,
      email,
      role: 'partner',
      color: '#8EA8F5',
      points: 0,
      streak: 0,
      shadeIntensity: 'a_little_shady',
      muteShadeNotifications: false,
      pushEnabled: false,
      avatarConfig: {
        skinTone: 'honey',
        hairStyle: 'waves',
        facialHair: 'none',
        clothing: 'lavender_sweater',
        accessory: 'none',
        expression: 'smile',
        accentColor: '#8EA8F5',
      },
    });
    household.activityLog = prependActivity(household.activityLog, {
      type: 'house',
      actorId: residentId,
      summary: `${name} joined HAUS OF HUNZ`,
    });
    household.lastSyncedAt = new Date().toISOString();

    await persistStore();
    broadcastHouseholdEvent(targetHouseholdId, 'household:sync', {
      state: household,
      meta: buildRuntimeMeta(targetHouseholdId),
    });

    const token = signSessionToken({
      userId,
      residentId,
      householdId: targetHouseholdId,
      exp: Date.now() + 30 * 24 * 3600 * 1000,
    });

    res.cookie('hoc_session', token, {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 30 * 24 * 3600 * 1000,
    });

    res.status(201).json({
      token,
      user: {
        userId,
        residentId,
        householdId: targetHouseholdId,
        name,
        email,
        handle,
      },
    });
  });

  app.post('/api/auth/logout', (_req: Request, res: Response) => {
    res.clearCookie('hoc_session', { path: '/' });
    res.status(200).json({ ok: true });
  });

  app.post(
    '/api/auth/change-password',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const currentPassword = String(req.body?.currentPassword || '');
      const newPassword = String(req.body?.newPassword || '');
      if (newPassword.length < 6) {
        res
          .status(400)
          .json({ error: 'New password must be at least 6 characters' });
        return;
      }

      const user = store.users.find((u) => u.userId === authUser.userId);
      if (
        !user ||
        !verifyPassword(currentPassword, user.passwordSalt, user.passwordHash)
      ) {
        res.status(401).json({ error: 'Current password is incorrect' });
        return;
      }

      const nextPass = hashPassword(newPassword);
      user.passwordSalt = nextPass.salt;
      user.passwordHash = nextPass.hash;
      await persistStore();
      res.status(200).json({ ok: true });
    }
  );

  // Household State Fetch
  app.get(
    '/api/household',
    requireAuth,
    (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const inviteCode =
        Object.entries(store.inviteCodes).find(
          ([, hId]) => hId === household.householdId
        )?.[0] || 'HOUSE-TENS';

      res.status(200).json({
        state: household,
        user: authUser,
        inviteCode,
        meta: buildRuntimeMeta(household.householdId),
      });
    }
  );

  // Tasks Routes
  app.post(
    '/api/tasks',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const title = String(req.body?.title || '').trim();
      if (!title) {
        res.status(400).json({ error: 'Chore title is required' });
        return;
      }

      const dueDate = String(
        req.body?.dueDate || getTodayYMD(household.timeZone)
      );
      const dueTime = String(req.body?.dueTime || '20:00');
      const pool: string[] =
        Array.isArray(req.body?.participantIds) &&
        req.body.participantIds.length > 0
          ? req.body.participantIds.filter((id: string) =>
              household.residents.some((r) => r.id === id)
            )
          : household.residents.map((r) => r.id);

      const assignedToId = pool.includes(req.body?.assignedToId)
        ? String(req.body.assignedToId)
        : pool[0];

      const taskId = createId('task');
      const frequency = (req.body?.frequency || 'weekly') as TaskFrequency;
      const newTask: HouseholdTask = {
        id: taskId,
        title: title.slice(0, 120),
        description: req.body?.description
          ? String(req.body.description).trim().slice(0, 280)
          : undefined,
        category: (req.body?.category || 'Limpeza') as TaskCategory,
        points: Math.max(5, Math.min(200, Math.round(Number(req.body?.points) || 20))),
        priority: (req.body?.priority || 'media') as TaskPriority,
        frequency,
        customIntervalDays:
          frequency === 'custom'
            ? Math.max(1, Math.min(90, Number(req.body?.customIntervalDays) || 3))
            : undefined,
        assignedToId,
        participantIds: pool,
        dueDate,
        dueTime,
        dueAt: computeDueAtIso(dueDate, dueTime, household.timeZone),
        occurrenceSeq: 1,
        occurrenceId: `${taskId}::${dueDate}::1`,
        status: 'pending',
        history: [],
        createdAt: new Date().toISOString(),
      };

      household.tasks = [newTask, ...household.tasks];
      household.activityLog = prependActivity(household.activityLog, {
        type: 'task',
        actorId: authUser.residentId,
        summary: `Added chore "${newTask.title}" (${newTask.points} pts)`,
      });
      household.lastSyncedAt = new Date().toISOString();

      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(201).json({ state: household, task: newTask });
    }
  );

  app.patch(
    '/api/tasks/:taskId',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const task = household.tasks.find((t) => t.id === req.params.taskId);
      if (!task) {
        res.status(404).json({ error: 'Chore not found' });
        return;
      }

      const nowMs = Date.now();
      const body = req.body || {};

      if (body.action === 'pause') {
        task.status = 'paused';
        task.pausedUntil = body.pausedUntil ? String(body.pausedUntil) : undefined;
        task.pausedReason = body.pausedReason
          ? String(body.pausedReason).trim().slice(0, 120)
          : undefined;
        household.activityLog = prependActivity(household.activityLog, {
          type: 'task',
          actorId: authUser.residentId,
          summary: `Paused "${task.title}"${task.pausedReason ? ` (${task.pausedReason})` : ''}`,
        });
      } else if (body.action === 'resume') {
        task.status = 'pending';
        task.pausedUntil = undefined;
        task.pausedReason = undefined;
        household.activityLog = prependActivity(household.activityLog, {
          type: 'task',
          actorId: authUser.residentId,
          summary: `Resumed "${task.title}"`,
        });
      } else if (body.action === 'reassign' && body.assignedToId) {
        const nextId = String(body.assignedToId);
        if (!household.residents.some((r) => r.id === nextId)) {
          res.status(400).json({ error: 'Invalid resident' });
          return;
        }
        const beforeDeadline = nowMs <= new Date(task.dueAt).getTime();
        task.assignedToId = nextId;
        if (!task.participantIds.includes(nextId)) {
          task.participantIds = [...task.participantIds, nextId];
        }
        task.reassignedAt = new Date().toISOString();
        task.reassignedBeforeDeadline = beforeDeadline;
        const nextName =
          household.residents.find((r) => r.id === nextId)?.name || 'Partner';
        household.activityLog = prependActivity(household.activityLog, {
          type: 'task',
          actorId: authUser.residentId,
          summary: `Reassigned "${task.title}" to ${nextName}`,
        });
      } else {
        const title = body.title ? String(body.title).trim() : task.title;
        if (!title) {
          res.status(400).json({ error: 'Title cannot be empty' });
          return;
        }
        task.title = title.slice(0, 120);
        task.description =
          body.description !== undefined
            ? String(body.description).trim().slice(0, 280) || undefined
            : task.description;
        if (body.category) task.category = body.category as TaskCategory;
        if (body.points) {
          task.points = Math.max(
            5,
            Math.min(200, Math.round(Number(body.points)))
          );
        }
        if (body.priority) task.priority = body.priority as TaskPriority;
        if (body.frequency) task.frequency = body.frequency as TaskFrequency;
        if (task.frequency === 'custom') {
          task.customIntervalDays = Math.max(
            1,
            Math.min(90, Number(body.customIntervalDays) || 3)
          );
        } else {
          task.customIntervalDays = undefined;
        }
        if (Array.isArray(body.participantIds) && body.participantIds.length > 0) {
          task.participantIds = body.participantIds;
        }
        if (body.assignedToId) {
          if (body.assignedToId !== task.assignedToId) {
            task.reassignedAt = new Date().toISOString();
            task.reassignedBeforeDeadline =
              nowMs <= new Date(task.dueAt).getTime();
          }
          task.assignedToId = String(body.assignedToId);
        }
        if (body.dueDate) task.dueDate = String(body.dueDate);
        if (body.dueTime) task.dueTime = String(body.dueTime);
        task.dueAt = computeDueAtIso(
          task.dueDate,
          task.dueTime || '20:00',
          household.timeZone
        );
      }

      household.lastSyncedAt = new Date().toISOString();
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household, task });
    }
  );

  app.post(
    '/api/tasks/:taskId/complete',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const task = household.tasks.find((t) => t.id === req.params.taskId);
      if (!task) {
        res.status(404).json({ error: 'Chore not found' });
        return;
      }

      const nowIso = new Date().toISOString();
      // Award completion to the authenticated user completing it (or assigned partner if triggered on shared board)
      const executorId = authUser.residentId;
      const result = applyTaskCompletion(
        task,
        household.residents,
        household.pointLedger,
        executorId,
        nowIso,
        household.timeZone,
        household.penaltySettings
      );

      if (!result.completed || !result.transaction) {
        res.status(409).json({
          error:
            result.reason === 'paused'
              ? 'Chore is paused'
              : 'Chore occurrence already completed',
        });
        return;
      }

      household.residents = result.updatedResidents;
      household.tasks = household.tasks.map((t) =>
        t.id === task.id ? result.updatedTask : t
      );
      household.pointLedger = [result.transaction, ...household.pointLedger];

      const actorName =
        household.residents.find((r) => r.id === result.executorId)?.name ||
        authUser.name;

      household.activityLog = prependActivity(household.activityLog, {
        type: result.penaltyPoints > 0 ? 'penalty' : 'task',
        actorId: result.executorId,
        summary:
          result.penaltyPoints > 0
            ? `${actorName} completed "${task.title}" late (-${result.penaltyPercent}% penalty, +${result.pointsAwarded} pts)`
            : `${actorName} served "${task.title}" (+${result.pointsAwarded} pts)`,
      });

      if (result.penaltyPoints > 0) {
        household.notifications = [
          {
            id: createId('notif'),
            recipientId: result.executorId,
            type: 'penalty' as const,
            title: 'Not the deadline getting ghosted.',
            body: `"${task.title}" was completed late (-${result.penaltyPercent}%, ${result.penaltyPoints} pts deducted). You earned ${result.pointsAwarded} pts.`,
            taskId: task.id,
            createdAt: nowIso,
          },
          ...household.notifications,
        ].slice(0, 50);
      }

      household.lastSyncedAt = nowIso;
      await persistStore();

      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });

      res.status(200).json({
        state: household,
        completion: result,
      });
    }
  );

  app.delete(
    '/api/tasks/:taskId',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const target = household.tasks.find((t) => t.id === req.params.taskId);
      if (!target) {
        res.status(404).json({ error: 'Chore not found' });
        return;
      }

      household.tasks = household.tasks.filter((t) => t.id !== target.id);
      household.activityLog = prependActivity(household.activityLog, {
        type: 'task',
        actorId: authUser.residentId,
        summary: `Removed chore "${target.title}"`,
      });
      household.lastSyncedAt = new Date().toISOString();
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household });
    }
  );

  // POKE & SHADE Route (Server-enforced overdue, cooldown, cap, and consent)
  app.post(
    '/api/tasks/:taskId/poke',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const task = household.tasks.find((t) => t.id === req.params.taskId);
      if (!task) {
        res.status(404).json({ error: 'Chore not found' });
        return;
      }

      const recipient = household.residents.find(
        (r) => r.id === task.assignedToId
      );
      if (!recipient) {
        res.status(400).json({ error: 'Assigned housemate not found' });
        return;
      }

      const nowMs = Date.now();
      const eligibility = checkPokeEligibility(
        task,
        authUser.residentId,
        recipient,
        household.pokes,
        nowMs,
        household.penaltySettings
      );

      if (!eligibility.allowed) {
        res.status(422).json({
          error: eligibility.reason || 'Poke not permitted',
          eligibility,
        });
        return;
      }

      const locale = req.body?.locale === 'pt-BR' ? 'pt-BR' : 'en-US';
      const intensity: ShadeIntensity = recipient.shadeIntensity;
      const message = buildShadeMessage(
        intensity,
        recipient.name,
        task.title,
        locale,
        household.pokes.length
      );
      const nowIso = new Date(nowMs).toISOString();

      const pushResult = await dispatchWebPushToResident(
        recipient.id,
        household.householdId,
        {
          title: `${authUser.name} threw some shade 💅`,
          body: message,
          tag: `poke-${task.occurrenceId}`,
          url: '/',
        }
      );

      const poke = {
        id: createId('poke'),
        taskId: task.id,
        taskTitle: task.title,
        occurrenceId: task.occurrenceId,
        fromResidentId: authUser.residentId,
        toResidentId: recipient.id,
        intensity,
        message,
        deliveredViaPush: pushResult.sent > 0,
        createdAt: nowIso,
      };

      const notification = {
        id: createId('notif'),
        recipientId: recipient.id,
        senderId: authUser.residentId,
        type: 'poke' as const,
        title: `You've been READ by ${authUser.name}.`,
        body: message,
        taskId: task.id,
        intensity,
        createdAt: nowIso,
      };

      household.pokes = [poke, ...household.pokes].slice(0, 80);
      household.notifications = [notification, ...household.notifications].slice(
        0,
        60
      );
      household.activityLog = prependActivity(household.activityLog, {
        type: 'poke',
        actorId: authUser.residentId,
        summary: `Threw shade at ${recipient.name} over "${task.title}"`,
      });
      household.lastSyncedAt = nowIso;

      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'poke:received', {
        poke,
        notification,
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });

      res.status(201).json({
        state: household,
        poke,
        pushDelivered: pushResult.sent > 0,
      });
    }
  );

  // Chore Swap Requests (Mutual Confirmation)
  app.post(
    '/api/swaps',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const task = household.tasks.find((t) => t.id === req.body?.taskId);
      const partner = household.residents.find(
        (r) => r.id !== authUser.residentId
      );
      if (!task || !partner) {
        res.status(400).json({ error: 'Valid chore and partner required' });
        return;
      }

      const existing = household.swapRequests.find(
        (s) => s.taskId === task.id && s.status === 'pending'
      );
      if (existing) {
        res.status(409).json({ error: 'Swap request already pending' });
        return;
      }

      const nowIso = new Date().toISOString();
      const swap = {
        id: createId('swap'),
        taskId: task.id,
        taskTitle: task.title,
        fromResidentId: authUser.residentId,
        toResidentId: partner.id,
        note: req.body?.note
          ? String(req.body.note).trim().slice(0, 120)
          : undefined,
        status: 'pending' as const,
        createdAt: nowIso,
      };

      household.swapRequests = [swap, ...household.swapRequests].slice(0, 40);
      household.notifications = [
        {
          id: createId('notif'),
          recipientId: partner.id,
          senderId: authUser.residentId,
          type: 'swap' as const,
          title: `${authUser.name} requested a chore swap`,
          body: `"${task.title}"${swap.note ? ` — "${swap.note}"` : ''}`,
          taskId: task.id,
          createdAt: nowIso,
        },
        ...household.notifications,
      ].slice(0, 60);
      household.activityLog = prependActivity(household.activityLog, {
        type: 'swap',
        actorId: authUser.residentId,
        summary: `Requested swap with ${partner.name} for "${task.title}"`,
      });
      household.lastSyncedAt = nowIso;

      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(201).json({ state: household, swap });
    }
  );

  app.post(
    '/api/swaps/:swapId/respond',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const swap = household.swapRequests.find(
        (s) => s.id === req.params.swapId
      );
      if (!swap || swap.status !== 'pending') {
        res.status(404).json({ error: 'Pending swap not found' });
        return;
      }

      const decision = String(req.body?.decision || '');
      const nowIso = new Date().toISOString();

      if (decision === 'cancel' && swap.fromResidentId === authUser.residentId) {
        swap.status = 'cancelled';
        swap.respondedAt = nowIso;
      } else if (
        (decision === 'accept' || decision === 'decline') &&
        swap.toResidentId === authUser.residentId
      ) {
        swap.status = decision === 'accept' ? 'accepted' : 'declined';
        swap.respondedAt = nowIso;

        if (decision === 'accept') {
          const task = household.tasks.find((t) => t.id === swap.taskId);
          if (task) {
            const newAssignee =
              task.assignedToId === swap.fromResidentId
                ? swap.toResidentId
                : swap.fromResidentId;
            task.reassignedAt = nowIso;
            task.reassignedBeforeDeadline =
              Date.now() <= new Date(task.dueAt).getTime();
            task.assignedToId = newAssignee;
          }
          household.activityLog = prependActivity(household.activityLog, {
            type: 'swap',
            actorId: authUser.residentId,
            summary: `Accepted swap for "${swap.taskTitle}"`,
          });
        } else {
          household.activityLog = prependActivity(household.activityLog, {
            type: 'swap',
            actorId: authUser.residentId,
            summary: `Declined swap for "${swap.taskTitle}"`,
          });
        }
      } else {
        res.status(403).json({ error: 'Not authorized to respond to this swap' });
        return;
      }

      household.lastSyncedAt = nowIso;
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household, swap });
    }
  );

  // Shopping Routes (Strictly NO financial fields)
  app.post(
    '/api/shopping',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const name = String(req.body?.name || '').trim();
      if (!name) {
        res.status(400).json({ error: 'Item name is required' });
        return;
      }

      const item = {
        id: createId('shop'),
        name: name.slice(0, 100),
        quantity: Math.max(0.1, Number(req.body?.quantity) || 1),
        unit: (req.body?.unit || 'un') as ShoppingUnit,
        category: (req.body?.category || 'Mercado') as ShoppingCategory,
        authorId: authUser.residentId,
        status: 'pending' as const,
        createdAt: new Date().toISOString(),
      };

      household.shoppingItems = [item, ...household.shoppingItems];
      household.activityLog = prependActivity(household.activityLog, {
        type: 'shopping',
        actorId: authUser.residentId,
        summary: `Added "${item.name}" to shopping list`,
      });
      household.lastSyncedAt = new Date().toISOString();

      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(201).json({ state: household, item });
    }
  );

  app.patch(
    '/api/shopping/:itemId',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const item = household.shoppingItems.find(
        (i) => i.id === req.params.itemId
      );
      if (!item) {
        res.status(404).json({ error: 'Shopping item not found' });
        return;
      }

      const body = req.body || {};
      if (body.action === 'mark_bought') {
        item.status = 'bought';
        item.boughtAt = new Date().toISOString();
        item.buyerId = authUser.residentId;
        household.activityLog = prependActivity(household.activityLog, {
          type: 'shopping',
          actorId: authUser.residentId,
          summary: `Picked up "${item.name}"`,
        });
      } else if (body.action === 'restore') {
        item.status = 'pending';
        item.boughtAt = undefined;
        item.buyerId = undefined;
      } else {
        const name = body.name ? String(body.name).trim() : item.name;
        if (!name) {
          res.status(400).json({ error: 'Item name cannot be empty' });
          return;
        }
        item.name = name.slice(0, 100);
        if (body.quantity !== undefined) {
          item.quantity = Math.max(0.1, Number(body.quantity) || 1);
        }
        if (body.unit) item.unit = body.unit as ShoppingUnit;
        if (body.category) item.category = body.category as ShoppingCategory;
      }

      household.lastSyncedAt = new Date().toISOString();
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household, item });
    }
  );

  app.delete(
    '/api/shopping/:itemId',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }
      household.shoppingItems = household.shoppingItems.filter(
        (i) => i.id !== req.params.itemId
      );
      household.lastSyncedAt = new Date().toISOString();
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household });
    }
  );

  // Pinboard Notes Routes
  app.post(
    '/api/notes',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }
      const content = String(req.body?.content || '').trim();
      if (!content) {
        res.status(400).json({ error: 'Note content required' });
        return;
      }
      const nowIso = new Date().toISOString();
      const note = {
        id: createId('note'),
        authorId: authUser.residentId,
        content: content.slice(0, 220),
        pinned: Boolean(req.body?.pinned),
        createdAt: nowIso,
        updatedAt: nowIso,
      };
      household.pinNotes = [note, ...household.pinNotes];
      household.lastSyncedAt = nowIso;
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(201).json({ state: household, note });
    }
  );

  app.patch(
    '/api/notes/:noteId',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }
      const note = household.pinNotes.find((n) => n.id === req.params.noteId);
      if (!note) {
        res.status(404).json({ error: 'Note not found' });
        return;
      }
      if (req.body?.togglePin) {
        note.pinned = !note.pinned;
      }
      if (typeof req.body?.content === 'string') {
        const trimmed = req.body.content.trim();
        if (!trimmed) {
          res.status(400).json({ error: 'Note content required' });
          return;
        }
        note.content = trimmed.slice(0, 220);
      }
      note.updatedAt = new Date().toISOString();
      household.lastSyncedAt = note.updatedAt;
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household, note });
    }
  );

  app.delete(
    '/api/notes/:noteId',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }
      household.pinNotes = household.pinNotes.filter(
        (n) => n.id !== req.params.noteId
      );
      household.lastSyncedAt = new Date().toISOString();
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household });
    }
  );

  // Notifications Read Route
  app.post(
    '/api/notifications/read-all',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }
      const nowIso = new Date().toISOString();
      household.notifications = household.notifications.map((n) =>
        n.recipientId === authUser.residentId && !n.readAt
          ? { ...n, readAt: nowIso }
          : n
      );
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household });
    }
  );

  // Own Resident Profile & Avatar Customization + Shade Preferences
  app.patch(
    '/api/resident/me',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const resident = household.residents.find(
        (r) => r.id === authUser.residentId
      );
      if (!resident) {
        res.status(404).json({ error: 'Resident profile not found' });
        return;
      }

      const body = req.body || {};
      if (typeof body.name === 'string' && body.name.trim()) {
        resident.name = body.name.trim().slice(0, 30);
        const userRecord = store.users.find((u) => u.userId === authUser.userId);
        if (userRecord) userRecord.name = resident.name;
      }
      if (typeof body.color === 'string') {
        resident.color = body.color;
      }
      if (
        body.shadeIntensity === 'soft_serve' ||
        body.shadeIntensity === 'a_little_shady' ||
        body.shadeIntensity === 'full_ballroom'
      ) {
        resident.shadeIntensity = body.shadeIntensity as ShadeIntensity;
      }
      if (typeof body.muteShadeNotifications === 'boolean') {
        resident.muteShadeNotifications = body.muteShadeNotifications;
      }
      if (body.avatarConfig && typeof body.avatarConfig === 'object') {
        const cfg = body.avatarConfig as Partial<AvatarConfig>;
        resident.avatarConfig = {
          ...resident.avatarConfig,
          ...cfg,
          customPhotoUrl:
            cfg.customPhotoUrl === ''
              ? undefined
              : cfg.customPhotoUrl ?? resident.avatarConfig.customPhotoUrl,
        };
      }

      household.lastSyncedAt = new Date().toISOString();
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household, resident });
    }
  );

  // Household Settings & Penalty Rules
  app.patch(
    '/api/household/settings',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const household = getHouseholdForUser(authUser);
      if (!household) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const body = req.body || {};
      if (typeof body.houseName === 'string' && body.houseName.trim()) {
        household.houseName = body.houseName.trim().slice(0, 50);
      }
      if (typeof body.tagline === 'string' && body.tagline.trim()) {
        household.tagline = body.tagline.trim().slice(0, 80);
      }
      if (
        body.houseStyle === 'apartment' ||
        body.houseStyle === 'loft' ||
        body.houseStyle === 'garden'
      ) {
        household.houseStyle = body.houseStyle as HouseStyle;
      }
      if (typeof body.timeZone === 'string' && body.timeZone.trim()) {
        household.timeZone = body.timeZone.trim();
        household.tasks = household.tasks.map((t) => ({
          ...t,
          dueAt: computeDueAtIso(t.dueDate, t.dueTime || '20:00', household.timeZone),
        }));
      }
      if (body.preferences && typeof body.preferences === 'object') {
        household.preferences = {
          weeklyPointsGoal: Math.max(
            20,
            Math.min(
              1000,
              Number(body.preferences.weeklyPointsGoal) ||
                household.preferences.weeklyPointsGoal
            )
          ),
          reducedMotionOverride:
            typeof body.preferences.reducedMotionOverride === 'boolean'
              ? body.preferences.reducedMotionOverride
              : household.preferences.reducedMotionOverride,
        };
      }
      if (body.penaltySettings && typeof body.penaltySettings === 'object') {
        const nextPenalty = body.penaltySettings as Partial<PenaltySettings>;
        household.penaltySettings = {
          enabled:
            typeof nextPenalty.enabled === 'boolean'
              ? nextPenalty.enabled
              : household.penaltySettings.enabled,
          gracePeriodMinutes: Math.max(
            0,
            Math.min(
              720,
              Number(nextPenalty.gracePeriodMinutes ?? household.penaltySettings.gracePeriodMinutes)
            )
          ),
          tiers: Array.isArray(nextPenalty.tiers) && nextPenalty.tiers.length > 0
            ? nextPenalty.tiers.map((tier) => ({
                maxDelayMinutes: Math.max(1, Number(tier.maxDelayMinutes) || 60),
                deductionPercent: Math.max(0, Math.min(100, Number(tier.deductionPercent) || 0)),
              }))
            : household.penaltySettings.tiers,
          reminderFrequencyHours: Math.max(
            1,
            Math.min(
              72,
              Number(nextPenalty.reminderFrequencyHours ?? household.penaltySettings.reminderFrequencyHours)
            )
          ),
          maxPokesPerOccurrence: Math.max(
            1,
            Math.min(
              5,
              Number(nextPenalty.maxPokesPerOccurrence ?? household.penaltySettings.maxPokesPerOccurrence)
            )
          ),
        };
      }

      household.activityLog = prependActivity(household.activityLog, {
        type: 'house',
        actorId: authUser.residentId,
        summary: `${authUser.name} updated household settings`,
      });
      household.lastSyncedAt = new Date().toISOString();
      await persistStore();
      broadcastHouseholdEvent(household.householdId, 'household:sync', {
        state: household,
        meta: buildRuntimeMeta(household.householdId),
      });
      res.status(200).json({ state: household });
    }
  );

  // Web Push Subscription & Real Test / Poke Dispatch
  app.get(
    '/api/push/vapid-public-key',
    requireAuth,
    (_req: AuthedRequest, res: Response) => {
      res.status(200).json({ publicKey: VAPID_KEYS.publicKey });
    }
  );

  app.post(
    '/api/push/subscribe',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const residentId = String(req.body?.residentId || authUser.residentId);
      const householdId = String(req.body?.householdId || authUser.householdId);
      const household = getHouseholdForUser(authUser);

      const subscription = req.body?.subscription;
      if (!subscription || typeof subscription.endpoint !== 'string') {
        res.status(400).json({ error: 'Valid PushSubscription required' });
        return;
      }

      const existingIdx = store.pushSubscriptions.findIndex(
        (s) =>
          s.residentId === residentId &&
          s.householdId === householdId &&
          s.subscription.endpoint === subscription.endpoint
      );

      if (existingIdx >= 0) {
        store.pushSubscriptions[existingIdx].subscription = subscription;
        store.pushSubscriptions[existingIdx].uid = authUser.userId;
      } else {
        store.pushSubscriptions.push({
          id: createId('push'),
          uid: authUser.userId,
          residentId,
          householdId,
          subscription,
          userAgent: req.headers['user-agent'],
          createdAt: new Date().toISOString(),
        });
      }

      if (household) {
        const resident = household.residents.find((r) => r.id === residentId);
        if (resident) resident.pushEnabled = true;
      }

      await persistStore();
      if (household) {
        broadcastHouseholdEvent(household.householdId, 'household:sync', {
          state: household,
          meta: buildRuntimeMeta(household.householdId),
        });
      }
      res.status(201).json({ ok: true, state: household });
    }
  );

  app.delete(
    '/api/push/subscribe',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const residentId = String(req.body?.residentId || authUser.residentId);
      const householdId = String(req.body?.householdId || authUser.householdId);
      const household = getHouseholdForUser(authUser);
      store.pushSubscriptions = store.pushSubscriptions.filter(
        (s) => !(s.residentId === residentId && s.householdId === householdId)
      );
      if (household) {
        const resident = household.residents.find((r) => r.id === residentId);
        if (resident) resident.pushEnabled = false;
      }
      await persistStore();
      res.status(200).json({ ok: true, state: household });
    }
  );

  app.post(
    '/api/push/test',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const residentId = String(req.body?.residentId || authUser.residentId);
      const householdId = String(req.body?.householdId || authUser.householdId);
      const result = await dispatchWebPushToResident(residentId, householdId, {
        title: 'HAUS OF HUNZ ✨',
        body: `Category is: PUSH REALNESS, ${authUser.name}! Your device received a live test push.`,
        tag: `test-push-${Date.now()}`,
        url: '/',
      });

      if (result.sent === 0) {
        res.status(422).json({
          delivered: false,
          sent: 0,
          failed: result.failed,
          error:
            result.lastError ||
            'No active push subscription registered for your device yet.',
        });
        return;
      }

      res.status(200).json({
        delivered: true,
        sent: result.sent,
        failed: result.failed,
      });
    }
  );

  app.post(
    '/api/push/poke',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const recipientId = String(req.body?.recipientId || '');
      const householdId = String(req.body?.householdId || authUser.householdId);
      const title = String(req.body?.title || 'HAUS OF HUNZ 💅');
      const body = String(req.body?.body || '');
      const tag = String(req.body?.tag || `poke-${Date.now()}`);

      if (!recipientId || !body) {
        res.status(400).json({ error: 'recipientId and body required' });
        return;
      }

      const result = await dispatchWebPushToResident(recipientId, householdId, {
        title: title.slice(0, 120),
        body: body.slice(0, 280),
        tag: tag.slice(0, 120),
        url: '/',
      });

      res.status(200).json({
        delivered: result.sent > 0,
        sent: result.sent,
        failed: result.failed,
      });
    }
  );

  app.post(
    '/api/household/reset-demo',
    requireAuth,
    async (req: AuthedRequest, res: Response) => {
      const authUser = req.authUser!;
      const existing = getHouseholdForUser(authUser);
      if (!existing) {
        res.status(403).json({ error: 'Household access denied' });
        return;
      }

      const fresh = createInitialHouseholdState(new Date());
      fresh.householdId = existing.householdId;
      store.households[existing.householdId] = fresh;
      await persistStore();
      broadcastHouseholdEvent(existing.householdId, 'household:sync', {
        state: fresh,
        meta: buildRuntimeMeta(existing.householdId),
      });
      res.status(200).json({ state: fresh });
    }
  );

  const httpServer = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true });

  // Mount Vite Dev Middleware OR Static Prod Dist
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const hmrDisabled = process.env.DISABLE_HMR === 'true';
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        ws: {
          server: httpServer,
        },
        hmr: !hmrDisabled,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  httpServer.on('upgrade', async (request, socket, head) => {
    const protocol = String(request.headers['sec-websocket-protocol'] || '');
    if (protocol === 'vite-hmr' || protocol === 'vite-ping') {
      // Handled by Vite's attached upgrade listener when HMR is active
      return;
    }

    const reqUrl = new URL(
      request.url || '/',
      `http://${request.headers.host || 'localhost'}`
    );
    if (reqUrl.pathname !== '/ws') {
      socket.destroy();
      return;
    }

    const tokenFromQuery = reqUrl.searchParams.get('token');
    const cookies = parseCookies(request.headers.cookie);
    const rawToken = tokenFromQuery || cookies.hoc_session || null;
    let authUser = resolveAuthUser(rawToken);

    if (!authUser && rawToken) {
      const fbUser = await verifyFirebaseIdToken(rawToken);
      if (fbUser) {
        const residentId = reqUrl.searchParams.get('residentId') || fbUser.uid;
        const householdId = reqUrl.searchParams.get('householdId') || DEFAULT_HOUSEHOLD_ID;
        authUser = {
          userId: fbUser.uid,
          residentId,
          householdId,
          name: fbUser.name,
          email: fbUser.email,
          handle: (fbUser.email.split('@')[0] || 'icon').toLowerCase(),
        };
      }
    }

    if (!authUser) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
      const client: WsClient = {
        ws,
        userId: authUser.userId,
        residentId: authUser.residentId,
        householdId: authUser.householdId,
      };
      wsClients.add(client);

      broadcastHouseholdEvent(authUser.householdId, 'presence:updated', {
        onlineResidentIds: getHouseholdOnlineResidents(authUser.householdId),
      });

      ws.on('close', () => {
        wsClients.delete(client);
        broadcastHouseholdEvent(authUser.householdId, 'presence:updated', {
          onlineResidentIds: getHouseholdOnlineResidents(authUser.householdId),
        });
      });
    });
  });

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`THE_HOUSE_OF_CHORES_SERVER_READY on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
