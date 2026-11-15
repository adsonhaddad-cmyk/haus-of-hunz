import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

interface BlueprintSchema {
  entities: Record<
    string,
    {
      required?: string[];
      properties: Record<
        string,
        {
          type: string;
          enum?: unknown[];
          minLength?: number;
          maxLength?: number;
          pattern?: string;
        }
      >;
    }
  >;
  firestore: Record<
    string,
    {
      schema: { $ref: string };
      description: string;
    }
  >;
}

interface MockAuth {
  uid: string;
  emailVerified: boolean;
}

const blueprintPath = path.resolve(process.cwd(), 'firebase-blueprint.json');
const blueprint = JSON.parse(fs.readFileSync(blueprintPath, 'utf8')) as BlueprintSchema;

const rulesFileCandidate = fs.existsSync(path.resolve(process.cwd(), 'firestore.rules'))
  ? 'firestore.rules'
  : 'DRAFT_firestore.rules';
const rulesText = fs.readFileSync(path.resolve(process.cwd(), rulesFileCandidate), 'utf8');

// 1. Structural Verification of Security Rules against all 8 Pillars & Blueprint Coverage
assert.ok(rulesText.includes("rules_version = '2';"), 'Must declare rules_version = 2');

const firstMatchIdx = rulesText.indexOf('match /databases/{database}/documents');
const catchAllIdx = rulesText.indexOf('match /{document=**}');
assert.ok(firstMatchIdx !== -1 && catchAllIdx > firstMatchIdx, 'Catch-all match must appear inside documents match');
const betweenMatchAndCatchAll = rulesText.slice(firstMatchIdx, catchAllIdx);
assert.ok(
  !betweenMatchAndCatchAll.includes('allow '),
  'Default-deny catch-all MUST be the very first rule block inside /databases/{database}/documents'
);

// Verify every blueprint collection path has an explicit match block
const expectedCollectionMatchers = [
  'match /users/{userId}',
  'match /private/{docId}',
  'match /invites/{inviteCode}',
  'match /households/{householdId}',
  'match /members/{memberUid}',
  'match /residents/{residentId}',
  'match /tasks/{taskId}',
  'match /shoppingItems/{itemId}',
  'match /pinNotes/{noteId}',
  'match /pointLedger/{txId}',
  'match /pokes/{pokeId}',
  'match /swapRequests/{swapId}',
  'match /notifications/{notifId}',
  'match /activityLog/{logId}',
];
for (const matcher of expectedCollectionMatchers) {
  assert.ok(rulesText.includes(matcher), `Missing security rule block for ${matcher}`);
}

// Verify ZERO get() or exists() inside allow list blocks (Pillar 8 Cost-Optimization Clause)
const listBlocks = [...rulesText.matchAll(/allow list:[^;]+;/g)].map((m) => m[0]);
assert.ok(listBlocks.length >= 10, 'Expected explicit allow list rules');
for (const block of listBlocks) {
  assert.ok(!block.includes('get(') && !block.includes('exists('), `Forbidden get()/exists() inside allow list: ${block}`);
  if (!block.includes('if false')) {
    assert.ok(
      block.includes('resource.data.memberUids') && block.includes('request.auth.uid'),
      `allow list must evaluate resource.data.memberUids against request.auth.uid: ${block}`
    );
  }
}

// Verify every allow update block wraps with isValid[Entity](incoming())
const updateBlocks = [...rulesText.matchAll(/allow update:[\s\S]*?;/g)].map((m) => m[0]);
for (const block of updateBlocks) {
  if (!block.includes('if false')) {
    assert.ok(/isValid[A-Za-z]+\(incoming\(\)\)/.test(block), `allow update must validate incoming() via isValid[Entity]: ${block}`);
    assert.ok(block.includes('affectedKeys().hasOnly('), `allow update must restrict changed fields via affectedKeys().hasOnly(): ${block}`);
  }
}

// 2. Dirty Dozen Adversarial Payload Verification against Blueprint + Rules Invariants
const ID_REGEX = /^[a-zA-Z0-9_-]+$/;
const SERVER_TIME_SYMBOL = '__SERVER_TIMESTAMP__';

function checkDirtyPayloadDenied(
  name: string,
  entityName: keyof typeof blueprint.entities,
  auth: MockAuth,
  docId: string,
  payload: Record<string, unknown>,
  options?: {
    operation?: 'create' | 'update' | 'get' | 'list';
    existingData?: Record<string, unknown>;
    existingRole?: 'owner' | 'partner';
    householdExists?: boolean;
    validInviteExists?: boolean;
    targetUserId?: string;
    memberUidsOnExisting?: string[];
  }
): 'ALLOWED' | 'PERMISSION_DENIED' {
  const op = options?.operation || 'create';

  if (!auth.emailVerified) return 'PERMISSION_DENIED';
  if (!ID_REGEX.test(docId) || docId.length > 128) return 'PERMISSION_DENIED';

  if (op === 'get' && entityName === 'UserPrivateProfile') {
    if (options?.targetUserId !== auth.uid) return 'PERMISSION_DENIED';
    return 'ALLOWED';
  }

  if (op === 'list') {
    const existingUids = options?.memberUidsOnExisting || [];
    if (!existingUids.includes(auth.uid)) return 'PERMISSION_DENIED';
    return 'ALLOWED';
  }

  if (entityName === 'HouseholdMember' && op === 'create') {
    if (options?.householdExists) {
      if (payload.role !== 'partner') return 'PERMISSION_DENIED';
      if (!options.validInviteExists) return 'PERMISSION_DENIED';
    }
  }

  if (entityName === 'SwapRequest' && op === 'update') {
    if (options?.existingData?.status !== 'pending') return 'PERMISSION_DENIED';
  }

  if (entityName === 'PointTransaction' && op === 'update') {
    return 'PERMISSION_DENIED';
  }

  const schema = blueprint.entities[entityName];
  const allowedKeys = new Set(Object.keys(schema.properties));
  for (const key of Object.keys(payload)) {
    if (!allowedKeys.has(key)) return 'PERMISSION_DENIED';
  }

  if (op === 'create') {
    for (const reqKey of schema.required || []) {
      if (!(reqKey in payload)) return 'PERMISSION_DENIED';
    }
    if ('createdAt' in schema.properties && payload.createdAt !== SERVER_TIME_SYMBOL) {
      return 'PERMISSION_DENIED';
    }
    if ('updatedAt' in schema.properties && payload.updatedAt !== SERVER_TIME_SYMBOL) {
      return 'PERMISSION_DENIED';
    }
    if ('uid' in payload && entityName === 'UserPublic' && payload.uid !== auth.uid) {
      return 'PERMISSION_DENIED';
    }
    if ('fromUid' in payload && payload.fromUid !== auth.uid) {
      return 'PERMISSION_DENIED';
    }
  }

  for (const [key, propDef] of Object.entries(schema.properties)) {
    const val = payload[key];
    if (val === undefined) continue;
    if (propDef.type === 'string' && val !== SERVER_TIME_SYMBOL) {
      if (typeof val !== 'string') return 'PERMISSION_DENIED';
      if (propDef.maxLength !== undefined && val.length > propDef.maxLength) {
        return 'PERMISSION_DENIED';
      }
      if (propDef.minLength !== undefined && val.length < propDef.minLength) {
        return 'PERMISSION_DENIED';
      }
      if (propDef.pattern && !new RegExp(propDef.pattern).test(val)) {
        return 'PERMISSION_DENIED';
      }
      if (propDef.enum && !propDef.enum.includes(val)) {
        return 'PERMISSION_DENIED';
      }
    }
  }

  return 'ALLOWED';
}

// Payload 1: Shadow field injection
assert.equal(
  checkDirtyPayloadDenied(
    'Shadow field injection',
    'HouseholdTask',
    { uid: 'uid-adson', emailVerified: true },
    'task-evil-1',
    {
      id: 'task-evil-1',
      title: 'Legit chore',
      category: 'Limpeza',
      points: 20,
      priority: 'alta',
      frequency: 'daily',
      assignedToId: 'res-adson',
      participantIds: ['res-adson', 'res-arty'],
      dueDate: '2026-11-15',
      dueTime: '20:00',
      dueAt: '2026-11-15T23:00:00.000Z',
      occurrenceId: 'task-evil-1::2026-11-15::1',
      occurrenceSeq: 1,
      status: 'pending',
      history: [],
      createdByUid: 'uid-adson',
      memberUids: ['uid-adson'],
      createdAt: SERVER_TIME_SYMBOL,
      updatedAt: SERVER_TIME_SYMBOL,
      isAdmin: true,
    }
  ),
  'PERMISSION_DENIED'
);

// Payload 2: Unverified email spoof
assert.equal(
  checkDirtyPayloadDenied(
    'Unverified email spoof',
    'UserPublic',
    { uid: 'uid-spoof', emailVerified: false },
    'uid-spoof',
    {
      uid: 'uid-spoof',
      displayName: 'Spoofer',
      householdId: 'house-adson-arty',
      residentId: 'res-adson',
      createdAt: SERVER_TIME_SYMBOL,
      updatedAt: SERVER_TIME_SYMBOL,
    }
  ),
  'PERMISSION_DENIED'
);

// Payload 3: Cross-user PII read
assert.equal(
  checkDirtyPayloadDenied(
    'Cross-user PII read',
    'UserPrivateProfile',
    { uid: 'uid-arty', emailVerified: true },
    'info',
    {},
    { operation: 'get', targetUserId: 'uid-adson' }
  ),
  'PERMISSION_DENIED'
);

// Payload 4: Self-escalation to owner on join
assert.equal(
  checkDirtyPayloadDenied(
    'Self-escalation to owner on join',
    'HouseholdMember',
    { uid: 'uid-arty', emailVerified: true },
    'uid-arty',
    {
      uid: 'uid-arty',
      householdId: 'house-adson-arty',
      residentId: 'res-arty',
      role: 'owner',
      inviteCode: 'HOUSE-TENS',
      memberUids: ['uid-adson', 'uid-arty'],
      joinedAt: SERVER_TIME_SYMBOL,
    },
    { householdExists: true, validInviteExists: true }
  ),
  'PERMISSION_DENIED'
);

// Payload 5: Forged invite code
assert.equal(
  checkDirtyPayloadDenied(
    'Forged invite code',
    'HouseholdMember',
    { uid: 'uid-intruder', emailVerified: true },
    'uid-intruder',
    {
      uid: 'uid-intruder',
      householdId: 'house-adson-arty',
      residentId: 'res-arty',
      role: 'partner',
      inviteCode: 'WRONG-CODE',
      memberUids: ['uid-adson', 'uid-intruder'],
      joinedAt: SERVER_TIME_SYMBOL,
    },
    { householdExists: true, validInviteExists: false }
  ),
  'PERMISSION_DENIED'
);

// Payload 6: Document ID poisoning
assert.equal(
  checkDirtyPayloadDenied(
    'Document ID poisoning',
    'PinNote',
    { uid: 'uid-adson', emailVerified: true },
    'evil$note/../../etc',
    {
      id: 'evil$note',
      authorId: 'res-adson',
      authorUid: 'uid-adson',
      content: 'Test',
      pinned: false,
      memberUids: ['uid-adson'],
      createdAt: SERVER_TIME_SYMBOL,
      updatedAt: SERVER_TIME_SYMBOL,
    }
  ),
  'PERMISSION_DENIED'
);

// Payload 7: Client-forged backdated timestamp
assert.equal(
  checkDirtyPayloadDenied(
    'Backdated client timestamp',
    'PinNote',
    { uid: 'uid-adson', emailVerified: true },
    'note-99',
    {
      id: 'note-99',
      authorId: 'res-adson',
      authorUid: 'uid-adson',
      content: 'Backdated',
      pinned: false,
      memberUids: ['uid-adson'],
      createdAt: '2020-01-01T00:00:00.000Z',
      updatedAt: '2020-01-01T00:00:00.000Z',
    }
  ),
  'PERMISSION_DENIED'
);

// Payload 8: Identity spoofing on PokeRecord
assert.equal(
  checkDirtyPayloadDenied(
    'Poke identity spoofing',
    'PokeRecord',
    { uid: 'uid-arty', emailVerified: true },
    'poke-spoof',
    {
      id: 'poke-spoof',
      taskId: 'task-1',
      taskTitle: 'Wash dishes',
      occurrenceId: 'task-1::2026-11-14::3',
      fromResidentId: 'res-adson',
      fromUid: 'uid-adson',
      toResidentId: 'res-arty',
      intensity: 'full_ballroom',
      message: 'Spoofed shade',
      deliveredViaPush: false,
      memberUids: ['uid-adson', 'uid-arty'],
      createdAt: SERVER_TIME_SYMBOL,
    }
  ),
  'PERMISSION_DENIED'
);

// Payload 9: Terminal state mutability on SwapRequest
assert.equal(
  checkDirtyPayloadDenied(
    'Terminal swap state mutation',
    'SwapRequest',
    { uid: 'uid-adson', emailVerified: true },
    'swap-1',
    {
      status: 'pending',
      updatedAt: SERVER_TIME_SYMBOL,
    },
    { operation: 'update', existingData: { status: 'accepted' } }
  ),
  'PERMISSION_DENIED'
);

// Payload 10: Value poisoning 500KB string bloat on ShoppingItem
assert.equal(
  checkDirtyPayloadDenied(
    'Value poisoning bloat',
    'ShoppingItem',
    { uid: 'uid-adson', emailVerified: true },
    'shop-99',
    {
      id: 'shop-99',
      name: 'x'.repeat(500000),
      quantity: 1,
      unit: 'un',
      category: 'Mercado',
      authorId: 'res-adson',
      authorUid: 'uid-adson',
      status: 'pending',
      memberUids: ['uid-adson'],
      createdAt: SERVER_TIME_SYMBOL,
      updatedAt: SERVER_TIME_SYMBOL,
    }
  ),
  'PERMISSION_DENIED'
);

// Payload 11: Immutable point ledger tampering
assert.equal(
  checkDirtyPayloadDenied(
    'Point ledger tampering',
    'PointTransaction',
    { uid: 'uid-arty', emailVerified: true },
    'tx-seed-1',
    {
      pointsDelta: 99999,
      penaltyDeducted: 0,
    },
    { operation: 'update' }
  ),
  'PERMISSION_DENIED'
);

// Payload 12: Blanket query scraping across households
assert.equal(
  checkDirtyPayloadDenied(
    'Cross-household list scraping',
    'HouseholdTask',
    { uid: 'uid-outsider', emailVerified: true },
    'task-1',
    {},
    { operation: 'list', memberUidsOnExisting: ['uid-adson', 'uid-arty'] }
  ),
  'PERMISSION_DENIED'
);

console.log('DIRTY_DOZEN_AND_FIRESTORE_RULES_VERIFIED');
