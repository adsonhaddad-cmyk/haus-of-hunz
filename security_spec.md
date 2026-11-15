# Security Specification — The House of Chores

## 1. Data Invariants
1. **Zero-Trust Default Deny**: Every document path defaults to `allow read, write: if false;` unless explicitly matched and verified.
2. **Verified Identity & Anti-Spoofing**: All reads and writes require `request.auth != null && request.auth.token.email_verified == true`. All author/owner UID fields (`uid`, `ownerUid`, `createdByUid`, `authorUid`, `actorUid`, `fromUid`) must strictly match `request.auth.uid` on creation and remain immutable afterward.
3. **PII Isolation**: User email addresses are stored exclusively in `/users/{userId}/private/{docId}` (`UserPrivateProfile`), readable and writable only by `request.auth.uid == userId`. Shared `/households/{householdId}/residents/{residentId}` profiles never contain email addresses.
4. **Master Gate Household Membership**: Access to `/households/{householdId}` and all subcollections is governed by `/households/{householdId}/members/{memberUid}`. Joining an existing household requires a valid `/invites/{inviteCode}` document whose `householdId` matches the target household, and joining sets `role: 'partner'` (self-escalation to `'owner'` is forbidden).
5. **No Client-Delegated List Queries**: Every `allow list` rule evaluates `resource.data.memberUids` directly (`request.auth.uid in resource.data.memberUids`) without `get()` or `exists()` lookups, blocking O(n) query scraping and cross-household reads.
6. **Temporal Integrity**: All `createdAt`, `joinedAt`, and `updatedAt` fields are validated against `request.time` (server timestamps). `createdAt` is immutable on update.
7. **Strict Schema & Volumetric Bounds**: Every `isValid[Entity]` helper enforces `keys().hasAll(...) && keys().hasOnly(...)`, `.size()` limits on every `string` and `list`, `isValidId()` regex (`^[a-zA-Z0-9_\-]+$`), and numeric range checks.
8. **Terminal State Locking**: Once a `SwapRequest` leaves `'pending'` (`accepted`, `declined`, `cancelled`), no further updates are permitted.
9. **Immutable Audit Logs**: `PointTransaction`, `PokeRecord`, and `HouseActivityLog` records cannot be modified by existing members (`update` is only allowed during a verified partner join batch to append the joining user's own UID to `memberUids`), and deletion is restricted to the household owner (for Reset Demo Data).
10. **Zero Financial Surfaces**: No schema or rule permits financial expense, split, debt, or settlement fields anywhere.

---

## 2. The "Dirty Dozen" Adversarial Payloads

### Payload 1 — Shadow Field Injection on HouseholdTask Create
```json
{
  "targetPath": "/households/house-adson-arty/tasks/task-evil-1",
  "operation": "create",
  "payload": {
    "id": "task-evil-1",
    "title": "Legit chore",
    "category": "Limpeza",
    "points": 20,
    "priority": "alta",
    "frequency": "daily",
    "assignedToId": "res-adson",
    "participantIds": ["res-adson", "res-arty"],
    "dueDate": "2026-11-15",
    "dueTime": "20:00",
    "dueAt": "2026-11-15T23:00:00.000Z",
    "occurrenceId": "task-evil-1::2026-11-15::1",
    "occurrenceSeq": 1,
    "status": "pending",
    "history": [],
    "createdByUid": "uid-adson",
    "memberUids": ["uid-adson", "uid-arty"],
    "isAdmin": true
  }
}
```
Expected: `PERMISSION_DENIED` (`keys().hasOnly(...)` rejects ghost field `isAdmin`).

### Payload 2 — Unverified Email Spoof Attack
```json
{
  "auth": { "uid": "uid-spoof", "token": { "email": "adson@gmail.com", "email_verified": false } },
  "targetPath": "/users/uid-spoof",
  "operation": "create",
  "payload": {
    "uid": "uid-spoof",
    "displayName": "Spoofer",
    "householdId": "house-adson-arty",
    "residentId": "res-adson",
    "createdAt": "SERVER_TIME",
    "updatedAt": "SERVER_TIME"
  }
}
```
Expected: `PERMISSION_DENIED` (`request.auth.token.email_verified == true` fails).

### Payload 3 — Cross-User PII Read Attempt
```json
{
  "auth": { "uid": "uid-arty", "token": { "email_verified": true } },
  "targetPath": "/users/uid-adson/private/info",
  "operation": "get"
}
```
Expected: `PERMISSION_DENIED` (`request.auth.uid == userId` fails).

### Payload 4 — Self-Escalation to Household Owner on Join
```json
{
  "auth": { "uid": "uid-arty", "token": { "email_verified": true } },
  "targetPath": "/households/house-adson-arty/members/uid-arty",
  "operation": "create",
  "payload": {
    "uid": "uid-arty",
    "householdId": "house-adson-arty",
    "residentId": "res-arty",
    "role": "owner",
    "inviteCode": "HOUSE-TENS",
    "memberUids": ["uid-adson", "uid-arty"],
    "joinedAt": "SERVER_TIME"
  }
}
```
Expected: `PERMISSION_DENIED` (joining an existing household mandates `role == 'partner'`).

### Payload 5 — Invalid / Forged Invite Code Membership Injection
```json
{
  "auth": { "uid": "uid-intruder", "token": { "email_verified": true } },
  "targetPath": "/households/house-adson-arty/members/uid-intruder",
  "operation": "create",
  "payload": {
    "uid": "uid-intruder",
    "householdId": "house-adson-arty",
    "residentId": "res-arty",
    "role": "partner",
    "inviteCode": "WRONG-CODE",
    "memberUids": ["uid-adson", "uid-intruder"],
    "joinedAt": "SERVER_TIME"
  }
}
```
Expected: `PERMISSION_DENIED` (`exists(/invites/WRONG-CODE)` fails).

### Payload 6 — Document ID Poisoning (Oversized / Illegal Characters)
```json
{
  "auth": { "uid": "uid-adson", "token": { "email_verified": true } },
  "targetPath": "/households/house-adson-arty/pinNotes/evil$note/../../etc",
  "operation": "create",
  "payload": {
    "id": "evil$note",
    "authorId": "res-adson",
    "authorUid": "uid-adson",
    "content": "Test",
    "pinned": false,
    "memberUids": ["uid-adson"]
  }
}
```
Expected: `PERMISSION_DENIED` (`isValidId` regex `^[a-zA-Z0-9_\-]+$` fails).

### Payload 7 — Client-Forged Backdated Timestamp
```json
{
  "auth": { "uid": "uid-adson", "token": { "email_verified": true } },
  "targetPath": "/households/house-adson-arty/pinNotes/note-99",
  "operation": "create",
  "payload": {
    "id": "note-99",
    "authorId": "res-adson",
    "authorUid": "uid-adson",
    "content": "Forged timestamp",
    "pinned": false,
    "memberUids": ["uid-adson"],
    "createdAt": "2020-01-01T00:00:00.000Z",
    "updatedAt": "2020-01-01T00:00:00.000Z"
  }
}
```
Expected: `PERMISSION_DENIED` (`incoming().createdAt == request.time` rejects client strings / backdated timestamps).

### Payload 8 — Identity Spoofing on PokeRecord (`fromUid` Mismatch)
```json
{
  "auth": { "uid": "uid-arty", "token": { "email_verified": true } },
  "targetPath": "/households/house-adson-arty/pokes/poke-spoof",
  "operation": "create",
  "payload": {
    "id": "poke-spoof",
    "taskId": "task-1",
    "taskTitle": "Wash dishes",
    "occurrenceId": "task-1::2026-11-14::3",
    "fromResidentId": "res-adson",
    "fromUid": "uid-adson",
    "toResidentId": "res-arty",
    "intensity": "full_ballroom",
    "message": "Spoofed shade",
    "deliveredViaPush": false,
    "memberUids": ["uid-adson", "uid-arty"],
    "createdAt": "SERVER_TIME"
  }
}
```
Expected: `PERMISSION_DENIED` (`data.fromUid == request.auth.uid` fails).

### Payload 9 — Terminal State Mutability Attack on Accepted SwapRequest
```json
{
  "auth": { "uid": "uid-adson", "token": { "email_verified": true } },
  "targetPath": "/households/house-adson-arty/swapRequests/swap-1",
  "existingData": { "status": "accepted", "fromUid": "uid-adson", "toResidentId": "res-arty" },
  "operation": "update",
  "payload": {
    "status": "pending",
    "updatedAt": "SERVER_TIME"
  }
}
```
Expected: `PERMISSION_DENIED` (Terminal State Locking rejects updates once `existing().status != 'pending'`).

### Payload 10 — Value Poisoning / Denial-of-Wallet String Bloat on ShoppingItem
```json
{
  "auth": { "uid": "uid-adson", "token": { "email_verified": true } },
  "targetPath": "/households/house-adson-arty/shoppingItems/shop-99",
  "operation": "create",
  "payload": {
    "id": "shop-99",
    "name": "<500KB_STRING_REPEAT>",
    "quantity": 1,
    "unit": "un",
    "category": "Mercado",
    "authorId": "res-adson",
    "authorUid": "uid-adson",
    "status": "pending",
    "memberUids": ["uid-adson"],
    "createdAt": "SERVER_TIME",
    "updatedAt": "SERVER_TIME"
  }
}
```
Expected: `PERMISSION_DENIED` (`data.name.size() <= 100` fails).

### Payload 11 — Immutable Point Ledger Tampering by Existing Member
```json
{
  "auth": { "uid": "uid-arty", "token": { "email_verified": true } },
  "targetPath": "/households/house-adson-arty/pointLedger/tx-seed-1",
  "operation": "update",
  "payload": {
    "pointsDelta": 99999,
    "penaltyDeducted": 0
  }
}
```
Expected: `PERMISSION_DENIED` (`PointTransaction` forbids updates by existing members).

### Payload 12 — Blanket Query Scraping Across Households (`list` without UID filter)
```json
{
  "auth": { "uid": "uid-outsider", "token": { "email_verified": true } },
  "targetPath": "/households/house-adson-arty/tasks",
  "operation": "list",
  "query": "collection('households/house-adson-arty/tasks') // no array-contains uid filter"
}
```
Expected: `PERMISSION_DENIED` (`allow list: if isEmailVerified() && request.auth.uid in resource.data.memberUids` rejects unfiltered list queries).
