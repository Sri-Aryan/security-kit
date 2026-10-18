# Business logic guide

Sources: OWASP Abuse Case, Transaction Authorization and REST Security (out-of-order execution) cheat sheets;
OWASP API6:2023. Domain-neutral.

Business logic bugs are **valid requests used against the intent of the design**. The method is to write down
the invariants the business relies on, then try to break each one with requests a normal UI would never send.

## 1. Write the invariants per workflow

Examples: "the charged amount equals the sum of catalog prices × quantities − valid discounts + tax";
"a coupon is redeemed at most once per customer"; "an order ships only after payment is confirmed";
"a user cannot approve their own expense"; "a refund never exceeds what was captured";
"free-tier accounts create at most 3 projects".

## 2. Abuse each invariant

| Technique | Try | Control |
|---|---|---|
| Tamper values | send `price`, `total`, `discount`, `role`, `plan`, `status` in the body | ignore client values; compute server-side (BIZ-PRICE, BIZ-TRUST) |
| Extreme numbers | negative, zero, fractional, huge, overflow quantities and amounts | validate range and type (BIZ-QTY) |
| Repeat | redeem/apply/refund/claim twice, sequentially and in parallel | single-use state + atomic writes (BIZ-COUPON, BIZ-RACE, BIZ-REVERSAL) |
| Skip or reorder | call step 3 without step 2; replay an old step token | server-side state machine (BIZ-FLOW) |
| Swap identities | act on another user's object; approve own request | per-action authorization, separation of duties (BIZ-AUTHZ) |
| Multiply | many accounts for trials/referrals, scripted purchases | per-person limits, verification, velocity checks (BIZ-LIMIT) |
| Guess | sequential coupon/invite/gift codes | CSPRNG codes (BIZ-ENUM) |
| Round | many tiny transactions exploiting rounding/conversion | integer minor units, defined rounding (BIZ-MONEY) |

## 3. Correct shapes

- **Pricing**: the client sends product IDs and quantities; the server loads prices, applies validated discounts,
  computes tax/shipping, and stores the computed total it charges.
- **Workflows**: an explicit state machine (`pending → paid → shipped`); each endpoint requests a transition and
  the server checks the current state allows it, in the same transaction as the change.
- **One-time value**: `UPDATE coupons SET used_by = $user WHERE code = $c AND used_by IS NULL` and check the row
  count; or a unique constraint on (coupon, user).
- **Money**: integer cents or a decimal type; never floats.

## 4. Test

Turn each abuse case into an automated test that sends the abusive request and asserts the invariant still holds.
