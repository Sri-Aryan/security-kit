# Game security guide: the client is in the cheater's hands

Sources: Unity Netcode for GameObjects (ownership, RPC permissions, NetworkVariable permissions), Mirror, Photon,
Godot high-level multiplayer (`@rpc`, `get_remote_sender_id`), Unreal replication (Server RPCs, `WithValidation`),
Roblox Creator Hub (Security tactics and cheat mitigation, RemoteEvents), PlayFab (API access policy, title settings,
CloudScript), Nakama (server runtime, wallets), Apple App Store Server API, Google Play Developer API, AdMob
server-side verification; OWASP MASVS (resilience).

Players can read and modify everything in the client: memory, saves, network traffic, compiled code (IL2CPP dumpers,
`.pck`/`.pak` extractors, Luau decompilers). Client-side checks only raise the cost of cheating. Anything that
affects **other players, money or rankings** must be decided or verified on the server.

## Authority (GAME-AUTH-001, GAME-NET-001)

| Engine | Danger | Safe pattern |
|---|---|---|
| Roblox | `RemoteEvent.OnServerEvent:Connect(function(player, amount)` trusting `amount`/`damage`/`position` | Client sends intent (`"CollectCoin", coinId`); server checks distance, cooldown, existence, then awards from its own table. |
| Unity NGO | `[ServerRpc(RequireOwnership = false)]`, `NetworkVariableWritePermission.Owner` on gameplay state | Server-write NetworkVariables; validate `RpcParams.Receive.SenderClientId`; clamp inputs. |
| Mirror | `[Command(requiresAuthority = false)]` | Check `connectionToClient`; validate arguments. |
| Godot 4 | `@rpc("any_peer")` handlers that set state | `var id = multiplayer.get_remote_sender_id()` and verify it owns the node; prefer `"authority"`. |
| Unreal | Server RPCs trusting parameters | `WithValidation` + `_Validate` rejecting impossible values; server-side movement correction. |
| Colyseus / Socket.IO / Nakama | `onMessage` assigning `state.x = message.x` | Apply bounded deltas; simulate on the server tick. |

## Scores and economy (GAME-SCORE-001, GAME-ECON-001, GAME-SAVE-001)

- Never let the client write the leaderboard (`AddPlayerScoreAsync`, Steam `UploadLeaderboardScore`, direct Firestore/
  Supabase inserts into `scores`). Submit a run summary to server code (Cloud Code, CloudScript, an RPC) that checks
  plausibility (max score per second, server-measured duration from a server-issued session) or replays inputs.
- Shop prices come from server data keyed by item ID; rewards from server tables keyed by quest/level ID. Make grants
  idempotent (daily reward claimed once, quest completed once) and atomic (see `/sk-race` for duplication races).
- Local saves (`PlayerPrefs`, `localStorage`, `user://` files) are fine for single-player progress. For anything that
  touches purchases, leaderboards or multiplayer, keep the source of truth on the server.

## Purchases and ads (GAME-IAP-001, GAME-ADS-001)

- Validate every purchase on your server: Apple **App Store Server API** / signed transactions (StoreKit 2 JWS;
  `verifyReceipt` is deprecated), **Google Play Developer API** (`purchases.products.get` / `subscriptionsv2`), Steam
  `ISteamMicroTxn`. Store processed transaction/order IDs with a unique constraint; handle refund/void notifications
  (App Store Server Notifications, Play Real-time Developer Notifications) by revoking items.
- Unity IAP `ProcessPurchase` should return `Pending` until your server confirms. RevenueCat: grant via its webhooks or
  REST API on the server, not the client's entitlement check, when the reward is server-side currency.
- Rewarded ads: use the network's server-side verification (AdMob SSV, Unity Ads S2S, AppLovin S2S); grant in that
  callback.

## Backends (GAME-BACKEND-001, GAME-SECRET-001)

- **PlayFab**: in Title settings → API Features, turn off "Allow client to post player statistics" and "Allow client to
  add virtual currency"; use CloudScript / Azure Functions. Never ship the developer secret key or
  `ENABLE_PLAYFABSERVER_API`/`ENABLE_PLAYFABADMIN_API` in client builds.
- **Unity Gaming Services**: Cloud Code for writes; Leaderboards with server-authoritative submission.
- **Nakama**: server RPCs compute wallet changes; storage objects for economy data are `permission_write: 0`.
- **Firebase/Supabase as backend**: see `/sk-baas`; rules must stop players writing their own stats.

## Network hygiene (GAME-RATE-001, GAME-CHAT-001)

Per-connection message rate and size limits, kicking flooders; validate enum/array sizes; chat length limits, filters,
reporting; escape names shown in web UIs (see `/sk-xss`).

## Release builds (GAME-DEBUG-001, GAME-ANTICHEAT-001)

Wrap cheats and consoles in `#if DEVELOPMENT_BUILD` / `OS.is_debug_build()` / `UE_BUILD_SHIPPING` guards and refuse
debug RPCs on the server. Log impossible stats server-side for review and bans.
