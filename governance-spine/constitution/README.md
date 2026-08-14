# Constitution — release artifact

`constitution.json` + `constitution.json.sig` are baked into the Sentinel
image at build time (`governance-spine/Dockerfile`) and loaded/verified at
startup (A2 — see `src/constitution.rs::load_verified` and `src/server.rs`
`main()`). Startup refuses to proceed if either file is missing, the
signature doesn't verify against the compiled-in pinned public key
(`TRUSTED_CONSTITUTION_AUTHORITY_PUBLIC_KEY_HEX` in `src/constitution.rs`),
the JSON is malformed, required fields are missing, the validity window
(`effective_at`/`expires_at`) doesn't cover now, or `industry_profile`
doesn't match `SENTOW_INDUSTRY_PROFILE`.

## Current content: placeholder, not real policy

`constitution_id`/`client_id` are literally `"PENDING-OPERATOR-APPROVAL"`,
`policy_version` is `"0.0.0-placeholder"`, and every list
(`prohibited_categories`/`prohibited_patterns`/`required_deferrals`) is
empty. This document exists ONLY to satisfy the mandatory load-and-verify
infrastructure so the container can start and be live-verified — it
enforces nothing. It is explicitly NOT the real Abigail/LOGOS ASF
governance policy, which is pending operator decisions on every policy
section (see `FINDINGS.md`, `A2_DESIGN.md`).

## Re-signing after real content is authored

The signing private key is held OFFLINE at
`~/.logosgs/constitution-signing/constitution-authority-ed25519.key`
(never in this repo, never in the build context, mode 600). To sign a new
`constitution.json`:

```
cd governance-spine
cargo run --example sign_constitution -- constitution/constitution.json
```

This writes `constitution.json.sig` next to it. If the key is ever
rotated, `TRUSTED_CONSTITUTION_AUTHORITY_PUBLIC_KEY_HEX` in
`src/constitution.rs` must be updated to the new public key and the
binary rebuilt — rotation is deliberately a source change, not a
runtime-mutable file, so the trust anchor can't be swapped by anything
short of a new release.
