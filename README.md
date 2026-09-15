# yubikey

The YubiKey stack as a home-manager module: `ykman`, ssh config for
hardware-backed keys, and the signing conventions that make one verifiable.

Its own flake rather than a few lines in `bdelanghe/home` because home is
temporary and meant to be transferred; a hardware-key stack outlives it and is
what a second machine wants verbatim.

## Use

```nix
# flake.nix
inputs.yubikey.url = "github:bounded-systems/yubikey";

# modules
imports = [ yubikey.homeManagerModules.default ];
programs.yubikey.enable = true;
```

Module path: `homeManagerModules.default` → `modules/home-manager.nix`
(also exported as `homeManagerModules.yubikey`).

`nix run github:bounded-systems/yubikey#ykman -- info` runs the CLI without
declaring anything.

## Hardware caveat — read before relying on this

Bobby's keys are from yubico.com/openai and are most likely **Security Key
Series**: FIDO2/WebAuthn only, with **no PIV and no OpenPGP applet**.

| works | does not |
|---|---|
| `ed25519-sk` / `ecdsa-sk` ssh keys | `ykman piv` |
| ssh signing with those keys | `ykman openpgp` |
| FIDO2 / WebAuthn | gpg-agent smartcard flows |
| `ykman info`, `ykman fido` | PIV-backed ssh via pkcs11 |

Those applets are **absent, not locked** — no PIN unlocks them. Nothing built
on this module should depend on them.

Confirm with the key inserted:

```
ykman info
```

That is also where the **firmware >= 5.7** check happens, which gates
`ed25519-sk` resident-key generation. It is deliberately a runtime check: the
key is not present at build time, so asserting a firmware version
declaratively would be asserting something unobservable.

## What this module does not do

- **It does not generate a key.** `ssh-keygen -t ed25519-sk -O resident -O
  verify-required` is an interactive, touch-confirmed act.
- **It does not write `allowed_signers`.** A generated one is either empty —
  so every signature verifies as "unknown", which reads like success — or
  embeds a key this module never saw. Write it once, by hand, after the key
  exists.
- **It does not enforce touch-per-signature.** That flag lives on the key, set
  at generation. `signing.verifyRequired` records the expectation so a key
  generated without it is a visible mismatch rather than an invisible one.

Every setting it does write uses `mkDefault`, so a consuming config that
already has opinions about ssh or git signing wins without disabling half of
this.
