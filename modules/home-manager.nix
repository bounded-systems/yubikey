{ config, lib, pkgs, ... }:

# The YubiKey stack as one declaration: the management CLI, the ssh client
# config for hardware-backed keys, and the signing conventions that make a
# hardware key actually verifiable rather than merely present.
#
# WHY ITS OWN FLAKE rather than a few lines in bdelanghe/home: home is
# explicitly temporary and is meant to be transferred, not re-created. A
# hardware-key stack outlives it, is not machine-specific, and is the kind of
# thing a second machine wants verbatim. Same shape as claude-token-tools.
#
# HARDWARE CAVEAT, and it decides which half of this module is usable.
# Bobby's keys are from yubico.com/openai and are most likely **Security Key
# Series**: FIDO2/WebAuthn only, with **no PIV and no OpenPGP applet**. That
# means:
#
#   WORKS      ed25519-sk / ecdsa-sk ssh keys, ssh signing with them, FIDO2
#              WebAuthn, and `ykman info` / `ykman fido` subcommands.
#   DOES NOT   `ykman piv`, `ykman openpgp`, gpg-agent smartcard flows, and
#              any PIV-backed ssh via pkcs11 — the applets are absent, not
#              locked. Nothing here should be written to depend on them.
#
# The firmware-version check that gates key generation (>= 5.7 for ed25519-sk
# resident keys with the newer attestation) is a runtime question, not a
# declarative one: run `ykman info` with the key inserted. This module puts
# `ykman` on PATH so that check is possible; it deliberately does not try to
# assert a firmware version at build time, where the key is not present.

let
  cfg = config.programs.yubikey;

  # Read-only sanity check. Never invokes -t ed25519-sk, never touches the
  # authenticator — it only resolves PATH, so it is safe to run unattended
  # and as often as wanted. Deliberately separate from the disposable probe
  # below, which does touch hardware and is not something to run casually.
  preflight = pkgs.writeShellApplication {
    name = "yubikey-preflight";
    text = ''
      resolved="$(command -v ssh-keygen || true)"
      if [ -z "$resolved" ]; then
        echo "FAIL: no ssh-keygen on PATH" >&2
        exit 1
      fi
      case "$resolved" in
        /usr/bin/*)
          echo "FAIL: ssh-keygen resolves to $resolved — nix-provided openssh (${cfg.ssh.package}) is not ahead of /usr/bin on PATH" >&2
          exit 1
          ;;
        *)
          echo "OK: ssh-keygen resolves to $resolved"
          ;;
      esac

      if ! command -v ykman >/dev/null 2>&1; then
        echo "FAIL: ykman not on PATH (programs.yubikey.enable should provide it)" >&2
        exit 1
      fi
      echo "OK: ykman on PATH at $(command -v ykman)"

      if ykman info >/dev/null 2>&1; then
        echo "--- ykman info (device present) ---"
        ykman info
        echo "Firmware must be >= 5.7 for ed25519-sk resident keys; check the line above."
      else
        echo "NOTE: no YubiKey detected (ykman info failed) — insert one to check firmware."
      fi
    '';
  };

  # The scoped, disposable liveness probe. Runs ssh-keygen against a
  # throwaway path in a fresh temp directory with a hard timeout, and treats
  # anything past "you may need to touch" as success — it does not wait for
  # an actual touch, does not accept a PIN, and always tears itself down
  # (temp dir + child process) via its own trap, so it never depends on
  # being killed from outside. NOT run automatically; invoke by hand.
  probe = pkgs.writeShellApplication {
    name = "yubikey-probe";
    text = ''
      resolved="$(command -v ssh-keygen)"
      case "$resolved" in
        /usr/bin/*)
          echo "FAIL: ssh-keygen resolves to $resolved, not a nix-provided build" >&2
          exit 1
          ;;
      esac

      tmpdir="$(mktemp -d)"
      trap 'kill "$kgpid" 2>/dev/null || true; rm -rf "$tmpdir"' EXIT

      out="$tmpdir/out"
      "$resolved" -t ed25519-sk -f "$tmpdir/probe" -N "" -C yubikey-probe-disposable \
        >"$out" 2>&1 &
      kgpid=$!

      # Poll for the touch line instead of a fixed sleep, bounded at 10s.
      status="timeout"
      for _ in $(seq 1 20); do
        if grep -q "touch your authenticator" "$out" 2>/dev/null; then
          status="touch-prompt"
          break
        fi
        if ! kill -0 "$kgpid" 2>/dev/null; then
          status="exited"
          break
        fi
        sleep 0.5
      done

      cat "$out"
      case "$status" in
        touch-prompt)
          echo "PASS: reached the touch prompt via $resolved"
          exit 0
          ;;
        exited)
          echo "FAIL: ssh-keygen exited before prompting for touch — see output above" >&2
          exit 1
          ;;
        timeout)
          echo "FAIL: no touch prompt within 10s — see output above" >&2
          exit 1
          ;;
      esac
    '';
  };

  # Append one line to allowed_signers if it is not already present, rather
  # than overwrite the file — this module deliberately never generates
  # allowed_signers wholesale (see signing.allowedSignersFile above).
  allowedSigners = pkgs.writeShellApplication {
    name = "yubikey-allowed-signers";
    text = ''
      if [ "$#" -lt 2 ]; then
        echo "usage: yubikey-allowed-signers <email> <path-to-pubkey> [comment]" >&2
        exit 1
      fi
      email="$1"
      pubkey_path="$2"
      comment="''${3:-}"

      if [ ! -f "$pubkey_path" ]; then
        echo "FAIL: $pubkey_path does not exist" >&2
        exit 1
      fi

      keytype_and_key="$(cut -d' ' -f1,2 "$pubkey_path")"
      line="$email $keytype_and_key"
      if [ -n "$comment" ]; then
        line="$line  # $comment"
      fi

      target="${cfg.signing.allowedSignersFile}"
      mkdir -p "$(dirname "$target")"
      touch "$target"

      if grep -qF "$email $keytype_and_key" "$target"; then
        echo "OK: already present in $target"
        exit 0
      fi

      echo "$line" >> "$target"
      echo "OK: appended to $target"
    '';
  };
in
{
  options.programs.yubikey = {
    enable = lib.mkEnableOption "the YubiKey stack (ykman + ssh + signing conventions)";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.yubikey-manager;
      defaultText = lib.literalExpression "pkgs.yubikey-manager";
      description = "The management CLI. Provides `ykman` (mainProgram).";
    };

    ssh = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Write the ssh client conventions for hardware-backed keys.

          OFF by intent for a machine whose ssh config is owned elsewhere —
          this writes into programs.ssh, and two modules writing one config
          is how a setting silently stops taking effect.
        '';
      };

      identityFile = lib.mkOption {
        type = lib.types.str;
        default = "${config.home.homeDirectory}/.ssh/id_ed25519_sk";
        description = ''
          The hardware-backed key. `_sk` suffix is load-bearing: it is what
          distinguishes a FIDO2-resident key from a software key sitting in
          the same directory, at a glance and in a backup.
        '';
      };

      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.openssh;
        defaultText = lib.literalExpression "pkgs.openssh";
        description = ''
          The `ssh-keygen`/`ssh` build put on PATH ahead of `/usr/bin`.

          Verified live on phobos (2026-09-15): `pkgs.openssh` is built with
          `--with-security-key-builtin=yes`, so `ssh-keygen -t ed25519-sk`
          reaches "You may need to touch your authenticator" against a real
          device with no `SSH_SK_PROVIDER` set — the FIDO2 middleware is
          compiled in, not an external provider library. Home-manager's
          `home.packages` already lands ahead of `/usr/bin` in PATH, so no
          separate PATH surgery is needed here — declaring the package is
          the whole fix.
        '';
      };
    };

    signing = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Git commit/tag signing through the hardware key, with an allowed-signers file.";
      };

      allowedSignersFile = lib.mkOption {
        type = lib.types.str;
        default = "${config.home.homeDirectory}/.config/git/allowed_signers";
        description = ''
          Where `gpg.ssh.allowedSignersFile` points.

          NOT generated here, deliberately. The file maps identities to public
          keys, and a generated one would either be empty (so every signature
          verifies as "unknown", which reads like success) or would embed a
          key this module cannot have seen. It is written once, by hand, after
          the key exists.
        '';
      };

      verifyRequired = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Set `ykman`-generated keys to require user verification (touch/PIN)
          per signature, and record that expectation here.

          This option does not enforce verification — the flag lives on the
          key, set at generation time with `ssh-keygen -O verify-required`.
          What it does is make the intent declared, so a key generated without
          it is a visible mismatch rather than an invisible one.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    { home.packages = [ cfg.package ]; }

    (lib.mkIf cfg.ssh.enable {
      home.packages = [ cfg.ssh.package preflight probe ];
      programs.ssh.enable = lib.mkDefault true;
      # mkDefault throughout: a consuming config that already has opinions
      # about ssh should win without having to disable this half.
      programs.ssh.extraConfig = lib.mkDefault ''
        # YubiKey: hardware-backed identity, offered before any software key.
        IdentityFile ${cfg.ssh.identityFile}
      '';
    })

    (lib.mkIf cfg.signing.enable {
      home.packages = [ allowedSigners ];
      programs.git.extraConfig = {
        gpg.format = lib.mkDefault "ssh";
        gpg.ssh.allowedSignersFile = lib.mkDefault cfg.signing.allowedSignersFile;
        user.signingKey = lib.mkDefault "${cfg.ssh.identityFile}.pub";
        commit.gpgsign = lib.mkDefault true;
        tag.gpgsign = lib.mkDefault true;
      };
    })
  ]);
}
