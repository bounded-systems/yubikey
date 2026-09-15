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
      programs.ssh.enable = lib.mkDefault true;
      # mkDefault throughout: a consuming config that already has opinions
      # about ssh should win without having to disable this half.
      programs.ssh.extraConfig = lib.mkDefault ''
        # YubiKey: hardware-backed identity, offered before any software key.
        IdentityFile ${cfg.ssh.identityFile}
      '';
    })

    (lib.mkIf cfg.signing.enable {
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
