{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.services.crowdsec;
  format = pkgs.formats.yaml {};
  configFile = format.generate "crowdsec.yaml" cfg.settings;

  pkg = cfg.package.overrideAttrs (old: {
    ldflags =
      (old.ldflags or [])
      ++ [
        "-X github.com/crowdsecurity/go-cs-lib/version.Version=v${old.version}"
      ];
    patches =
      (old.patches or [])
      ++ [
        (
          pkgs.fetchpatch
          {
            url = "https://patch-diff.githubusercontent.com/raw/crowdsecurity/crowdsec/pull/2868.patch";
            hash = "sha256-RSfLhNZ3JVvHoW/BNca9Hs4lpjcDtE1vsBDjJeaHqvc=";
          }
        )
      ];
  });

  defaultPatterns = lib.mapAttrs (name: value: lib.mkDefault "${pkg}/share/crowdsec/config/patterns/${name}") (builtins.readDir "${pkg}/share/crowdsec/config/patterns");

  patternsDir = pkgs.runCommandNoCC "crowdsec-patterns" {} ''
    mkdir -p $out
    ${lib.concatStringsSep "\n" (lib.attrValues (lib.mapAttrs (
        k: v: ''
          ln -sf ${v} $out/${k}
        ''
      )
      cfg.patterns))}
  '';

  consoleSettings = {
    share_manual_decisions = false;
    share_custom = true;
    share_tainted = true;
    share_context = false;
  };

  defaultSettings = with lib; {
    common = {
      daemonize = mkForce false;
      log_media = mkForce "stdout";
    };
    config_paths = {
      config_dir = mkDefault "/var/lib/crowdsec/config";
      data_dir = mkDefault dataDir;
      hub_dir = mkDefault hubDir;
      index_path = mkDefault "${hubDir}/.index.json";
      simulation_path = mkDefault "${pkg}/share/crowdsec/config/simulation.yaml";
      pattern_dir = mkDefault patternsDir;
    };
    db_config = {
      type = mkDefault "sqlite";
      db_path = mkDefault "${dataDir}/crowdsec.db";
      use_wal = true;
    };
    crowdsec_service = {
      enable = mkDefault true;
    };
    api = {
      client = {
        credentials_path = mkDefault "${stateDir}/local_api_credentials.yaml";
      };
      server = {
        enable = mkDefault (cfg.enrollKeyFile != null);
        listen_uri = mkDefault "127.0.0.1:8080";

        console_path = mkDefault "${stateDir}/console.yaml";
        profiles_path = mkDefault "${pkg}/share/crowdsec/config/profiles.yaml";

        online_client.credentials_path = mkDefault "${stateDir}/online_api_credentials.yaml";
      };
    };
  };

  user = "crowdsec";
  group = "crowdsec";
  stateDir = "/var/lib/crowdsec";
  dataDir = "${stateDir}/data";
  hubDir = "${stateDir}/hub";
in {
  options.services.crowdsec = with lib; {
    enable = mkEnableOption "CrowSec Security Engine";
    package = mkPackageOption pkgs "crowdsec" {};
    name = mkOption {
      type = types.str;
      description = mdDoc ''
        Name of the machine when registering it at the central or loal api.
      '';
      default = config.networking.hostName;
    };
    enrollKeyFile = mkOption {
      description = mdDoc ''
        The file containing the enrollment key used to enroll the engine at the central api console.
        See <https://docs.crowdsec.net/docs/next/console/enrollment/#where-can-i-find-my-enrollment-key> for details.
      '';
      type = types.nullOr types.path;
      default = null;
    };
    patterns = mkOption {
      description = mdDoc ''
        A set of pattern files for parsing logs, in the form "type" to file containing the corresponding GROK patterns.
        All default patterns are automatically included.
        See <https://github.com/crowdsecurity/crowdsec/tree/master/config/patterns>.
      '';
      type = types.attrsOf types.pathInStore;
      default = {};
      example = lib.literalExpression ''
        { ssh = ./patterns/ssh;}
      '';
    };
    settings = mkOption {
      description = mdDoc ''
        Settings for MediaMTX. Refer to the defaults at
        <https://github.com/bluenviron/mediamtx/blob/main/mediamtx.yml>.
      '';
      type = format.type;
      default = {};
    };
    allowLocalJournalAccess = mkOption {
      description = mkDoc ''
        Allow acquisitions from local systemd-journald.
        For details, see <https://doc.crowdsec.net/docs/data_sources/journald>.
      '';
      type = types.bool;
      default = false;
    };
  };
  config = let
    cscli = pkgs.writeScriptBin "cscli" ''
      #!${pkgs.runtimeShell}
      set -eu
      set -o pipefail

      exec ${pkg}/bin/cscli -c=${configFile} "''${@}"
    '';
  in
    lib.mkIf (cfg.enable) {
      services.crowdsec.settings = defaultSettings;
      services.crowdsec.patterns = defaultPatterns;

      environment = {
        systemPackages = [cscli];
      };

      systemd.packages = [pkg];
      systemd.timers.crowdsec-update-hub = {
        description = "Update the crowdsec hub index";
        wantedBy = ["timers.target"];
        timerConfig = {
          OnCalendar = "daily";
          Persistent = "yes";
          Unit = "crowdsec-update-hub.service";
        };
      };
      systemd.services = let
        sudo_doas =
          if config.security.doas.enable == true
          then "${pkgs.doas}/bin/doas"
          else "${pkgs.sudo}/bin/sudo";
      in {
        crowdsec-update-hub = {
          description = "Update the crowdsec hub index";
          path = [cscli];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${sudo_doas} -u crowdsec ${cscli}/bin/cscli --error hub upgrade";
            ExecStartPost = " systemctl restart crowdsec.service";
          };
        };

        crowdsec = {
          description = "CrowdSec is a free, modern & collaborative behavior detection engine, coupled with a global IP reputation network.";

          path = [cscli];

          wantedBy = ["multi-user.target"];
          serviceConfig = with lib; {
            User = "crowdsec";
            Group = "crowdsec";
            Restart = "on-failure";

            LimitNOFILE = mkDefault 65536;

            CapabilityBoundingSet = mkDefault [];

            NoNewPrivileges = mkDefault true;
            LockPersonality = mkDefault true;
            RemoveIPC = mkDefault true;

            ReadWritePaths = [stateDir];
            ProtectSystem = mkDefault "strict";

            PrivateUsers = mkDefault true;
            ProtectHome = mkDefault true;
            PrivateTmp = mkDefault true;

            PrivateDevices = mkDefault true;
            ProtectHostname = mkDefault true;
            ProtectKernelTunables = mkDefault true;
            ProtectKernelModules = mkDefault true;
            ProtectControlGroups = mkDefault true;

            ProtectProc = mkDefault "invisible";
            ProcSubset = mkIf (!cfg.allowLocalJournalAccess) (mkDefault "pid");

            RestrictNamespaces = mkDefault true;
            RestrictRealtime = mkDefault true;
            RestrictSUIDSGID = mkDefault true;

            SystemCallFilter = mkDefault ["@system-service" "@network-io"];
            SystemCallArchitectures = ["native"];
            SystemCallErrorNumber = mkDefault "EPERM";

            ExecPaths = ["/nix/store"];
            NoExecPaths = ["/"];

            ExecStart = "${pkg}/bin/crowdsec -c ${configFile}";
            ExecStartPre = let
              script = pkgs.writeScriptBin "crowdsec-setup" ''
                #!${pkgs.runtimeShell}
                set -eu
                set -o pipefail

                if [ ! -s "${cfg.settings.api.client.credentials_path}" ]; then
                  cscli machine add "${cfg.name}" --auto
                fi

                ${lib.optionalString cfg.settings.api.server.enable ''
                  if ! grep -q password "${cfg.settings.api.server.online_client.credentials_path}" ]; then
                    cscli capi register
                  fi

                  cscli hub update

                  ${lib.optionalString (cfg.enrollKeyFile != null) ''
                    if [ ! -e "${cfg.settings.api.server.console_path}" ]; then
                      cscli console enroll "$(cat ${cfg.enrollKeyFile})" --name ${cfg.name}
                    fi
                  ''}
                ''}
              '';
            in ["${script}/bin/crowdsec-setup"];
          };
        };
      };
      systemd.tmpfiles.rules = [
        "d '${stateDir}' 0750 ${user} ${group} - -"
        "d '${dataDir}' 0750 ${user} ${group} - -"
        "d '${hubDir}' 0750 ${user} ${group} - -"
        "f '${cfg.settings.api.server.online_client.credentials_path}' 0750 ${user} ${group} - -"
        "f '${cfg.settings.config_paths.index_path}' 0750 ${user} ${group} - -"
      ];
      users.users.${user} = {
        name = lib.mkDefault user;
        description = lib.mkDefault "Crowdsec service user";
        isSystemUser = lib.mkDefault true;
        group = lib.mkDefault group;
        extraGroups = lib.mkIf cfg.allowLocalJournalAccess ["systemd-journal"];
      };

      users.groups.${group} = lib.mapAttrs (name: lib.mkDefault) {};
    };
}
