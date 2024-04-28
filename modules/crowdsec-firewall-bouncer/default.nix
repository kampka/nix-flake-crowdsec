{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.services.crowdsec-firewall-bouncer;
  format = pkgs.formats.yaml {};
  configFile = format.generate "crowdsec.yaml" cfg.settings;

  pkg = cfg.package;

  backend =
    if config.networking.nftables.enable
    then "nftables"
    else "iptables";

  defaultSettings = with lib; {
    log_mode = "stdout";

    mode = mkDefault backend;
    ipset_type = mkDefault "nethash";
    update_frequency = mkDefault "10s";
    deny_action = mkDefault "DROP";
    blacklists_ipv4 = mkDefault "crowdsec-blacklists";
    blacklists_ipv6 = mkDefault "crowdsec6-blacklists";
    iptables_chains = mkDefault ["INPUT"];
  };
in {
  options.services.crowdsec-firewall-bouncer = with lib; {
    enable = mkEnableOption "CrowSec Firewall Bouncer";
    package = mkPackageOption pkgs "crowdsec-firewall-bouncer" {};
    settings = mkOption {
      description = mdDoc ''
        Settings for CrowdSec Firewall Bouncer. Refer to <https://docs.crowdsec.net/u/bouncers/firewall/#configuration-directives> for details.
      '';
      type = format.type;
      default = {};
    };
  };
  config = lib.mkIf (cfg.enable) {
    warnings = [
      ''
        nix-flake-crowdsec has moved to Codeberg.
        You can find the latest version at https://codeberg.org/kampka/nix-flake-crowdsec
        Please make sure to update your dependency to receive the latests updates.
      ''
    ];

    services.crowdsec-firewall-bouncer.settings = defaultSettings;

    systemd.packages = [pkg];
    systemd.services = {
      crowdsec-firewall-bouncer = {
        description = "Crowdsec Firewall Bouncer";

        path = [pkg pkgs.ipset pkgs.iptables pkgs.nftables];

        wantedBy = ["multi-user.target"];
        partOf = ["firewall.service"];

        serviceConfig = with lib; {
          Type = "notify";
          Restart = "on-failure";
          RestartSec = 10;

          LimitNOFILE = mkDefault 65536;

          MemoryDenyWriteExecute = mkDefault true;

          CapabilityBoundingSet = mkDefault ["CAP_NET_ADMIN" "CAP_NET_RAW"];

          NoNewPrivileges = mkDefault true;
          LockPersonality = mkDefault true;
          RemoveIPC = mkDefault true;

          ProtectSystem = mkDefault "strict";
          ProtectHome = mkDefault true;

          PrivateTmp = mkDefault true;
          PrivateDevices = mkDefault true;
          ProtectHostname = mkDefault true;
          ProtectKernelTunables = mkDefault true;
          ProtectKernelModules = mkDefault true;
          ProtectControlGroups = mkDefault true;

          ProtectProc = mkDefault "invisible";
          ProcSubset = mkDefault "pid";

          RestrictNamespaces = mkDefault true;
          RestrictRealtime = mkDefault true;
          RestrictSUIDSGID = mkDefault true;

          SystemCallFilter = mkDefault ["@system-service" "@network-io"];
          SystemCallArchitectures = ["native"];
          SystemCallErrorNumber = mkDefault "EPERM";

          ExecPaths = ["/nix/store"];
          NoExecPaths = ["/"];

          ExecStartPost = "${pkgs.coreutils}/bin/sleep 0.2";

          ExecStart = "${pkg}/bin/cs-firewall-bouncer -c ${configFile}";
          ExecStartPre = ["${pkg}/bin/cs-firewall-bouncer -t -c ${configFile}"];
        };
      };
    };
  };
}
