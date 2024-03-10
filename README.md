# Crowdsec for NixOS

This repository contains a [Nix flake](https://nixos.wiki/wiki/Flakes) for running [Crowdsec](https://www.crowdsec.net/) on NixOS.

CrowdSec is a security tool designed to protect servers, services, and applications by analyzing user behavior and network traffic to detect and block potential attacks. It operates similarly to Fail2Ban but with a few key differences:

CrowdSec leverages the power of its community by sharing information about attacks among users. When one user detects a new threat, the details are shared across the network, allowing others to protect themselves against this threat, effectively creating a collective intelligence about emerging threats.

In simple terms, think of CrowdSec as a neighborhood watch program for the internet, where everyone contributes to and benefits from a shared pool of intelligence about potential threats.

## Usage

### Crowdsec engine

To setup the [security engine](https://docs.crowdsec.net/docs/getting_started/security_engine_intro/), import the module and activate the service.

```nix
{
  inputs = {
    crowdsec = {
      url = "github:kampka/nix-flake-crowdsec";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = flakes @ {
    self,
    nixpkgs,
    crowdsec,
    ...
  }: {
    nixosConfiguration.<your-hostname> = nixpkgs.lib.nixosSystem {
      # ...
      modules = [
        # ...
        crowdsec.nixosModules.crowdsec

        ({ pkgs, lib, ... }: {
          services.crowdsec = {
            enable = true;
            enrollKeyFile = "/path/to/enroll-key";
            settings = {
              api.server = {
                listen_uri = "127.0.0.1:8080";
              };
            };
          };
        })
      ];
    };
  };
}
```

In case you are setting up a central security engine, adjust the `listen_uri` to be reachable by your bouncers.

To enroll your crowdsec engine into the central API, you need to obtain an enrollment key from the central [app dashboard](https://app.crowdsec.net/).
Enrolling your engine will give it access to community or commercial blocklist and decisions, depending on your plan.
Enrollment is optional, if you do not want to enroll your engine and just at on your own logs / events, simply omit the `enrollKeyFile` from the settings.

For additional configuration options, please consult the (Crowdsec documentation)[https://docs.crowdsec.net/docs/configuration/crowdsec_configuration/].


### Crowdsec firewall bouncer

This flake ships the Crowdsec [firewall bouncer](https://docs.crowdsec.net/docs/getting_started/security_engine_intro/).
It will block traffic from blacklisted IPs on the firewall level.

At the time of writing, only `iptables` support has proper defaults and testing.
If you are using `nftables` (`networking.nftables.enable = true`), you need to supply bouncer configuration yourself (PRs welcome). 
Please consult the [bouncer documentation](https://docs.crowdsec.net/u/bouncers/firewall/#nftables-specific-directives) for directions.


```nix
{
  inputs = {
    crowdsec = {
      url = "github:kampka/nix-flake-crowdsec";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = flakes @ {
    self,
    nixpkgs,
    crowdsec,
    ...
  }: {
    nixosConfiguration.<your-hostname> = nixpkgs.lib.nixosSystem {
      # ...
      modules = [
        # ...
        crowdsec.nixosModules.crowdsec-firewall-bouncer;

        ({ pkgs, lib, ... }: {
          nixpkgs.overlays = [crowdsec.overlays.default];
          services.crowdsec-firewall-bouncer = {
            enable = true;
            settings = {
              api_key = "<api-key>";
              api_url = "http://localhost:8080";
            };
          };
        })
      ];
    };
  };
}
```

In order to connect to your security engine, you need to [add your bouncer](https://docs.crowdsec.net/docs/cscli/cscli_bouncers_add/) to the security engine.
You can either use a pre-generated key or have the security engine generate one for you.
Depending on your security requirements and secrets management, this process is scriptable through an `ExecStartPre` script of the engine, eg.

```nix
{
  services.crowdsec = {
    ExecStartPre = let
      script = pkgs.writeScriptBin "register-bouncer" ''
        #!${pkgs.runtimeShell}
        set -eu
        set -o pipefail

        if ! cscli bouncers list | grep -q "my-bouncer"; then
          cscli bouncers add "my-bouncer" --key "<api-key>"
        fi
      '';
    in ["${script}/bin/register-bouncer"];
  };
}

```
