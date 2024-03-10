{
  description = "A Aggregate prometheus exporters into a single endpoint";

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }: let
    systems = flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};

      bouncer-firewall = pkgs.callPackage ./packages/bouncer-firewall {};
    in {
      formatter = pkgs.alejandra;
      packages."crowdsec-firewall-bouncer" = bouncer-firewall;
    });
  in (systems
    // {
      nixosModules = {
        crowdsec = import ./modules/crowdsec;
        crowdsec-firewall-bouncer = import ./modules/crowdsec-firewall-bouncer;
      };
      overlays.default = final: prev: {
        crowdsec-firewall-bouncer = systems.packages.${final.system}.crowdsec-firewall-bouncer;
      };
    });
}
