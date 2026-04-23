# SPDX-License-Identifier: MIT
{
  description = "Object-driven minimal local CO-RE header generator";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          gitRevision =
            if self ? shortRev then self.shortRev
            else if self ? dirtyShortRev then self.dirtyShortRev
            else "unknown";
        in
        {
          default = pkgs.stdenv.mkDerivation {
            pname = "min-corehdr";
            version = "0.1.0";
            src = self;

            nativeBuildInputs = [
              pkgs.cmake
              pkgs.ninja
              pkgs.pkg-config
            ];

            buildInputs = [
              pkgs.libbpf
              pkgs.elfutils
              pkgs.zlib
              pkgs.zstd
            ];

            cmakeFlags = [
              "-DMIN_COREHDR_GIT_REVISION=${gitRevision}"
            ];

            meta = {
              description = "Object-driven minimal local CO-RE header generator";
              license = pkgs.lib.licenses.mit;
              mainProgram = "min-corehdr";
              platforms = pkgs.lib.platforms.linux;
            };
          };
        });

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.clang
              pkgs.clang-tools
              pkgs.cmake
              pkgs.ninja
              pkgs.pkg-config
              pkgs.libbpf
              pkgs.elfutils
              pkgs.zlib
              pkgs.zstd
              pkgs.lld
              pkgs.llvmPackages.llvm
              pkgs.hyperfine
            ];

            shellHook = ''
              export CC=clang
              export CXX=clang++
            '';
          };
        });
    };
}
