with import <nixpkgs> {};
stdenv.mkDerivation {
  name = "dlopen-resolver";
  nativeBuildInputs = [
    python3Packages.wrapPython
  ];
  pythonPath = [
    python3.pkgs.r2pipe
    python3.pkgs.intervaltree
  ];
  buildInputs = [
    python3.pkgs.r2pipe
    python3.pkgs.intervaltree
    # useful for debugging
    radare2
  ];
  dontUnpack = true;
  installPhase = ''
    install -m755 -D ${./dlopen-resolver.py} $out/bin/dlopen-resolver
    wrapPythonPrograms
  '';
  doInstallCheck = true;

  installCheckPhase = ''
    $CC -ldl -o main ${./main.c}
    $out/bin/dlopen-resolver main | grep libfoo | wc -l | grep -q 3
  '';
}
