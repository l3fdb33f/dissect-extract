/*
  Heuristic rules for Linux persistence triage (Go/Rust ELF binaries, PHP webshells).
  Expect false positives on benign Go/Rust dev tools and some PHP apps — tune as needed.
*/

rule golang_elf_implant_heuristic {
    meta:
        description = "ELF with multiple Go runtime / toolchain markers"
    strings:
        $elf = { 7F 45 4C 46 }
        $go1 = "go1." ascii
        $go2 = "go.buildid" ascii
        $go3 = "runtime." ascii
    condition:
        $elf at 0 and 2 of ($go1, $go2, $go3)
}

rule rust_elf_implant_heuristic {
    meta:
        description = "ELF with Rust compiler / std paths (rustc)"
    strings:
        $elf = { 7F 45 4C 46 }
        $r1 = "/rustc/" ascii
        $r2 = "rustc version" ascii nocase
    condition:
        $elf at 0 and 1 of ($r1, $r2)
}

rule php_webshell_common {
    meta:
        description = "Common PHP webshell / eval patterns"
    strings:
        $s1 = "$_GET[base64_decode" nocase
        $s2 = "eval(base64_decode(" nocase
        $s3 = "$_POST[base64_decode(" nocase
        $s4 = ";return EvAl(" nocase
        $r1 = /\$_(GET|POST)\["\w"\]/
    condition:
        any of them
}
