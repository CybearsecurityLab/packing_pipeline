#!/usr/bin/env python3
"""Guest-visible machine configuration per analysis profile.

`certified` reproduces the certified lane's QEMU arguments exactly. `vmarm` is the
anti-VM-hardened arm: same qemu64 feature set and AMD family/model, with the
hypervisor bit, the TCG CPUID leaf, the QEMU brand string, SMBIOS, ACPI OEM ids,
IDE identify strings and the RTC base replaced by fixed realistic constants.

run_trace.py and build_boot_snapshot.sh both take their machine arguments from
here, because resuming a snapshot requires the identical machine configuration.

    python3 ops/qemu/vm_profiles.py qemu-args vmarm --disk booted.qcow2 --cdrom empty.iso
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

CERTIFIED = "certified"
VMARM = "vmarm"
PROFILES = (CERTIFIED, VMARM)

MACHINE = "pc-i440fx-5.2"

VMARM_MODEL_ID = "AMD Athlon(tm) 64 X2 Dual Core Processor 5000+"
VMARM_CPU = f"qemu64,hypervisor=off,tcg-cpuid=off,model-id={VMARM_MODEL_ID}"
VMARM_OEM_ID = "ALASKA"
VMARM_OEM_TABLE_ID = "A M I"
VMARM_RTC_BASE = "2027-01-12T09:14:00"
VMARM_UUID = "6f2b1e4c-8a3d-4e57-9b1a-3c5d7e9f0a21"

VMARM_SMBIOS: tuple[tuple[tuple[str, str], ...], ...] = (
    (("type", "0"), ("vendor", "American Megatrends Inc."), ("version", "5.13"),
     ("date", "01/08/2008"), ("release", "5.13")),
    (("type", "1"), ("manufacturer", "HP-Pavilion"), ("product", "GN556AA-ABA a6110n"),
     ("version", "1.00"), ("serial", "MXX7480K2N"), ("uuid", VMARM_UUID),
     ("sku", "GN556AA#ABA"), ("family", "103C_53316J")),
    (("type", "2"), ("manufacturer", "ASUSTek Computer INC."), ("product", "NAGAMI2L"),
     ("version", "1.03"), ("serial", "MS1C78T7019"), ("asset", "CZC7480K2N"),
     ("location", "Base Board")),
    (("type", "3"), ("manufacturer", "Hewlett-Packard"), ("version", "1.00"),
     ("serial", "MXX7480K2N"), ("asset", "CZC7480K2N"), ("sku", "GN556AA#ABA")),
    (("type", "4"), ("sock_pfx", "CPU"), ("manufacturer", "AMD"),
     ("version", VMARM_MODEL_ID), ("max-speed", "2600"), ("current-speed", "2600"),
     ("processor-family", "131"), ("part", "ADO5000IAA5DO")),
    (("type", "17"), ("loc_pfx", "DIMM"), ("bank", "BANK"), ("manufacturer", "Kingston"),
     ("serial", "2A1B3C4D"), ("asset", "DIMM_A1_AssetTag"),
     ("part", "99U5316-028.A00LF"), ("speed", "800")),
)

VMARM_DISK = (("model", "WDC WD3200AAJS-60M0A1"), ("serial", "WD-WCAV2A417923"),
              ("ver", "01.03E01"))
VMARM_CDROM = (("model", "HL-DT-ST DVDRAM GH20NS10"), ("serial", "K1Q7B9C4521"),
               ("ver", "EL00"))

VMARM_PLUGIN_ARGS = ("evasion=on",)


def _check(profile: str) -> str:
    if profile not in PROFILES:
        raise ValueError(f"unknown analysis profile {profile!r}; expected one of {PROFILES}")
    return profile


def _opt(value: str) -> str:
    return str(value).replace(",", ",,")


def _join(pairs) -> str:
    return ",".join(f"{key}={_opt(value)}" for key, value in pairs)


def machine_arg(profile: str) -> str:
    if _check(profile) == CERTIFIED:
        return MACHINE
    return f"{MACHINE}," + _join((("x-oem-id", VMARM_OEM_ID),
                                  ("x-oem-table-id", VMARM_OEM_TABLE_ID)))


def cpu_arg(profile: str, cpu_model: str = "qemu64", transparent: bool = False) -> str:
    if _check(profile) == CERTIFIED:
        return cpu_model + ",-hypervisor" if transparent else cpu_model
    return f"qemu64,hypervisor=off,tcg-cpuid=off,model-id={_opt(VMARM_MODEL_ID)}"


def rtc_arg(profile: str, icount: bool) -> str:
    base = "localtime" if _check(profile) == CERTIFIED else VMARM_RTC_BASE
    return f"base={base},clock=vm" if icount else f"base={base}"


def smbios_args(profile: str) -> list[str]:
    if _check(profile) == CERTIFIED:
        return []
    out: list[str] = []
    for table in VMARM_SMBIOS:
        out += ["-smbios", _join(table)]
    return out


def _disk_backend(image: Path | str, deterministic: bool) -> str:
    if deterministic:
        return f"driver=blkdet,image.driver=qcow2,image.file.filename={image}"
    return f"file={image},format=qcow2"


def disk_args(profile: str, image: Path | str, deterministic: bool) -> list[str]:
    if _check(profile) == CERTIFIED:
        return ["-drive",
                (f"driver=blkdet,image.driver=qcow2,image.file.filename={image},"
                 "if=ide,cache=writeback"
                 if deterministic
                 else f"file={image},format=qcow2,if=ide,cache=writeback")]
    return ["-drive", f"{_disk_backend(image, deterministic)},if=none,id=ide0-hd0,"
                      "cache=writeback",
            "-device", "ide-hd,drive=ide0-hd0,bus=ide.0,unit=0," + _join(VMARM_DISK)]


def cdrom_args(profile: str, medium: Path | str | None) -> list[str]:
    if _check(profile) == CERTIFIED:
        if medium is None:
            return []
        return ["-drive", f"file={medium},format=raw,if=ide,index=2,media=cdrom"]
    backend = f"file={medium},format=raw," if medium is not None else ""
    return ["-drive", f"{backend}if=none,id=ide1-cd0,media=cdrom",
            "-device", "ide-cd,drive=ide1-cd0,bus=ide.1,unit=0," + _join(VMARM_CDROM)]


def plugin_args(profile: str) -> list[str]:
    return [] if _check(profile) == CERTIFIED else list(VMARM_PLUGIN_ARGS)


def default_stamp(profile: str, repo: Path) -> Path:
    if _check(profile) == CERTIFIED:
        return repo / "ops/qemu/backend_validation.json"
    return repo / f"ops/qemu/backend_validation.{profile}.json"


def machine_config(profile: str, *, disk: Path | str, cdrom: Path | str | None = None,
                   deterministic: bool = False, icount: bool = True,
                   cpu_model: str = "qemu64", transparent: bool = False) -> list[str]:
    return ["-machine", machine_arg(profile),
            "-cpu", cpu_arg(profile, cpu_model, transparent),
            *smbios_args(profile),
            "-rtc", rtc_arg(profile, icount),
            *disk_args(profile, disk, deterministic),
            *cdrom_args(profile, cdrom)]


def machine_config_sha256(profile: str) -> str:
    canonical = machine_config(profile, disk="DISK", cdrom="CDROM") + plugin_args(profile)
    return hashlib.sha256(json.dumps(canonical).encode()).hexdigest()


def identity_fields(profile: str) -> dict:
    if _check(profile) == CERTIFIED:
        return {}
    return {"profile": profile, "machine_config_sha256": machine_config_sha256(profile)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    qa = sub.add_parser("qemu-args", help="print the machine/device arguments, one per line")
    qa.add_argument("profile", choices=PROFILES)
    qa.add_argument("--disk", required=True)
    qa.add_argument("--cdrom")
    qa.add_argument("--deterministic", action="store_true")
    qa.add_argument("--no-icount", action="store_true")
    ident = sub.add_parser("identity", help="print the profile's backend-identity fields")
    ident.add_argument("profile", choices=PROFILES)
    args = parser.parse_args(argv)
    if args.command == "qemu-args":
        for item in machine_config(args.profile, disk=args.disk, cdrom=args.cdrom,
                                   deterministic=args.deterministic,
                                   icount=not args.no_icount):
            print(item)
    else:
        print(json.dumps(identity_fields(args.profile), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
