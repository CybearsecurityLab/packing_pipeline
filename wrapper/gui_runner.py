"""
GUI Wrapper Runner
Scans benign_sources/x86 directory and runs appropriate GUI packers on compatible files
"""

import os
import sys
import re
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Set
import argparse
import yaml
from tqdm import tqdm

# The script is commonly launched directly (`python wrapper/gui_runner.py`)
# which leaves the repo root off sys.path. Bootstrap it so the SHA gate
# shared with the CLI runner is importable.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from utils.sha_gate import ShaGate
except ImportError:
    from sha_gate import ShaGate

from base_gui import (
    BaseGUI,
    close_all_windows,
    clear_last_moved_output,
    consume_last_moved_output,
)
from asm_guard import AsmGuard
from alienyze_protector import AlienyzeProtector
from mew import Mew
from packman import Packman
from rlpack import RLPack
from ped import PEDiminisher
from shrinker import Shrinker
from upx_scrambler import (
    UpxScrambler304,
    UpxScrambler306,
    UpxScramblerRC1,
    UpxScramblerRC103,
    UpxScramblerRC105,
    UpxScramblerRC1b10,
)
from jdpack import JDPack
from npack import NPack
from nspack import NSpack
from wupack import WinUpack
from yoda_crypter import YodaCrypter
from yoda_crypter_v12 import YodaCrypterV12
from yoda_protector_v10 import YodaProtectorV10
from yoda_protector_v1012 import YodaProtectorV1012
from yoda_protector_v102 import YodaProtectorV102
from yoda_protector_v1032 import YodaProtectorV1032
from yoda_protector_v1033 import YodaProtectorV1033
from acprotect import ACProtect
from telock import Telock
from pelock import PELock
from armadillo import Armadillo
from themida_gui import ThemidaGUI
from zprotect_gui import ZProtectGUI

PACKER_FILE_SUPPORT: Dict[str, List[str]] = {
    "acprotect_std": [".exe"],
    "alienyze_protector": [".exe"],
    "armadillo": [".exe"],
    "asm_guard": [".exe"],
    "jdpack_v1.00": [".exe"],
    "mew": [".exe"],
    "npack_v1.1": [".exe"],
    "nspack_v3.7": [".exe"],
    "packman": [".exe"],
    "pe_diminisher": [".exe"],
    "pelock_v2.40": [".exe"],
    "rlpack": [".exe"],
    "shrinker_v3.4_demo": [".exe"],
    "telock_v0.98": [".exe"],
    "themida_v3.2.4.34": [".exe"],
    "upx_scrambler": [".exe"],
    "upx_scrambler_306": [".exe"],
    "upx_scrambler_rc1": [".exe"],
    "upx_scrambler_rc103": [".exe"],
    "upx_scrambler_rc105": [".exe"],
    "upx_scrambler_rc1b10": [".exe"],
    "winupack": [".exe"],
    "yoda_crypter_v1.2": [".exe"],
    "yoda_crypter_v1.3": [".exe"],
    "yoda_protector_v1.0": [".exe"],
    "yoda_protector_v1.01.2": [".exe"],
    "yoda_protector_v1.02": [".exe"],
    "yoda_protector_v1.03.2": [".exe"],
    "yoda_protector_v1.03.3": [".exe"],
    "zprotect": [".exe"],
}

PACKER_OPTIONS: Dict[str, Dict[str, str]] = {
    "asm_guard": {
        "max_compression": "maximum_instruction_compression",
        "junk_cpp": "add_junk_cpp_functions",
        "junk_partitions": "add_junk_partitions",
        "flood_mode": "enhanced_flood_mode",
        "different_types": "add_different_types",
    },
}


PACKER_DEFAULT_STATES: Dict[str, Dict[str, bool]] = {
    "acprotect_std": {},
    "alienyze_protector": {},
    "armadillo": {},
    "asm_guard": {
        "maximum_instruction_compression": False,
        "add_junk_cpp_functions": True,
        "add_junk_partitions": True,
        "enhanced_flood_mode": False,
        "add_different_types": False,
    },
    "jdpack_v1.00": {},
    "mew": {},
    "npack_v1.1": {},
    "nspack_v3.7": {},
    "packman": {},
    "pe_diminisher": {},
    "pelock_v2.40": {},
    "rlpack": {},
    "shrinker_v3.4_demo": {},
    "telock_v0.98": {},
    "themida_v3.2.4.34": {},
    "upx_scrambler": {},
    "upx_scrambler_306": {},
    "upx_scrambler_rc1": {},
    "upx_scrambler_rc103": {},
    "upx_scrambler_rc105": {},
    "upx_scrambler_rc1b10": {},
    "winupack": {},
    "yoda_crypter_v1.2": {},
    "yoda_crypter_v1.3": {},
    "yoda_protector_v1.0": {},
    "yoda_protector_v1.01.2": {},
    "yoda_protector_v1.02": {},
    "yoda_protector_v1.03.2": {},
    "yoda_protector_v1.03.3": {},
    "zprotect": {},
}

# Default packer to use
DEFAULT_PACKER = "all"


class GUIWrapperRunner:
    def __init__(
        self,
        source_dir: str,
        main_dir: str,
        yaml_path: str,
        sha_gate: Optional[object] = None,
    ):
        """
        Initialize the GUI Wrapper Runner

        Args:
            source_dir: Directory containing files to pack (e.g., benign_sources/x86)
            main_dir: Main project directory
            yaml_path: Path to packer_corpus.yaml
            sha_gate: Optional ShaGate instance shared with the CLI runner.
        """
        self.source_dir = Path(source_dir).resolve()
        self.main_dir = Path(main_dir).resolve()
        self.yaml_path = Path(yaml_path).resolve()
        self.sha_gate = sha_gate

        # One row per packer batch, accumulated across the whole run (including
        # partial rows recorded on Ctrl+C) and printed by print_final_report.
        self.report_rows = []

        # Validate paths
        if not self.source_dir.exists():
            raise FileNotFoundError(f"Source directory not found: {self.source_dir}")
        if not self.yaml_path.exists():
            raise FileNotFoundError(f"YAML file not found: {self.yaml_path}")

        # Load YAML config for version lookups
        with open(self.yaml_path, "r") as f:
            self._config = yaml.safe_load(f)
        self._version_map = {}
        for defn in self._config.get("definitions", []):
            name = defn.get("packer_name", "").lower()
            version = defn.get("version", "unknown")
            self._version_map[name] = version

    def get_supported_extensions(self, packer_name: str) -> List[str]:
        """Get list of supported file extensions for a packer"""
        return PACKER_FILE_SUPPORT.get(packer_name, ["*"])

    def get_packer_options(self, packer_name: str) -> Dict[str, str]:
        """Get option name mappings for a packer"""
        return PACKER_OPTIONS.get(packer_name, {})

    def get_packer_defaults(self, packer_name: str) -> Dict[str, bool]:
        """Get default option states for a packer"""
        return PACKER_DEFAULT_STATES.get(packer_name, {})

    def get_packer_directory_name(self, packer_name: str) -> str:
        """
        Canonical ``<packer>_<safe_version>`` directory name used for the
        SHA gate's packer identity (independent of any --output-dir override).
        """
        version = self._version_map.get(packer_name.lower(), "unknown")
        # Sanitize version for filesystem (replace spaces, parens, etc.)
        safe_version = re.sub(r'[^\w\.\-]', '_', version).strip('_')
        return f"{packer_name}_{safe_version}"

    def get_output_directory(self, packer_name: str) -> Path:
        """
        Get the output directory for a packer's packed files

        Args:
            packer_name: Name of the packer

        Returns:
            Path: Output directory (e.g., main_dir/packed_sources/asm_guard_2.9.4)
        """
        dir_name = self.get_packer_directory_name(packer_name)
        output_dir = self.main_dir / "packed_sources" / dir_name
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def get_temp_directory(self, output_dir: Path) -> Path:
        """
        Get the temp directory inside the output directory for working copies

        Args:
            output_dir: The output directory

        Returns:
            Path: Temp directory (e.g., output_dir/temp)
        """
        temp_dir = output_dir / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        return temp_dir

    def copy_to_temp(self, file_path: Path, output_dir: Path) -> Path:
        """
        Copy input file to temp directory inside output directory

        Args:
            file_path: Path to the original input file
            output_dir: The output directory

        Returns:
            Path: Path to the copied file in temp directory
        """
        temp_dir = self.get_temp_directory(output_dir)
        temp_file = temp_dir / file_path.name

        print("[INFO] Copying input file to temp directory...")
        print(f"[INFO]   Source: {file_path}")
        print(f"[INFO]   Dest:   {temp_file}")

        try:
            shutil.copy2(file_path, temp_file)
        except OSError as e:
            if e.winerror in (32, 1224):
                # WinError 1224: file has a user-mapped section open (memory-mapped by OS).
                # WinError 32: sharing violation (file locked by another process).
                # Fall back to raw binary copy which bypasses this restriction.
                print(f"[WARNING] shutil.copy2 blocked (WinError {e.winerror}); using raw binary copy.")
                with open(file_path, "rb") as src, open(temp_file, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                shutil.copystat(file_path, temp_file)
            else:
                raise

        return temp_file

    def is_file_supported(self, file_path: Path, packer_name: str) -> bool:
        """Check if a file is supported by the specified packer"""
        supported = self.get_supported_extensions(packer_name)

        # "*" means all files are supported
        if "*" in supported:
            return True

        return file_path.suffix.lower() in [ext.lower() for ext in supported]

    # ========== DIRECTORY SNAPSHOT & CLEANUP ==========

    def snapshot_directory(self, directory: Path, recursive: bool = False) -> Set[Path]:
        """
        Take a snapshot of all files in a directory

        Args:
            directory: Directory to snapshot
            recursive: Whether to include subdirectories

        Returns:
            Set of absolute file paths
        """
        directory = Path(directory).resolve()

        if recursive:
            files = set(f.resolve() for f in directory.rglob("*") if f.is_file())
        else:
            files = set(f.resolve() for f in directory.glob("*") if f.is_file())

        print(f"[SNAPSHOT] Captured {len(files)} files in {directory}")
        return files

    # ========== SCANNING & PACKING ==========

    def scan_source_directory(
        self, packer_name: str = "asm_guard", recursive: bool = False
    ) -> List[Path]:
        """
        Scan source directory for files compatible with the specified packer

        Args:
            packer_name: Name of the packer to filter by
            recursive: Whether to scan subdirectories

        Returns:
            List of compatible file paths
        """
        print(f"\n[INFO] Scanning directory: {self.source_dir}")
        print(f"[INFO] Packer: {packer_name}")
        print(
            f"[INFO] Supported extensions: {self.get_supported_extensions(packer_name)}"
        )

        if recursive:
            all_files = list(self.source_dir.rglob("*"))
        else:
            all_files = list(self.source_dir.glob("*"))

        # Filter to only files (not directories)
        all_files = [f for f in all_files if f.is_file()]

        # Filter by supported extensions
        compatible_files = [
            f for f in all_files if self.is_file_supported(f, packer_name)
        ]

        print(f"[INFO] Total files found: {len(all_files)}")
        print(f"[INFO] Compatible files: {len(compatible_files)}")

        return compatible_files

    def build_packer_config(
        self,
        packer_name: str,
        check_options: Optional[List[str]] = None,
        uncheck_options: Optional[List[str]] = None,
    ) -> Optional[Dict[str, bool]]:
        """
        Build configuration dict for a packer from check/uncheck lists
        """
        if not check_options and not uncheck_options:
            return None

        name_map = self.get_packer_options(packer_name)
        if not name_map:
            print(f"[WARNING] No options defined for packer: {packer_name}")
            return None

        config = {}

        if check_options:
            for short_name in check_options:
                if short_name in name_map:
                    config[name_map[short_name]] = True
                else:
                    print(f"[WARNING] Unknown option '{short_name}' for {packer_name}")

        if uncheck_options:
            for short_name in uncheck_options:
                if short_name in name_map:
                    config[name_map[short_name]] = False
                else:
                    print(f"[WARNING] Unknown option '{short_name}' for {packer_name}")

        return config if config else None

    def run_npack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run nPack wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = NPack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("npack_v1.1")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_nspack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run NSpack wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = NSpack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("nspack_v3.7")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_jdpack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run JDPack wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = JDPack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("jdpack_v1.00")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_asm_guard(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run ASM Guard wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = AsmGuard(str(self.yaml_path), str(self.main_dir))

            # Determine click mode - default to "all" (check all boxes)
            click_mode = packer_config if packer_config else "all"

            # Use packer-specific output directory if not specified
            if output_dir is None:
                output_dir = self.get_output_directory("asm_guard")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=click_mode,
                file_path=str(file_path.resolve()),  # Always use absolute path
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_alienyze_protector(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Alienyze Protector wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = AlienyzeProtector(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("alienyze_protector")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_mew(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run MEW wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Mew(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("mew")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_packman(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Packman wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Packman(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("packman")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_rlpack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run RLPack wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = RLPack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("rlpack")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_pe_diminisher(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run PE Diminisher wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = PEDiminisher(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("pe_diminisher")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_shrinker(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run shrinker wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Shrinker(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("shrinker_v3.4_demo")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_upx_scrambler(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run UPX Scrambler wrapper on a single file.
        The wrapper handles UPX pre-packing internally via packer_runner.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScrambler304(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_upx_scrambler_306(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler 3.06 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScrambler306(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_306")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_upx_scrambler_rc1(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler RC1 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScramblerRC1(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_rc1")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_upx_scrambler_rc103(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler RC1.03 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScramblerRC103(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_rc103")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_upx_scrambler_rc105(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler RC1.05 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScramblerRC105(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_rc105")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_upx_scrambler_rc1b10(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run UPX Scrambler RC1b10 wrapper on a single file."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = UpxScramblerRC1b10(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("upx_scrambler_rc1b10")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_winupack(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run WinUpack wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = WinUpack(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("winupack")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_yoda_crypter(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Crypter wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaCrypter(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_crypter_v1.3")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_yoda_crypter_v12(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Crypter v1.2 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaCrypterV12(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_crypter_v1.2")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_yoda_protector_v10(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.0 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV10(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.0")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_yoda_protector_v1012(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.01.2 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV1012(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.01.2")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_yoda_protector_v102(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.02 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV102(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.02")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_yoda_protector_v1032(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.03.2 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV1032(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.03.2")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_yoda_protector_v1033(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Yoda's Protector v1.03.3 wrapper on a single file.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = YodaProtectorV1033(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("yoda_protector_v1.03.3")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback

            traceback.print_exc()
            return False

    def run_telock(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Telock wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Telock(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("telock_v0.98")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_acprotect(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run ACProtect wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = ACProtect(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("acprotect_std")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_pelock(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run PELock wrapper on a single file
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = PELock(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("pelock_v2.40")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode=packer_config if packer_config else "all",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_armadillo(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Armadillo wrapper - launch, wait 60 seconds, close.
        Armadillo is GUI-only; no CLI scripting is possible.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = Armadillo(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("armadillo")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode="none",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_themida(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run Themida wrapper - launch, wait 60 seconds, close.
        Themida is GUI-only; no CLI scripting is possible.
        """
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = ThemidaGUI(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("themida_v3.2.4.34")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                click_mode="none",
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_zprotect(
        self,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """Run ZProtect v1.4.2.0 GUI wrapper."""
        print(f"\n{'=' * 60}")
        print(f"PROCESSING: {file_path.name}")
        print(f"{'=' * 60}")

        try:
            wrapper = ZProtectGUI(str(self.yaml_path), str(self.main_dir))

            if output_dir is None:
                output_dir = self.get_output_directory("zprotect")

            print(f"[INFO] Output directory: {output_dir}")

            success = wrapper.run(
                file_path=str(file_path.resolve()),
                output_dir=str(output_dir),
            )
            return success

        except Exception as e:
            print(f"[ERROR] Failed to process {file_path.name}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def run_packer(
        self,
        packer_name: str,
        file_path: Path,
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
    ) -> bool:
        """
        Run the specified packer on a file

        The input file is first copied to a temp directory inside the output
        directory, and the packer operates on that copy.
        """
        packer_methods = {
            "acprotect_std": self.run_acprotect,
            "alienyze_protector": self.run_alienyze_protector,
            "armadillo": self.run_armadillo,
            "asm_guard": self.run_asm_guard,
            "jdpack_v1.00": self.run_jdpack,
            "mew": self.run_mew,
            "npack_v1.1": self.run_npack,
            "nspack_v3.7": self.run_nspack,
            "packman": self.run_packman,
            "pe_diminisher": self.run_pe_diminisher,
            "pelock_v2.40": self.run_pelock,
            "rlpack": self.run_rlpack,
            "shrinker_v3.4_demo": self.run_shrinker,
            "telock_v0.98": self.run_telock,
            "themida_v3.2.4.34": self.run_themida,
            "upx_scrambler": self.run_upx_scrambler,
            "upx_scrambler_306": self.run_upx_scrambler_306,
            "upx_scrambler_rc1": self.run_upx_scrambler_rc1,
            "upx_scrambler_rc103": self.run_upx_scrambler_rc103,
            "upx_scrambler_rc105": self.run_upx_scrambler_rc105,
            "upx_scrambler_rc1b10": self.run_upx_scrambler_rc1b10,
            "winupack": self.run_winupack,
            "yoda_crypter_v1.2": self.run_yoda_crypter_v12,
            "yoda_crypter_v1.3": self.run_yoda_crypter,
            "yoda_protector_v1.0": self.run_yoda_protector_v10,
            "yoda_protector_v1.01.2": self.run_yoda_protector_v1012,
            "yoda_protector_v1.02": self.run_yoda_protector_v102,
            "yoda_protector_v1.03.2": self.run_yoda_protector_v1032,
            "yoda_protector_v1.03.3": self.run_yoda_protector_v1033,
            "zprotect": self.run_zprotect,
        }

        if packer_name not in packer_methods:
            print(f"[ERROR] Unknown packer: {packer_name}")
            print(f"[INFO] Available packers: {list(packer_methods.keys())}")
            return False

        if output_dir is None:
            output_dir = self.get_output_directory(packer_name)

        # Copy input file to temp directory inside output directory.
        temp_file = self.copy_to_temp(file_path, output_dir)

        # The SHA gate needs an input SHA that does not change after the
        # wrapper runs (the GUI packer frequently modifies or moves the
        # temp copy in place). Hash it immediately while its bytes are
        # guaranteed to be the pre-pack input.
        input_sha = (
            self.sha_gate.add_input(temp_file)
            if self.sha_gate is not None
            else None
        )

        # Clear any stale thread-local path from a previous wrapper call
        # so we only consume the move THIS call performs.
        clear_last_moved_output()

        wrapper_ok = packer_methods[packer_name](
            temp_file,
            packer_config=packer_config,
            output_dir=output_dir,
        )

        if not wrapper_ok:
            return False

        final_path = consume_last_moved_output()
        if final_path is None:
            if self.sha_gate is not None:
                print(
                    f"[ERROR] [PACK_SHA_GATE_ERROR] packer={packer_name} "
                    f"app={file_path.name}: wrapper reported success without a "
                    f"final output path"
                )
            return False

        if self.sha_gate is None:
            return True

        result = self.sha_gate.verify_pack(
            input_path=temp_file,
            input_sha256=input_sha,
            output_path=final_path,
            packer_dir=self.get_packer_directory_name(packer_name),
            app=file_path.name,
        )
        if result.accepted:
            return True

        print(f"[ERROR] [GATE] {result.message}")
        try:
            Path(final_path).unlink(missing_ok=True)
        except OSError as e:
            print(f"[WARNING] Could not remove rejected output {final_path}: {e}")
        return False

    def is_already_packed(self, file_path: Path, packer_name: str) -> bool:
        """
        Check if a file has already been packed (output exists in packed_sources)
        Uses fuzzy matching - checks if any file contains the original stem
        """
        output_dir = self.get_output_directory(packer_name)
        stem = file_path.stem.lower()

        # Check if any file in output_dir contains the original filename stem
        for existing_file in output_dir.glob("*"):
            if existing_file.is_file() and stem in existing_file.stem.lower():
                return True
        return False

    def run_batch(
        self,
        packer_name: str = "asm_guard",
        packer_config: Optional[Dict[str, bool]] = None,
        output_dir: Optional[Path] = None,
        recursive: bool = False,
        dry_run: bool = False,
        limit: Optional[int] = None,
        skip_existing: bool = True,
    ) -> Dict[str, bool]:
        """
        Run packer on all compatible files in the source directory

        Args:
            packer_name: Name of the packer to use
            packer_config: Packer-specific configuration
            output_dir: Directory to save packed files (if None, uses default)
            recursive: Whether to scan subdirectories
            dry_run: If True, only list files without processing
            limit: Maximum number of files to process (None = all)
            skip_existing: If True, skip files that are already packed

        Returns:
            Dict mapping filename to success status
        """
        # Get compatible files
        files = self.scan_source_directory(packer_name, recursive)

        if not files:
            print("[WARNING] No compatible files found!")
            self._record_report_row(packer_name, {}, [], note="no compatible files")
            return {}

        # Use packer-specific output directory if not specified
        if output_dir is None:
            output_dir = self.get_output_directory(packer_name)

        # Filter out already packed files
        if skip_existing:
            files_to_process = []
            skipped_files = []

            for f in files:
                if self.is_already_packed(f, packer_name):
                    skipped_files.append(f)
                else:
                    files_to_process.append(f)

            if skipped_files:
                print(f"\n[INFO] Skipping {len(skipped_files)} already packed files:")
                for f in skipped_files[:10]:
                    print(f"  - {f.name}")
                if len(skipped_files) > 10:
                    print(f"  ... and {len(skipped_files) - 10} more")

            files = files_to_process

        if limit:
            files = files[:limit]
            print(f"[INFO] Limited to first {limit} files")

        if not files:
            print("[INFO] All files already packed! Nothing to do.")
            self._record_report_row(
                packer_name, {}, skipped_files, note="all files already packed"
            )
            return {}

        # Print file list
        print(f"\n{'=' * 60}")
        print(f"FILES TO PROCESS ({len(files)} files)")
        print(f"{'=' * 60}")
        print(f"[INFO] Output directory: {output_dir}")
        for i, f in enumerate(files, 1):
            print(f"  {i:3d}. {f.name}")

        if dry_run:
            print("\n[DRY RUN] No files will be processed")
            self._record_report_row(packer_name, {}, [], note="dry run")
            return {f.name: None for f in files}

        # Prime the SHA gate with the input batch BEFORE any wrapper call so
        # an output cannot equal an input that hasn't been packed yet. The
        # individual run_packer() call still re-hashes the per-file temp
        # copy (which may differ when --no-skip overrides existing outputs),
        # so the gate's input set is authoritative.
        if self.sha_gate is not None:
            self.sha_gate.prime_inputs(files)

        # ========== SNAPSHOT SOURCE DIRECTORY BEFORE PROCESSING ==========
        print("\n[INFO] Taking snapshot of source directory before processing...")
        original_files = self.snapshot_directory(self.source_dir, recursive=recursive)

        # Process each file
        results = {}
        skipped = skipped_files if skip_existing else []
        file_bar = tqdm(
            files,
            total=len(files),
            unit="file",
            desc=f"[{packer_name}] Files",
            position=1,
            leave=False,
        )
        try:
            for i, file_path in enumerate(file_bar, 1):
                file_bar.set_postfix_str(file_path.name)

                success = self.run_packer(
                    packer_name,
                    file_path,
                    packer_config=packer_config,
                    output_dir=output_dir,
                )
                results[file_path.name] = success

                # Brief pause between files
                if i < len(files):
                    import time

                    time.sleep(2)
        finally:
            file_bar.close()
            # Always run on the way out — including a Ctrl+C mid-batch — so an
            # interrupted run still contributes its partial counts to the final
            # report and never leaves working copies behind.
            self._record_report_row(packer_name, results, skipped)

            # ========== DELETE TEMP DIRECTORY ==========
            temp_dir = self.get_temp_directory(output_dir)
            if temp_dir.exists():
                import shutil

                shutil.rmtree(temp_dir, ignore_errors=True)
                print(f"[INFO] Deleted temp directory: {temp_dir}")

        # Print per-packer summary (full runs only; Ctrl+C unwinds to the final
        # report instead).
        self.print_summary(results, skipped)

        return results

    def print_summary(self, results: Dict[str, bool], skipped_files: List[Path] = None):
        """Print processing summary"""
        print(f"\n{'=' * 60}")
        print("BATCH PROCESSING SUMMARY")
        print(f"{'=' * 60}")

        successful = sum(1 for v in results.values() if v is True)
        failed = sum(1 for v in results.values() if v is False)
        dry_run_skipped = sum(1 for v in results.values() if v is None)
        already_packed = len(skipped_files) if skipped_files else 0
        total = len(results) + already_packed

        for filename, status in results.items():
            if status is True:
                status_str = "✓ SUCCESS"
            elif status is False:
                status_str = "✗ FAILED"
            else:
                status_str = "○ DRY RUN"
            print(f"  {status_str}  {filename}")

        # List skipped (already packed) files
        if skipped_files:
            print("\n  SKIPPED (already packed):")
            for f in skipped_files:
                print(f"    ○ {f.name}")

        # List failed files explicitly
        failed_files = [name for name, status in results.items() if status is False]
        if failed_files:
            print("\n  FAILED FILES:")
            for name in failed_files:
                print(f"    ✗ {name}")

        print(f"\n  Total:         {total}")
        print(f"  Successful:    {successful}")
        print(f"  Failed:        {failed}")
        print(f"  Already packed:{already_packed}")
        if dry_run_skipped:
            print(f"  Dry run:       {dry_run_skipped}")
        print(f"{'=' * 60}")

    def _record_report_row(self, packer_name, results, skipped_files, note=""):
        """Append one packer's outcome to self.report_rows for the final report.

        Counts only completed files (True/False); dry-run placeholders (None)
        are ignored. Safe to call from a finally block on Ctrl+C, where results
        holds only the files finished before the interrupt.
        """
        successful = sum(1 for v in results.values() if v is True)
        failed = sum(1 for v in results.values() if v is False)
        already = len(skipped_files) if skipped_files else 0
        processed = sum(1 for v in results.values() if v is not None)
        self.report_rows.append(
            {
                "packer": packer_name,
                "packed": successful,
                "failed": failed,
                "skipped": already,
                "total": processed + already,
                "note": note,
            }
        )

    def print_final_report(self):
        """Print an aggregated summary of every packer batch and write it to file.

        Mirrors the packer_runner report: a per-packer table with totals, plus a
        callout of packers that failed without packing anything and a list of
        packers that never ran. Written to packed_sources/gui_packing_report.txt,
        overwritten each run.
        """
        rows = self.report_rows
        executed = [r for r in rows if not r.get("note")]
        not_run = [r for r in rows if r.get("note")]

        lines = []
        lines.append("=" * 72)
        lines.append("FINAL GUI PACKING REPORT")
        lines.append("=" * 72)

        if not executed and not not_run:
            lines.append("No GUI packing was performed.")
            lines.append("=" * 72)
        else:
            if executed:
                name_w = max(max(len(r["packer"]) for r in executed), len("Packer"))

                header = (
                    f"{'Packer':<{name_w}}  {'Packed':>6}  {'Skipped':>7}  "
                    f"{'Failed':>6}  {'Total':>6}"
                )
                lines.append(header)
                lines.append("-" * len(header))

                tot_packed = tot_skipped = tot_failed = tot_total = 0
                for r in executed:
                    lines.append(
                        f"{r['packer']:<{name_w}}  {r['packed']:>6}  {r['skipped']:>7}  "
                        f"{r['failed']:>6}  {r['total']:>6}"
                    )
                    tot_packed += r["packed"]
                    tot_skipped += r["skipped"]
                    tot_failed += r["failed"]
                    tot_total += r["total"]

                lines.append("-" * len(header))
                lines.append(
                    f"{'TOTALS':<{name_w}}  {tot_packed:>6}  {tot_skipped:>7}  "
                    f"{tot_failed:>6}  {tot_total:>6}"
                )

                # Surface packers that produced nothing new but had failures.
                problem = [r for r in executed if r["failed"] > 0 and r["packed"] == 0]
                if problem:
                    lines.append("")
                    lines.append("[!] Packers that packed 0 files and had failures:")
                    for r in problem:
                        lines.append(
                            f"    - {r['packer']}: {r['failed']} failed of {r['total']}"
                        )
            else:
                lines.append("No packers produced output.")

            # Packers that never ran (no targets, dry run, already packed, etc.).
            if not_run:
                lines.append("")
                lines.append(f"[i] Packers not run ({len(not_run)}):")
                for r in not_run:
                    lines.append(f"    - {r['packer']}: {r['note']}")

            lines.append("=" * 72)

        report_text = "\n".join(lines)
        print("\n" + report_text)

        # Persist to packed_sources, overwriting any previous report.
        try:
            out_dir = self.main_dir / "packed_sources"
            out_dir.mkdir(parents=True, exist_ok=True)
            report_path = out_dir / "gui_packing_report.txt"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_text + "\n")
            print(f"\n[*] Report written to: {report_path}")
        except Exception as e:
            print(f"[!] Warning: could not write report file: {e}")


def build_packer_argparser(packer_name: str, parser: argparse.ArgumentParser):
    """Add packer-specific arguments to the parser"""
    options = PACKER_OPTIONS.get(packer_name, {})

    if not options:
        return

    option_choices = list(options.keys())

    parser.add_argument(
        "--check",
        nargs="+",
        choices=option_choices,
        metavar="OPTION",
        help=f"Set these options to ENABLED. Choices: {', '.join(option_choices)}",
    )

    parser.add_argument(
        "--uncheck",
        nargs="+",
        choices=option_choices,
        metavar="OPTION",
        help=f"Set these options to DISABLED. Choices: {', '.join(option_choices)}",
    )


def print_packer_info(packer_name: str):
    """Print detailed info about a packer's options"""
    print(f"\n{'=' * 60}")
    print(f"PACKER: {packer_name}")
    print(f"{'=' * 60}")

    extensions = PACKER_FILE_SUPPORT.get(packer_name, ["*"])
    ext_str = ", ".join(extensions) if extensions != ["*"] else "ALL FILES"
    print(f"\nSupported file types: {ext_str}")

    options = PACKER_OPTIONS.get(packer_name, {})
    defaults = PACKER_DEFAULT_STATES.get(packer_name, {})

    if options:
        print("\nAvailable options:")
        for short_name, full_name in options.items():
            default_state = defaults.get(full_name, False)
            state_str = "CHECKED" if default_state else "UNCHECKED"
            print(f"  {short_name:20s} -> {full_name}")
            print(f"  {'':20s}    Default: {state_str}")
    else:
        print("\nNo configurable options defined.")

    print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="GUI Wrapper Runner - Batch process files with GUI packers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all compatible files in x86 directory with ASM Guard
  # Output goes to ../packed_sources/asm_guard/
  python gui_wrapper_runner.py
  
  # Dry run - list files without processing
  python gui_wrapper_runner.py --dry-run
  
  # Process only first 5 files
  python gui_wrapper_runner.py --limit 5
  
  # Process single file
  python gui_wrapper_runner.py --file "C:\\path\\to\\file.exe"
  
  # Use custom options (packer-specific)
  python gui_wrapper_runner.py --check max_compression --uncheck junk_cpp
  
  # Specify custom output directory
  python gui_wrapper_runner.py --output-dir "C:\\custom\\output"
  
  # Scan subdirectories recursively
  python gui_wrapper_runner.py --recursive
  
  # Show info about a specific packer
  python gui_wrapper_runner.py --packer-info asm_guard

  # List all available packers
  python gui_wrapper_runner.py --list-packers
  
  # Re-process all files (don't skip existing)
  python gui_wrapper_runner.py --no-skip
        """,
    )

    parser.add_argument(
        "--packer",
        nargs="+",
        default=[DEFAULT_PACKER],
        metavar="PACKER",
        choices=list(PACKER_FILE_SUPPORT.keys()) + ["all"],
        help=f"One or more packers (space-separated), or 'all' to run every "
        f"GUI packer (default: {DEFAULT_PACKER}). Example: "
        f"--packer upx_scrambler_rc1 telock_v0.98 winupack",
    )

    parser.add_argument(
        "--exclude",
        nargs="+",
        default=None,
        metavar="PACKER",
        choices=list(PACKER_FILE_SUPPORT.keys()),
        help="Packer(s) to skip when --packer all is used (space-separated list)",
    )

    parser.add_argument(
        "--source-dir",
        type=str,
        default="../benign_sources/x86",
        help="Source directory containing files",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory to save packed files (default: ../packed_sources/<packer>/)",
    )

    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Process a single file instead of batch",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List files without processing",
    )

    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Scan subdirectories recursively",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of files to process",
    )

    parser.add_argument(
        "--list-packers",
        action="store_true",
        help="List available packers and their supported file types",
    )

    parser.add_argument(
        "--packer-info",
        type=str,
        metavar="PACKER",
        help="Show detailed info about a specific packer's options",
    )

    parser.add_argument(
        "--no-skip",
        action="store_true",
        help="Process all files even if already packed",
    )

    parser.add_argument(
        "--gui-timeout",
        type=int,
        default=BaseGUI.EXTRA_LONG_TIMEOUT,
        metavar="SECONDS",
        help=f"Max seconds to wait for a single file to finish packing "
        f"(default: {BaseGUI.EXTRA_LONG_TIMEOUT}). Raise this for large "
        f"inputs (e.g. --gui-timeout 1500 for 60+ MB files).",
    )

    parser.add_argument(
        "--sha-gate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Reject SHA pass-throughs and cross-packer duplicate outputs "
             "(default: enabled; use --no-sha-gate for legacy/debug runs).",
    )

    # Add packer-specific options for default packer
    build_packer_argparser(DEFAULT_PACKER, parser)

    args = parser.parse_args()

    # List packers and exit
    if args.list_packers:
        print("\n" + "=" * 60)
        print("AVAILABLE PACKERS AND SUPPORTED FILE TYPES")
        print("=" * 60)
        for packer, extensions in PACKER_FILE_SUPPORT.items():
            ext_str = ", ".join(extensions) if extensions != ["*"] else "ALL FILES"
            print(f"  {packer:20s} : {ext_str}")
        print("=" * 60)
        print("\nUse --packer-info <n> for detailed options")
        return 0

    # Show packer info and exit
    if args.packer_info:
        if args.packer_info not in PACKER_FILE_SUPPORT:
            print(f"[ERROR] Unknown packer: {args.packer_info}")
            print(f"[INFO] Available: {list(PACKER_FILE_SUPPORT.keys())}")
            return 1
        print_packer_info(args.packer_info)
        return 0

    # Determine paths
    script_dir = Path(__file__).parent.resolve()
    main_dir = script_dir.parent

    # Source directory - resolve to absolute. A relative path is tried
    # against, in order: the wrapper/ script dir (so the default
    # "../benign_sources/x86" keeps resolving exactly as before), then the
    # current working directory (what the user naturally types from the
    # project root, e.g. "benign_sources/x86"), then the project root.
    # First existing match wins; otherwise fall back to the script-relative
    # form so the error message shows a sensible path.
    raw_src = Path(args.source_dir)
    if raw_src.is_absolute():
        source_dir = raw_src.resolve()
    else:
        candidates = [script_dir / raw_src, Path.cwd() / raw_src, main_dir / raw_src]
        source_dir = next(
            (c.resolve() for c in candidates if c.exists()),
            (script_dir / raw_src).resolve(),
        )

    # Output directory (if specified via CLI)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    if output_dir is not None and output_dir == (main_dir / "packed_sources").resolve():
        parser.error(
            "--output-dir must not be the packed_sources root: every packer would "
            "write flat into it, so samples lose their packer attribution and "
            "collide on the input filename. Pass a per-packer subdirectory, or "
            "omit --output-dir to use packed_sources/<packer>/."
        )

    yaml_path = main_dir / "manifest" / "packer_corpus.yaml"

    # --packer is a list (nargs="+"). Normalize it into the concrete run
    # list: "all" (alone or mixed in) expands to every GUI packer minus
    # --exclude; otherwise take the names given, de-duplicated in order.
    requested = args.packer
    if "all" in requested:
        packers_to_run = list(PACKER_FILE_SUPPORT.keys())
        if args.exclude:
            excluded = set(args.exclude)
            packers_to_run = [p for p in packers_to_run if p not in excluded]
            print(
                f"[INFO] Excluding {len(excluded)} packer(s): "
                f"{', '.join(sorted(excluded))}"
            )
    else:
        seen = set()
        packers_to_run = []
        for p in requested:
            if p not in seen:
                seen.add(p)
                packers_to_run.append(p)
    multi_run = len(packers_to_run) > 1

    # Override the per-file packing timeout for every wrapper at once. Every
    # wrapper reads self.EXTRA_LONG_TIMEOUT at call time, so setting the base
    # class attribute here propagates to all of them (e.g. 62 MB inputs need
    # more than the 500s default to finish scrambling).
    if args.gui_timeout != BaseGUI.EXTRA_LONG_TIMEOUT:
        print(
            f"[INFO] Per-file packing timeout: {args.gui_timeout}s "
            f"(default {BaseGUI.EXTRA_LONG_TIMEOUT}s)"
        )
    BaseGUI.EXTRA_LONG_TIMEOUT = args.gui_timeout

    print(f"Script directory: {script_dir}")
    print(f"Main directory: {main_dir}")
    print(f"Source directory: {source_dir}")
    print(f"YAML path: {yaml_path}")
    if output_dir:
        print(f"Output directory (CLI): {output_dir}")
    elif multi_run:
        print(f"Packers: {', '.join(packers_to_run)}")
    else:
        print(f"Output directory: ../packed_sources/{packers_to_run[0]}/ (default)")

    # Instantiate the SHA gate once for the entire --packer all run so
    # state (input SHAs, published output SHAs) is shared across every
    # GUI packer in this process.
    packed_root = main_dir / "packed_sources"
    sha_gate = ShaGate(packed_root, pipeline="gui") if args.sha_gate else None
    if sha_gate is not None:
        print("[*] SHA gate: ENABLED  (use --no-sha-gate to disable)")
    else:
        print("[!] SHA gate: DISABLED  (pass-throughs and cross-packer "
              "duplicates will be accepted)")

    runner = None
    try:
        runner = GUIWrapperRunner(
            source_dir=str(source_dir),
            main_dir=str(main_dir),
            yaml_path=str(yaml_path),
            sha_gate=sha_gate,
        )

        # Build packer-specific config from args. Per-packer options only
        # make sense for a single packer; a multi-packer run uses defaults.
        packer_config = None
        if not multi_run:
            packer_config = runner.build_packer_config(
                packers_to_run[0],
                check_options=getattr(args, "check", None),
                uncheck_options=getattr(args, "uncheck", None),
            )

        # Multi-packer mode — run each packer in sequence.
        if multi_run:
            all_packers = packers_to_run
            any_failed = False

            packer_bar = tqdm(
                all_packers,
                total=len(all_packers),
                unit="packer",
                desc="Packers completed",
                position=0,
                leave=True,
            )

            if args.file:
                file_path = Path(args.file).resolve()
                if not file_path.exists():
                    packer_bar.close()
                    print(f"[ERROR] File not found: {file_path}")
                    return 1
                for packer_name in packer_bar:
                    packer_bar.set_postfix_str(packer_name)
                    tqdm.write(f"\n{'#' * 60}")
                    tqdm.write(f"PACKER: {packer_name}")
                    tqdm.write(f"{'#' * 60}")
                    success = runner.run_packer(
                        packer_name,
                        file_path,
                        packer_config=None,
                        output_dir=None,
                    )
                    runner._record_report_row(
                        packer_name, {file_path.name: success}, []
                    )
                    if not success:
                       any_failed = True
            else:
                for packer_name in packer_bar:
                    packer_bar.set_postfix_str(packer_name)
                    tqdm.write(f"\n{'#' * 60}")
                    tqdm.write(f"PACKER: {packer_name}")
                    tqdm.write(f"{'#' * 60}")
                    results = runner.run_batch(
                        packer_name=packer_name,
                        packer_config=None,
                        output_dir=None,
                        recursive=args.recursive,
                        dry_run=args.dry_run,
                        limit=args.limit,
                        skip_existing=not args.no_skip,
                    )
                    if any(v is False for v in results.values()):
                        any_failed = True

            packer_bar.close()
            return 1 if any_failed else 0

        # Single-packer mode
        single_packer = packers_to_run[0]

        # Single file mode
        if args.file:
            file_path = Path(args.file).resolve()
            if not file_path.exists():
                print(f"[ERROR] File not found: {file_path}")
                return 1

            success = runner.run_packer(
                single_packer,
                file_path,
                packer_config=packer_config,
                output_dir=output_dir,
            )
            runner._record_report_row(single_packer, {file_path.name: success}, [])

            return 0 if success else 1

        # Batch mode
        results = runner.run_batch(
            packer_name=single_packer,
            packer_config=packer_config,
            output_dir=output_dir,
            recursive=args.recursive,
            dry_run=args.dry_run,
            limit=args.limit,
            skip_existing=not args.no_skip,
        )

        # Return non-zero if any failed
        if any(v is False for v in results.values()):
            return 1
        return 0

    except KeyboardInterrupt:
        # Ctrl+C: tear down every packer GUI we launched so none are left open,
        # then fall through to the finally below which prints the partial report.
        print("\n\n[!] Interrupted by user (Ctrl+C) — shutting down...")
        close_all_windows()
        return 130
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        return 1
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return 1
    finally:
        # Always print the aggregated report — on success, error, or Ctrl+C —
        # provided the runner got far enough to exist.
        if runner is not None:
            runner.print_final_report()


if __name__ == "__main__":
    sys.exit(main())
