"""NAS browsing service — reads from pre-mounted CIFS share."""

from pathlib import Path

from app.config import settings


class NASService:
    BASE_PATH: Path = Path(settings.NAS_MOUNT_PATH)

    # ---- Public API ----

    def list_project_folders(self) -> list[str]:
        """Return direct subdirectory names under BASE_PATH."""
        return [p.name for p in sorted(self.BASE_PATH.iterdir()) if p.is_dir()]

    def browse_directory(self, subpath: str = "") -> dict:
        """Browse any directory level under NAS mount.

        Returns dict with 'folders' (list[str]) and 'files' (list[dict]).
        """
        target = self._validate_path(subpath) if subpath else self.BASE_PATH.resolve()
        if not target.is_dir():
            raise FileNotFoundError(f"資料夾不存在：{subpath}")

        folders: list[str] = []
        files: list[dict] = []
        for p in sorted(target.iterdir()):
            if p.name.startswith(".") or p.name.startswith("#"):
                continue
            if p.is_dir():
                folders.append(p.name)
            elif p.suffix.lower() in (".pcap", ".pcapng"):
                files.append({"name": p.name, "size_bytes": p.stat().st_size})
        return {"folders": folders, "files": files}

    def get_pcap_files(self, project_folder: str) -> list[dict]:
        """Return list of dicts with name and size_bytes for pcap/pcapng files."""
        base = self._validate_path(project_folder)
        result = []
        for p in sorted(base.iterdir()):
            if p.suffix.lower() in (".pcap", ".pcapng"):
                result.append({"name": p.name, "size_bytes": p.stat().st_size})
        return result

    def get_pcap_paths(self, project_folder: str, filenames: list[str]) -> list[str]:
        """Return validated absolute paths for given pcap filenames."""
        base = self._validate_path(project_folder)
        paths = []
        for fn in filenames:
            fpath = (base / fn).resolve()
            if not fpath.is_relative_to(base):
                raise ValueError("偵測到路徑穿越攻擊")
            if not fpath.exists():
                raise FileNotFoundError(f"檔案不存在：{fn}")
            paths.append(str(fpath))
        return paths

    # ---- Internal ----

    def _validate_path(self, rel_path: str) -> Path:
        """Validate a relative path under NAS mount. Supports multi-level and Unicode names."""
        if ".." in rel_path.split("/"):
            raise ValueError("偵測到路徑穿越攻擊")
        resolved = (self.BASE_PATH / rel_path).resolve()
        if not resolved.is_relative_to(self.BASE_PATH.resolve()):
            raise ValueError("偵測到路徑穿越攻擊")
        return resolved


nas_service = NASService()
