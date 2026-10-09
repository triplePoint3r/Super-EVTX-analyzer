from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------
# Files that are generated and safe to remove
# --------------------------------------------------

FILE_PATTERNS = [
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    "*.log",
    "*.tmp",
    "*.bak",
    "*.pdf",
    "*.evtx"
]


# --------------------------------------------------
# Directories that contain generated files
# --------------------------------------------------

GENERATED_DIRS = [
    "__pycache__",
    ".pytest_cache",
    ".coverage",
    "htmlcov",
]


# --------------------------------------------------
# Generated report directory
# --------------------------------------------------

REPORT_DIRS = [
    ROOT / "data" / "reports",
]


def delete_files():
    for pattern in FILE_PATTERNS:
        for path in ROOT.rglob(pattern):

            # Never touch .git
            if ".git" in path.parts:
                continue

            if path.is_file():
                try:
                    path.unlink()
                    print(f"[DELETE] {path.relative_to(ROOT)}")
                except Exception as e:
                    print(f"[ERROR] {path}: {e}")


def delete_generated_dirs():
    for name in GENERATED_DIRS:
        for path in ROOT.rglob(name):

            if ".git" in path.parts:
                continue

            if path.is_dir():
                try:
                    shutil.rmtree(path)
                    print(f"[DELETE DIR] {path.relative_to(ROOT)}")
                except Exception as e:
                    print(f"[ERROR] {path}: {e}")


def clean_reports():
    for directory in REPORT_DIRS:

        if not directory.exists():
            continue

        for path in directory.iterdir():

            if path.is_file():
                try:
                    path.unlink()
                    print(f"[DELETE REPORT] {path.relative_to(ROOT)}")
                except Exception as e:
                    print(f"[ERROR] {path}: {e}")


def main():
    print("=" * 60)
    print("Cleaning project")
    print("=" * 60)

    delete_files()
    delete_generated_dirs()
    clean_reports()

    print("=" * 60)
    print("Cleaning completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()