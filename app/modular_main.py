import sys

from PyQt6.QtWidgets import QApplication

from app.gui.main_window import MainWindow
from cases.manager import CaseManager
from config import DATABASE_PATH
from storage.database import Database


def main() -> int:
    case_manager = CaseManager(DATABASE_PATH)
    case_manager.connect()
    case_manager.create_tables()

    database = Database(DATABASE_PATH)
    database.connect()
    database.create_tables()

    app = QApplication(sys.argv)
    window = MainWindow(database, case_manager=case_manager)
    window.show()
    result = app.exec()
    database.close()
    case_manager.close()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
