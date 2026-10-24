import os

import pytest

from winsentinel import emailer, paths

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class FakeKeyring:
    def __init__(self):
        self.store = {}

    def get_password(self, service, user):
        return self.store.get((service, user))

    def set_password(self, service, user, password):
        self.store[(service, user)] = password

    def delete_password(self, service, user):
        self.store.pop((service, user), None)


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    """Every test gets its own data folder and an in-memory credential store."""
    folder = tmp_path / "home"
    paths.set_home(folder)
    keyring = FakeKeyring()
    monkeypatch.setattr(emailer, "_keyring", lambda: keyring)
    yield folder
    paths.set_home(None)


@pytest.fixture
def qapp():
    widgets = pytest.importorskip("PySide6.QtWidgets")
    return widgets.QApplication.instance() or widgets.QApplication([])
