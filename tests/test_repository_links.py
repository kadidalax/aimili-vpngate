import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RepositoryLinkTests(unittest.TestCase):
    def test_readme_uses_owner_install_commands_without_ads(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        owner = "https://raw.githubusercontent.com/kadidalax/aimili-vpngate/main/"
        self.assertIn(f"bash <(curl -Ls {owner}install.sh)", readme)
        self.assertIn(f"bash <(curl -Ls {owner}jkw.sh)", readme)
        for removed in (
            "baoweise-bot",
            "BandwagonHost",
            "RackNerd",
            "aff.php",
            "t.me/arestemple",
            "339936.xyz",
            "yaohunse7@gmail.com",
            "Donation Support",
            "捐赠支持",
        ):
            self.assertNotIn(removed, readme)

    def test_installer_defaults_to_owner_repository(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn('DEFAULT_USER="kadidalax"', installer)
        self.assertNotIn('DEFAULT_USER="baoweise-bot"', installer)

    def test_web_ui_uses_owner_repository_without_ads(self):
        manager = (ROOT / "vpngate_manager.py").read_text(encoding="utf-8")
        self.assertIn("https://github.com/kadidalax/aimili-vpngate", manager)
        for removed in (
            "baoweise-bot",
            "BandwagonHost",
            "RackNerd",
            "aff.php",
            "t.me/arestemple",
            "339936.xyz",
            "VPS购买推荐",
            "捐赠支持",
        ):
            self.assertNotIn(removed, manager)


if __name__ == "__main__":
    unittest.main()
