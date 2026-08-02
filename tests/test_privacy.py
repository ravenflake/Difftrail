import unittest

from difftrail.privacy import extract_safe_application_name, redact_text, redact_value


class PrivacyTests(unittest.TestCase):
    def test_redacts_user_profile_paths(self) -> None:
        text = r"C:\Users\testuser\AppData\Local\SomeTool\tool.exe"
        self.assertEqual(redact_text(text), r"C:\Users\<user>")

    def test_redacts_nested_values(self) -> None:
        value = {"path": r"C:\Users\testuser\Documents\notes.txt", "items": [r"C:\Users\testuser\x"]}
        redacted = redact_value(value)
        self.assertEqual(redacted["path"], r"C:\Users\<user>")
        self.assertEqual(redacted["items"][0], r"C:\Users\<user>")

    def test_extracts_only_a_safe_application_basename(self) -> None:
        message = r"Faulting application name: C:\Users\testuser\Games\Example.exe, version 1.2.3"
        self.assertEqual(extract_safe_application_name(message), "Example.exe")

    def test_extracts_hanging_program_name(self) -> None:
        message = "The program Example.exe version 1.0 stopped interacting with Windows."
        self.assertEqual(extract_safe_application_name(message), "Example.exe")
