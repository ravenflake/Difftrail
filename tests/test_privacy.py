import unittest

from difftrail.privacy import extract_safe_application_name, redact_legacy_text, redact_text, redact_value


class PrivacyTests(unittest.TestCase):
    def test_redacts_user_profile_paths(self) -> None:
        text = r"C:\Users\testuser\AppData\Local\SomeTool\tool.exe"
        self.assertEqual(redact_text(text), r"C:\Users\<user>")

    def test_redacts_profile_paths_with_spaces(self) -> None:
        text = r"The program C:\Users\Jane Doe\Games\Example Game.exe version 1.0 stopped interacting with Windows."
        self.assertEqual(
            redact_text(text),
            r"The program C:\Users\<user> version 1.0 stopped interacting with Windows.",
        )

    def test_repairs_v013_partially_redacted_profile_paths(self) -> None:
        cases = {
            r"C:\Users\<user> Doe\Games\Example Game.exe": r"C:\Users\<user>",
            r"C:\Documents and Settings\<user> Doe\Games\Example Game.exe": (
                r"C:\Documents and Settings\<user>"
            ),
            r"\\<machine>\Users\<user> Doe\Games\Example Game.exe": r"\\<machine>\Users\<user>",
        }

        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(redact_legacy_text(text), expected)

    def test_current_redaction_keeps_context_after_a_safe_path_marker(self) -> None:
        text = r"The program C:\Users\<user> version 1.0 stopped interacting."
        self.assertEqual(redact_text(text), text)

    def test_redacts_non_executable_profile_paths_with_spaces(self) -> None:
        cases = {
            r"Opened C:\Users\Jane Doe\Documents\My Report.docx": r"Opened C:\Users\<user>",
            r"Opened C:\Documents and Settings\Jane Doe\My Documents\My Report.docx": (
                r"Opened C:\Documents and Settings\<user>"
            ),
            r"Opened \\Workstation\Users\Jane Doe\Documents\My Report.docx": (
                r"Opened \\<machine>\Users\<user>"
            ),
            r'Could not access "C:\Users\Jane Doe\Documents\My Report.docx".': (
                r'Could not access "C:\Users\<user>".'
            ),
            r"Path=C:\Users\Jane Doe\Downloads\report 2026.pdf; status=denied": r"Path=C:\Users\<user>",
        }

        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(redact_text(text), expected)

    def test_redacts_spaced_profile_paths_with_event_log_punctuation(self) -> None:
        cases = {
            r'The program "C:\Users\Jane Doe\Games\Example Game.exe" version 1.0 stopped interacting.': (
                r'The program "C:\Users\<user>" version 1.0 stopped interacting.'
            ),
            r"The program C:\Users\Jane Doe\Games\Example Game.exe. version 1.0 stopped interacting.": (
                r"The program C:\Users\<user>. version 1.0 stopped interacting."
            ),
            r"The program C:\Users\Jane Doe\Games\Example Game.exe! version 1.0 stopped interacting.": (
                r"The program C:\Users\<user>! version 1.0 stopped interacting."
            ),
        }

        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(redact_text(text), expected)

    def test_redacts_spaced_profile_paths_for_supported_event_log_delimiters(self) -> None:
        for delimiter in ['"', "'", ".", "!", "?", ")", "]", "}", ",", ";", ":"]:
            with self.subTest(delimiter=delimiter):
                text = rf"The program C:\Users\Jane Doe\Games\Example Game.exe{delimiter} version 1.0 stopped interacting."
                redacted = redact_text(text)
                self.assertNotIn("Jane Doe", redacted)
                self.assertNotIn("Example Game.exe", redacted)

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

    def test_extracts_hanging_program_name_from_spaced_profile_path(self) -> None:
        message = r"The program C:\Users\Jane Doe\Games\Example Game.exe version 1.0 stopped interacting with Windows."
        self.assertEqual(extract_safe_application_name(message), "Example Game.exe")

    def test_extracts_hanging_program_name_with_version_in_filename(self) -> None:
        message = r"The program C:\Users\Jane Doe\Games\My version.exe version 1.0 stopped interacting with Windows."
        self.assertEqual(extract_safe_application_name(message), "My version.exe")

    def test_strips_event_log_punctuation_from_hanging_program_name(self) -> None:
        message = r'The program "C:\Users\Jane Doe\Games\Example Game.exe" version 1.0 stopped interacting with Windows.'
        self.assertEqual(extract_safe_application_name(message), "Example Game.exe")
