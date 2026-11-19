import unittest
from unittest.mock import patch

from utils.validators import ValidationError, validate_repository_url


class RepositoryUrlValidationTests(unittest.TestCase):
    def validate_without_dns(self, value):
        with patch("utils.validators.validate_outbound_host"):
            return validate_repository_url(value)

    def test_github_shorthand_is_normalized(self):
        result = self.validate_without_dns("  octo-org/model.v2  ")
        self.assertEqual(result["platform"], "github")
        self.assertEqual(result["repo_id"], "octo-org/model.v2")
        self.assertEqual(result["normalized_url"], "https://github.com/octo-org/model.v2")

    def test_github_git_suffix_and_web_path_are_normalized(self):
        result = self.validate_without_dns("https://www.github.com/owner/repo.git/tree/main")
        self.assertEqual(result["normalized_url"], "https://github.com/owner/repo")

    def test_hugging_face_short_identifiers_are_supported(self):
        top_level = self.validate_without_dns("gpt2")
        namespaced = self.validate_without_dns("hf:org/model")
        self.assertEqual(top_level["repo_id"], "gpt2")
        self.assertEqual(namespaced["repo_id"], "org/model")
        self.assertEqual(namespaced["normalized_url"], "https://huggingface.co/org/model")

    def test_hugging_face_dataset_url_preserves_type(self):
        result = self.validate_without_dns("https://huggingface.co/datasets/org/data")
        self.assertEqual(result["repo_type"], "dataset")
        self.assertEqual(result["normalized_url"], "https://huggingface.co/datasets/org/data")

    def test_invalid_inputs_have_actionable_errors(self):
        for value in (
            "",
            "http://github.com/owner/repo",
            "https://github.com:invalid/owner/repo",
            "owner/../repo",
            "https://example.com/a/b",
        ):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.validate_without_dns(value)


if __name__ == "__main__":
    unittest.main()
