import os

from apex_fuzzer.cli import load_dotenv


def test_load_dotenv_parses_and_respects_env(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text(
        "# comment\n"
        "\n"
        "APEX_TEST_A=hello\n"
        "APEX_TEST_B='quoted value'\n"
        'APEX_TEST_C="double"\n'
        "BAD LINE WITHOUT EQUALS\n"
        "123BAD=no\n"
        "APEX_TEST_D=\n"
    )
    for k in ("APEX_TEST_A", "APEX_TEST_B", "APEX_TEST_C",
              "APEX_TEST_D"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("APEX_TEST_A", "keep")
    n = load_dotenv(f)
    assert n == 3  # A kept (not counted), B/C/D set
    assert os.environ["APEX_TEST_A"] == "keep"
    assert os.environ["APEX_TEST_B"] == "quoted value"
    assert os.environ["APEX_TEST_C"] == "double"
    assert os.environ["APEX_TEST_D"] == ""


def test_load_dotenv_missing_file(tmp_path):
    assert load_dotenv(tmp_path / "nope.env") == 0


def test_env_example_documents_used_vars():
    example = open(".env.example").read()
    for var in ("GEMINI_API_KEY", "GITHUB_TOKEN", "HEROKU_USERNAME",
                "HEROKU_API_KEY", "HEROKU_APP_NAME"):
        assert var in example
