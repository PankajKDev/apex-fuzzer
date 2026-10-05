import json
import textwrap
from pathlib import Path

from main.validation.oast import InteractshProvider


def _fake_interactsh_client(path):
    path.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import signal
        import sys
        import time

        args = sys.argv[1:]
        def value(flag):
            return args[args.index(flag) + 1]
        payloads = value("-psf")
        interactions = value("-o")
        open(payloads, "w").write("faketokenabc123.oast.pro\\n")
        open(interactions, "w").close()
        signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
        while True:
            time.sleep(0.1)
    """))
    path.chmod(0o755)


def test_official_client_wrapper_registers_and_reads_jsonl(tmp_path,
                                                           monkeypatch):
    binary = tmp_path / "interactsh-client"
    _fake_interactsh_client(binary)
    monkeypatch.setattr("main.validation.oast.shutil.which",
                        lambda _name: str(binary))
    provider = InteractshProvider(timeout=2)

    assert provider.register()
    assert provider.available()
    assert provider.create_token() == "faketokenabc123.oast.pro"
    private_dir = Path(provider._client_tmp.name)

    interaction = {"protocol": "dns", "full-id":
                   "faketokenabc123nonce.oast.pro"}
    with open(provider._interaction_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(interaction) + "\n")
    assert provider.poll(timeout=0) == [interaction]
    assert provider.correlate([interaction], "faketokenabc123nonce")

    provider.close()
    assert not provider.available()
    assert provider._client_process is None
    assert not private_dir.exists()


def test_public_oast_fails_closed_without_official_client(monkeypatch):
    monkeypatch.setattr("main.validation.oast.shutil.which",
                        lambda _name: None)
    provider = InteractshProvider()
    assert not provider.register()
    assert not provider.available()


def test_official_client_retries_other_public_server(tmp_path, monkeypatch):
    binary = tmp_path / "interactsh-client"
    binary.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import signal
        import sys
        import time

        args = sys.argv[1:]
        def value(flag):
            return args[args.index(flag) + 1]
        server = value("-s")
        if server == "oast.pro":
            sys.exit(1)
        open(value("-psf"), "w").write(
            "faketokenabc123." + server + "\\n")
        open(value("-o"), "w").close()
        signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
        while True:
            time.sleep(0.1)
    """))
    binary.chmod(0o755)
    monkeypatch.setattr("main.validation.oast.shutil.which",
                        lambda _name: str(binary))
    provider = InteractshProvider(timeout=2)

    assert provider.register()
    assert provider.server == "oast.live"
    provider.close()
