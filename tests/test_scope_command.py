from main.shell import run


def test_rejects_string_command():
    try:
        run("ls -la")
    except TypeError:
        return
    raise AssertionError("shell.run must reject string commands")
