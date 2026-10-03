from apex_fuzzer.discovery.classifier import classify


def test_api():
    assert classify("/api/v1/users") == "api"


def test_graphql():
    assert classify("/graphql") == "graphql"


def test_admin():
    assert classify("/admin/panel") == "admin"


def test_auth():
    assert classify("/login") == "authentication"


def test_static():
    assert classify("/assets/app.css") == "static"


def test_page():
    assert classify("/about") == "page"
