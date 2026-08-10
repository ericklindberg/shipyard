from shipyard.redact import redact, redact_argv


def test_redacts_common_secret_shapes_without_hiding_normal_output():
    text = "token=super-secret Bearer abc.def.ghi password: hunter2 release=ok"

    result = redact(text)

    assert "super-secret" not in result
    assert "abc.def.ghi" not in result
    assert "hunter2" not in result
    assert result.endswith("release=ok")
    assert result.count("[REDACTED]") == 3


def test_redacts_credentials_embedded_in_urls():
    credential_url = "https://user:" + "private-token" + "@example.test/repo.git"
    result = redact(f"remote={credential_url}")

    assert "private-token" not in result
    assert result == "remote=https://[REDACTED]@example.test/repo.git"


def test_redacts_provider_tokens_signed_urls_and_private_keys():
    github_token = "ghp_" + "a" * 36
    openai_token = "sk-proj-" + "b" * 32
    aws_key = "AKIA" + "C" * 16
    private_key = (
        "-----BEGIN " + "PRIVATE KEY-----\nmaterial\n-----END " + "PRIVATE KEY-----"
    )
    text = (
        f"{github_token} {openai_token} {aws_key} "
        "https://example.test/file?X-Amz-Signature=signed-value "
        f"{private_key}"
    )

    result = redact(text)

    for secret in (github_token, openai_token, aws_key, "signed-value", "material"):
        assert secret not in result


def test_redacts_json_quoted_values_and_credential_headers():
    text = (
        '{"token":"json-secret","client_secret":"client-value"}\n'
        "password='quoted-secret'\n"
        "Authorization: Basic basic-secret\n"
        "X-Api-Key: header-secret\n"
        "Set-Cookie: session=session-secret; HttpOnly\n"
    )

    result = redact(text)

    for secret in (
        "json-secret",
        "client-value",
        "quoted-secret",
        "basic-secret",
        "header-secret",
        "session-secret",
    ):
        assert secret not in result
    assert result.count("[REDACTED]") >= 6


def test_redacts_secret_command_arguments():
    result = redact_argv(("deploy", "--token", "private-token", "--api-key=value", "production"))

    assert result == (
        "deploy",
        "--token",
        "[REDACTED]",
        "--api-key=[REDACTED]",
        "production",
    )
