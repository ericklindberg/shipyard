from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderContract:
    actions: frozenset[str]


PROVIDER_CONTRACTS = {
    "apple": ProviderContract(
        frozenset({"xcodecloud.build", "appstoreconnect.testflight"})
    ),
    "buzz": ProviderContract(frozenset({"buzz.workflow", "git.ref"})),
    "buzz-git": ProviderContract(frozenset({"git.ref"})),
    "digest-native": ProviderContract(frozenset({"oci.promote"})),
    "git": ProviderContract(frozenset({"git.ref"})),
    "github": ProviderContract(frozenset({"git.ref"})),
    "github-actions": ProviderContract(frozenset({"github.workflow"})),
    "heroku": ProviderContract(frozenset({"heroku.build"})),
    "kubernetes": ProviderContract(frozenset({"kubernetes.deploy"})),
    "render": ProviderContract(frozenset({"render.deploy"})),
    "vercel": ProviderContract(frozenset({"vercel.deploy"})),
}

ACTION_CONFIG_OPTIONS = {
    "appstoreconnect.testflight": frozenset(
        {
            "api_base",
            "app_id",
            "apple_observation_digest",
            "beta_group_id",
            "build_id",
            "build_number",
            "bundle_id",
            "issuer_id_env",
            "key_id_env",
            "marketing_version",
            "physical_device_attestation",
            "pre_release_version_id",
            "private_key_path_env",
            "release_project_digest",
            "token_env",
            "xcode_cloud_run_id",
        }
    ),
    "buzz.workflow": frozenset({"workflow_id"}),
    "git.ref": frozenset({"ref", "remote", "repo_path", "tag_kind"}),
    "github.workflow": frozenset(
        {
            "api_base",
            "owner",
            "ref",
            "repo",
            "repository_id",
            "token_env",
            "workflow_file",
            "workflow_id",
        }
    ),
    "heroku.build": frozenset(
        {"api_base", "app", "source_blob_url_env", "token_env"}
    ),
    "kubernetes.deploy": frozenset(
        {
            "api_base",
            "cluster_id",
            "container",
            "deployment",
            "deployment_uid",
            "image_repository",
            "manifest_digest",
            "namespace",
            "namespace_uid",
            "registry",
            "registry_token_env",
            "repository",
            "token_env",
        }
    ),
    "oci.promote": frozenset(
        {"manifest_digest", "registry", "repository", "target_tag", "token_env"}
    ),
    "render.deploy": frozenset({"api_base", "clear_cache", "service_id", "token_env"}),
    "vercel.deploy": frozenset(
        {
            "api_base",
            "git_type",
            "project",
            "repo_id",
            "target",
            "team_id",
            "token_env",
        }
    ),
    "xcodecloud.build": frozenset(
        {
            "api_base",
            "clean",
            "git_reference_id",
            "git_reference_name",
            "issuer_id_env",
            "key_id_env",
            "private_key_path_env",
            "repo_path",
            "source_remote",
            "source_observation_digest",
            "token_env",
            "workflow_id",
        }
    ),
}


def action_supported(provider: str, action: str) -> bool:
    contract = PROVIDER_CONTRACTS.get(provider)
    return contract is not None and action in contract.actions


def unsupported_action_options(action: str, options: object) -> tuple[str, ...]:
    if not isinstance(options, dict):
        return ()
    allowed = ACTION_CONFIG_OPTIONS.get(action)
    if allowed is None:
        return tuple(sorted(str(key) for key in options))
    return tuple(sorted(str(key) for key in set(options) - allowed - {"repo_path"}))


def provider_option_error(
    provider: str, action: str, options: object
) -> str | None:
    if not isinstance(options, dict):
        return None
    if (
        action == "git.ref"
        and options.get("tag_kind", "lightweight") == "annotated"
        and provider != "github"
    ):
        return "annotated git.ref is supported only by provider github"
    return None
