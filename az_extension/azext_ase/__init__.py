from azure.cli.core import AzCommandsLoader
from azure.cli.core.commands import CliCommandType

from ._help import helps  # pylint: disable=unused-import


class AseCommandsLoader(AzCommandsLoader):
    def __init__(self, cli_ctx=None):
        super().__init__(cli_ctx=cli_ctx)

    def load_command_table(self, args):
        custom = CliCommandType(operations_tmpl="azext_ase.custom#{}")
        with self.command_group("ase", custom) as group:
            group.command("diff", "run_diff")
            group.command("deploy", "run_deploy")
        with self.command_group("ase incident", custom) as group:
            group.command("list", "list_incidents")
            group.command("show", "show_incident")
        with self.command_group("ase block", custom) as group:
            group.command("list", "list_blocks")
        return self.command_table

    def load_arguments(self, command):
        for scope in ("ase diff", "ase deploy"):
            with self.argument_context(scope) as context:
                context.argument("profile", default="poc")
                context.argument("subscription_id")
                context.argument("resource_group", default="rg-ase-sentinel-poc")
                context.argument("location", default="eastus")
                context.argument("name_prefix", default="ase-sentinel-poc")
                context.argument("existing_waf_policy_name")
                context.argument("deploy_test_waf", action="store_true")
        with self.argument_context("ase deploy") as context:
            context.argument("apply", action="store_true")
        for scope in ("ase incident", "ase block"):
            with self.argument_context(scope) as context:
                context.argument(
                    "subscription_id",
                    required=True,
                    help="Subscription GUID. Reads use this value and do not follow the Azure CLI default.",
                )
                context.argument("resource_group", required=True, help="Resource group that contains the workspace and the WAF policy.")
                context.argument("workspace_name", required=True, help="Log Analytics workspace name that hosts Microsoft Sentinel.")
                context.argument(
                    "waf_policy_resource_id",
                    required=True,
                    help="Full ARM id of the one Application Gateway WAF policy to read.",
                )
                context.argument(
                    "python_path",
                    help="Python executable that can import this repo. The default is webapp/.venv.",
                )
        with self.argument_context("ase incident show") as context:
            context.argument("incident_id", required=True, help="Incident GUID.")


COMMAND_LOADER_CLS = AseCommandsLoader
