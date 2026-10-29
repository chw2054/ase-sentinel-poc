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
        return self.command_table

    def load_arguments(self, command):
        with self.argument_context("ase") as context:
            context.argument("profile", default="poc")
            context.argument("subscription_id")
            context.argument("resource_group", default="rg-ase-sentinel-poc")
            context.argument("location", default="eastus")
            context.argument("name_prefix", default="ase-sentinel-poc")
            context.argument("existing_waf_policy_name")
            context.argument("deploy_test_waf", action="store_true")
        with self.argument_context("ase deploy") as context:
            context.argument("apply", action="store_true")


COMMAND_LOADER_CLS = AseCommandsLoader
