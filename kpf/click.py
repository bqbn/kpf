from .config import ConfigLoader
from .file_utils import EncryptedFile
import click


# Custom Command class to allow dynamic options at the time of command definition
class DynamicOptionsCommand(click.Command):
    def __init__(self, name=None, dynamic_options_list_name=None, **attrs):
        if not dynamic_options_list_name:
            raise click.Abort(
                ValueError(
                    f"Invalid dynamic_options_list_name: `{dynamic_options_list_name}'."
                )
            )

        self.dynamic_options_list_name = dynamic_options_list_name
        super().__init__(name, **attrs)

    def get_params(self, ctx):
        # Get default params
        params = super().get_params(ctx)

        options = ctx.obj.get(self.dynamic_options_list_name, [])
        # Add dynamic options to the command parameters
        params.extend(options)

        return params


class MutuallyExclusiveOption(click.Option):
    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop("mutually_exclusive", []))
        help_text = kwargs.get("help", "")
        if self.mutually_exclusive:
            ex_str = ", ".join(self.mutually_exclusive)
            kwargs["help"] = (
                f"{help_text} NOTE: This option is mutually exclusive with: [{ex_str}]."
            )
        super().__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        if self.mutually_exclusive.intersection(opts) and self.name in opts:
            raise click.UsageError(
                f"Illegal usage: `{self.name}` cannot be used with "
                f"`{', '.join(self.mutually_exclusive)}`."
            )
        return super().handle_parse_result(ctx, opts, args)


@click.command(
    help="""
    Encrypt/decrypt files using KMS. By default, the script encrypts the specified
    file unless the "--decrypt" or "-d" option is used. Results are written to
    standard output by default.
"""
)
@click.argument("file_path", type=click.Path(dir_okay=False))
@click.option(
    "-d",
    "--decrypt",
    is_flag=True,
    default=False,
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["encrypt"],
    help="Decrypt the file.",
)
@click.option(
    "-e",
    "--encrypt",
    is_flag=True,
    default=False,
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["decrypt"],
    help="Encrypt the file.",
)
@click.option(
    "--update",
    is_flag=True,
    default=False,
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["decrypt", "encrypt", "validate"],
    help="Update remote secrets.",
)
@click.option(
    "--validate",
    is_flag=True,
    default=False,
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["decrypt", "encrypt"],
    help="Decrypt and validate a file.",
)
@click.pass_context
def cli(ctx, file_path, decrypt, encrypt, update, validate):
    ctx.ensure_object(dict)

    config = ConfigLoader.load_config()

    file = EncryptedFile(file_path)

    if decrypt:
        print(file.decrypt().decode(), end="")
    elif encrypt:
        file.add_encryptors(config.get("master_keys"))
        print(file.encrypt_file(file_path).decode(), end="")
    elif validate:
        if file.is_valid():
            print(f"File {file} is valid.")
        else:
            raise click.ClickException(f"File {file} is invalid.")
    elif update:
        file.update_secret()
    else:
        file.add_encryptors(config.get("master_keys"))
        file.edit()
