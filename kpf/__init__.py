import click
import google.auth


def get_project_id() -> str:  # type: ignore
    _, project_id = google.auth.default()
    if not project_id:
        click.echo(
            """Unable to determine the project ID. Please ensure you have
            configured your GCP project correctly.""",
            err=True,
        )
        click.exceptions.Exit(1)
    else:
        return project_id
