from pathlib import Path
import sys
import yaml


class ConfigLoader:
    @staticmethod
    def get_program_name() -> str:
        """Get the program name without extension."""
        program_path = sys.argv[0]
        return Path(program_path).stem

    @staticmethod
    def get_config_path() -> Path:
        """Get the configuration file path."""
        program_name = ConfigLoader.get_program_name()
        config_filename = f".{program_name}.yaml"
        return Path.cwd() / config_filename

    @classmethod
    def verify_config(cls, config):
        if not config:
            raise ValueError(f"Configuration is None or empty")

        return True

    @classmethod
    def load_config(cls):
        """Load the YAML configuration file."""
        config_path = cls.get_config_path()

        if not config_path.exists():
            raise FileNotFoundError(
                f"Configuration file '{config_path}' not found in the current directory"
            )

        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)

                ConfigLoader.verify_config(config)

                return config

        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML configuration: {str(e)}")
