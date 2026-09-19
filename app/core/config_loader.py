import yaml


def load_config(config_path="config.yaml"):
    """
    Load the RDRS configuration from YAML file.
    """

    with open(config_path, "r") as file:
        return yaml.safe_load(file)