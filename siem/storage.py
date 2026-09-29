import json
import os
from datetime import datetime


def _json_serializer(obj):
    """
    Convert objects that JSON cannot normally serialize
    into JSON-compatible values.
    """

    if isinstance(obj, datetime):
        return obj.isoformat()

    raise TypeError(
        f"Object of type {type(obj).__name__} "
        "is not JSON serializable"
    )


def save_data(file_path, new_data):
    """
    Append new data to an existing JSON file.

    Datetime objects are automatically converted to
    ISO-8601 strings.
    """

    directory = os.path.dirname(file_path)

    if directory and not os.path.exists(directory):
        os.makedirs(directory)

    # Load existing data
    if os.path.exists(file_path):

        try:

            with open(file_path, "r") as f:
                existing_data = json.load(f)

        except (json.JSONDecodeError, FileNotFoundError):

            existing_data = []

    else:

        existing_data = []

    # Make sure we are working with a list
    if not isinstance(existing_data, list):
        existing_data = []

    if isinstance(new_data, list):
        existing_data.extend(new_data)

    else:
        existing_data.append(new_data)

    # Save JSON
    with open(file_path, "w") as f:

        json.dump(
            existing_data,
            f,
            indent=4,
            sort_keys=True,
            default=_json_serializer
        )


def save_alerts(alerts):

    save_data(
        "storage/alerts.json",
        alerts
    )


def save_incidents(incidents):

    save_data(
        "storage/incidents.json",
        incidents
    )


def save_entities(entities):

    save_data(
        "storage/entities.json",
        entities
    )
