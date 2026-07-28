import json
import os

def save_data(file_path, new_data):

    directory = os.path.dirname(file_path)

    if directory and not os.path.exists(directory):
        os.makedirs(directory)

    if os.path.exists(file_path):

        try:

            with open(file_path, "r") as f:
                existing_data = json.load(f)

        except json.JSONDecodeError:
            existing_data = []

    else:

        existing_data = []

    existing_data.extend(new_data)

    with open(file_path, "w") as f:

        json.dump(
            existing_data,
            f,
            indent=4,
            sort_keys=True
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
