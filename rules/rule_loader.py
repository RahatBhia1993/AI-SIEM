import json

def load_rules(file_path):
    with open(file_path, "r") as f:
        rule = json.load(f)

    return [rule]
