import json
import os.path
import sys


class Credentials:
    _instance = None

    def __new__(cls, json_file="creds.json"):
        if cls._instance is None:
            cls._instance = super(Credentials, cls).__new__(cls)
            cls._instance._data = cls._instance._load_json(json_file)
        return cls._instance

    def _load_json(self, json_file):
        try:
            file_path = os.path.join(os.path.dirname(__file__), json_file)
            with open(file_path, "r") as f:
                return json.load(f)
        except Exception as e:
            sys.exit(f"File with credentials was not loaded. Exit status: 1.\n{e}")

    def get(self, key):
        return self._data.get(key)
