from data_source.book_keeper import BookKeeper
import json
from datetime import datetime


class JsonBookKeeper(BookKeeper):
    """
    A book keeper that reads book-keeping data from JSON file and provide the list of recently
    updated/inserted EPVs.

    Example JSON file:
    {
      "2017-02-08T12:26:51.962609": { "ecosystem": "npm", "name": "serve-static", "version": "1.7.1" },
      "2017-02-22T15:34:59.469864": { "ecosystem": "npm", "name": "send", "version": "0.10.1" }
    }

    NOTE: This book keeper is used mainly for implementing test cases of incremental-update functionality.
    """
    def __init__(self, json_file_name):
        self.json_file_name = json_file_name

    def get_name(self):
        return "Json Book Keeper: " + self.json_file_name

    def get_recent_epv(self, min_finished_at):
        list_epv = []
        try:
            date_time_format = "%Y-%m-%dT%H:%M:%S.%f"
            json_file = open(self.json_file_name)
            dict_ts_epv = json.load(json_file)

            min_datetime = datetime.strptime(min_finished_at, date_time_format)
            for key in dict_ts_epv.keys():
                key_datetime = datetime.strptime(key, date_time_format)
                if key_datetime > min_datetime:
                    list_epv.append(dict_ts_epv.get(key))

        except Exception as e:
            msg = "JsonBookKeeper::get_recent_epv() failed with error: %s" % e
            raise RuntimeError(msg)

        return list_epv


