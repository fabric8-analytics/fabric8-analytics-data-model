from abstract_data_source import AbstractDataSource
import os, fnmatch
import json


class LocalFileSystem(AbstractDataSource):

    def __init__(self, src_dir):
        self.src_dir = src_dir
        # ensure path ends with a forward slash
        self.src_dir = self.src_dir if self.src_dir.endswith("/") else self.src_dir + "/"

    def get_source_name(self):
        return "Local filesytem dir: " + self.src_dir

    def list_files(self, prefix=None):
        """List all the files in the source directory"""
        list_filenames = []
        for root, dirs, files in os.walk(self.src_dir):
            for basename in files:
                if fnmatch.fnmatch(basename, "*.json"):
                    filename = os.path.join(root, basename)
                    if prefix is None:
                        filename = filename[len(self.src_dir):]
                        list_filenames.append(filename)
                    elif filename.startswith(os.path.join(self.src_dir, prefix)):
                        filename = filename[len(self.src_dir):]
                        list_filenames.append(filename)
        list_filenames.sort()
        return list_filenames

    def read_json_file(self, filename):
        """Read JSON file from the data source"""
        return json.load(open(os.path.join(self.src_dir, filename)))
