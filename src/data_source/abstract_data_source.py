import abc


class AbstractDataSource(object):

    @abc.abstractmethod
    def get_source_name(self):
        return

    @abc.abstractmethod
    def list_files(self, prefix=None):
        """List all the files in the source directory"""
        return

    @abc.abstractmethod
    def read_json_file(self, filename):
        """Read JSON file from the data source"""
        return
