import abc


class BookKeeper(object):
    """
    Abstract class that represents a book keeper that can read book-keeping data and provide the list of recently
    updated/inserted EPVs.
    """

    @abc.abstractmethod
    def get_name(self):
        return

    @abc.abstractmethod
    def get_recent_epv(self, min_finished_at):
        """Get all the EPVs that were updated/inserted after the given timestamp"""
        return
