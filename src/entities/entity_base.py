import json
from graph_manager import BayesianGraph
import config
import logging

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)


def default_json_decoder(self):
    if isinstance(self, set):
        return list(self)
    return self.__dict__


class EntityBase(object):
    label = None

    def __init__(self):
        self.id = None
        self.label = self.__class__._get_label()

    @classmethod
    def _get_label(cls):
        if cls.label is None:
            return cls.__name__
        else:
            return cls.label

    @classmethod
    def g(self):
        return BayesianGraph.instance()

    def to_json(self):
        return json.dumps(self, default=default_json_decoder)

    def get_id(self):
        return self.id

    def save(self):
        if self.id is None:
            return self.create()
        else:
            return self.update()

    def create(self):
        raise NotImplementedError()

    def update(self):
        raise NotImplementedError()

    def delete(self):
        self.delete()

    @classmethod
    def delete_all(cls):
        raise NotImplementedError()

    @classmethod
    def find_all(self):
        raise NotImplementedError()

    @classmethod
    def count(self):
        raise NotImplementedError()

    @classmethod
    def find_by_criteria(self, label, criteria_dict):
        raise NotImplementedError()

    @classmethod
    def return_entity_obj(self):
        raise NotImplementedError

    @classmethod
    def edge_exists(cls):
        raise NotImplementedError

    @classmethod
    def edge_count(self):
        raise NotImplementedError

    @classmethod
    def delete_by_id(self,obj_id):
        try:
            if obj_id is not None:
                return  self.g().V(obj_id).drop().toList()

        except Exception as e:
            logger.error("delete() failed: %s" % e)
            return None
