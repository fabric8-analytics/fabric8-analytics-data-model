import json
from graph_manager import BayesianGraph
import logging
from entities.utils import get_values as gv

logger = logging.getLogger(__name__)
check_set = set(['CodeMetricsLanguage', 'GraphMetaData'])


def default_json_decoder(self):
    if isinstance(self, set):
        return list(self)
    return self.__dict__

#TODO: Code refactor to PEP8
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

    def save(self, criteria_dict=None):
        if self.__class__.__name__ in check_set:
            if self.id is None:
                return self.create()
            return self.update()
        
        present_node = self.__class__.find_by_criteria(
                self.label, criteria_dict)
        if present_node is None:
            return self.create()
        self.id = present_node.id
        return self.update()

    def create(self):
        raise NotImplementedError()

    def update(self):
        raise NotImplementedError()

    @classmethod
    def delete_all(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()).drop().toList()

        except Exception as e:
            logger.error("delete all() failed: %s" % e)
            return None

    @classmethod
    def find_all(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()).toList()

        except Exception as e:
            logger.error("find_all() failed: %s" % e)
            return None

    @classmethod
    def count(cls):
        try:
            return len(cls.find_all())

        except Exception as e:
            logger.error("count() failed: %s" % e)
            return None

    @classmethod
    def find_by_criteria(cls, label, criteria_dict):
        try:
            query = cls.g().V().has('vertex_label', label)
            for k, v in criteria_dict.items():
                query = query.has(k, v)
            check_pck = query.toList()
            logger.debug("query sent:------ %s" % query)
            logger.debug("query_result:----- %s" % check_pck)

            if len(check_pck) == 0:
                return None
            values = cls.g().V(check_pck[0].id).valueMap().toList()[0]
            values['id'] = check_pck[0].id
            return values
    
        except Exception as e:
            logger.error("find_by_criteria() failed: %s" % e)
            return None

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

    @classmethod
    def load_from_file(cls, file_name):
        input_json = gv.read_from_file(file_name)
        return cls.load_from_json(input_json)         