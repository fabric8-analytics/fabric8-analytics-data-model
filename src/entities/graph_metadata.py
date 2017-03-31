from entities.entity_base import EntityBase
from entities.utils import get_values as gv
import config
import traceback
import logging

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)


class GraphMetaData(EntityBase):
    """
    This class represents meta-data associated with the whole graph.

    Variety of meta-data can be stored here. Currently, it stores the last incremental update timestamp and last
    imported EPV.

    The graph meta-data will be stored in a vertex that has 'vertex-label' = 'GraphMetaData'. As there should be
    at max only one meta-data vertex in the graph, the logic of singleton vertex is implemented in create() method.
    """

    def __init__(self, last_incr_update_ts='', last_imported_epv=''):
        super(GraphMetaData, self).__init__()
        self.last_incr_update_ts = last_incr_update_ts
        self.last_imported_epv = last_imported_epv

    @classmethod
    def load_from_file(cls, file_name):
        raise NotImplementedError()

    @classmethod
    def load_from_json(cls, input_json):
        return GraphMetaData(gv.get_last_incr_update_ts(input_json),
                             gv.get_last_imported_epv(input_json))

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
    def edge_count(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()). \
                outE().count().toList()[0]

        except Exception as e:
            logger.error("edge_count() failed: %s" % e)

    @classmethod
    def delete_all(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()).drop().toList()

        except Exception as e:
            logger.error("delete all() failed: %s" % e)
            return None

    @classmethod
    def return_entity_obj(cls, vertex_id, last_incr_update_ts, last_imported_epv):
        obj = GraphMetaData(last_incr_update_ts, last_imported_epv)
        obj.id = vertex_id
        return obj

    @classmethod
    def find_by_criteria(cls, label, criteria_dict):
        try:
            query = cls.g().V().has('vertex_label', label)
            for k, v in criteria_dict.items():
                query = query.has(k, v)
            check_meta = query.toList()
            logger.debug("query sent:------ %s" % query)
            logger.debug("query_result:----- %s" % check_meta)

            if len(check_meta) == 0:
                return None
            else:
                values = cls.g().V(check_meta[0].id).valueMap().toList()[0]
                return cls.return_entity_obj(check_meta[0].id,
                                             values.get('last_incr_update_ts')[0],
                                             values.get('last_imported_epv')[0])

        except Exception as e:
            logger.error("find_by_criteria() failed: %s" % e)
            return None

    def create(self):
        try:
            # Note: we explicitly pass empty dictionary to find_by_criteria()
            # This way, we are enforcing singleton i.e. at max only one meta-data vertex should exist
            present_metadata = GraphMetaData.find_by_criteria(self.label, {})

            if present_metadata is None:
                results = self.g().addV(self.label). \
                    property('vertex_label', self.label). \
                    property('last_incr_update_ts', self.last_incr_update_ts). \
                    property('last_imported_epv', self.last_imported_epv).\
                    toList()
                logger.debug("create() %s - results: %s" % (self.label, results))

                self.id = results[0].id
                logger.info("Vertex ID : %s, %s: %s" % (self.id, self.label, self))
                return self.id

            else:
                logger.debug("Graph MetaData exists: %s " % present_metadata.id)
                self.id = present_metadata.id
                return self.id

        except Exception as e:
            logger.error("create() failed: %s" % e)
            return None

    def update(self):
        try:
            results = self.g().V(self.id).\
                property('last_incr_update_ts', self.last_incr_update_ts). \
                property('last_imported_epv', self.last_imported_epv).\
                toList()

            logger.debug("update() %s - results: %s" % (self.label, results))
            logger.info("Vertex ID : %s, %s: %s" % (self.id, self.label, self))

            return self.id

        except Exception as e:
            logger.error("update() failed: %s" % e)
            return None

    def update_from_json(self, input_json):
        last_incr_update_ts = gv.get_last_incr_update_ts(input_json)
        last_imported_epv = gv.get_last_imported_epv(input_json)
        if last_incr_update_ts is not None:
            self.last_incr_update_ts = last_incr_update_ts
        if last_imported_epv is not None:
            self.last_imported_epv = last_imported_epv
