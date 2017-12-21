"""This module has been commented out from the beginning."""

# TODO: create an issue whether this script should be deleted or reincarnated again

# from graph_manager import BayesianGraph
# import config
#
# from f8a_worker.models import Analysis, Ecosystem, Version, Package
# from sqlalchemy import create_engine
# from sqlalchemy.orm import sessionmaker
# from sqlalchemy.orm.exc import NoResultFound
#
# # TODO: Datetime is timezone naive
# from datetime import datetime
#
# from graph_populator import GraphPopulator
# import logging
#
#
# class PostgresGraphSync(object):
#     def __init__(self):
#         engine = create_engine(config.POSTGRES_SERVER)
#         session = sessionmaker(bind=engine)
#         self.rdb = session()
#         self.graph_db = BayesianGraph.instance()
#         logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
#         self.logger = logging.getLogger(__name__)
#
#     def obtain_last_sync_time(self):
#         """
#         Tries to look up for sync vertex if there is none, returns linux epoch datetime
#         :return: datetime object of last performed and synced analysis
#         """
#         result = self.graph_db.V().hasLabel("last_sync").valueMap().toList()
#         if len(result) == 0:
#             self.logger.info("No sync vertex found, syncing all")
#             # sync has never been performed before
#             return datetime.utcfromtimestamp(0)
#
#         self.logger.info("Last sync vertex found, last sync performed : %s" %
#                          result[0]['last_time_performed'])
#         # we have to convert string back to datetime object
#         return datetime.strptime(result[0]['last_analysis_performed'], '%Y-%m-%d %H:%M:%S.%f')
#
#     def update_last_sync_time(self, last_analysis_time):
#         """
#         This method updates last_analysis_time and last_performed time
#         :param last_analysis_time: time of the last analysis
#         :return: Nothing
#         """
#         result = self.graph_db.V().hasLabel('last_sync').toList()
#         if len(result) > 1:
#             raise ValueError("There is more then 1 sync vertexes")
#
#         if len(result) == 0:
#             result = self.graph_db.addV('last_sync'). \
#                 property('last_analysis_performed', str(last_analysis_time)). \
#                 property('last_time_performed', str(datetime.now())).toList()
#         else:
#             result = self.graph_db.V(result[0].id). \
#                 property('last_analysis_performed', str(last_analysis_time)). \
#                 property('last_time_performed', str(datetime.now())).toList()
#         self.logger.info("Vertex with ID %s has been updated or created" % result[0].id)
#
#     def do_synchronization(self):
#         last_time = self.obtain_last_sync_time()
#         populator = GraphPopulator()
#         try:
#             query = self.rdb.query(Analysis).join(Version).join(Package). \
#                 join(Ecosystem).order_by(Analysis.finished_at.asc()).filter(
#                     Analysis.finished_at >= last_time)
#             item = None
#             for item in query:
#                 d = item.to_dict()
#                 d['started_at'] = str(d['started_at'])
#                 d['finished_at'] = str(d['finished_at'])
#                 populator.populate_from_json(d)
#             else:
#                 self.update_last_sync_time(item.to_dict().finished_at)
#         except NoResultFound:
#             self.logger("No new analyses found")
#
#
# def main():
#     PostgresGraphSync().do_synchronization()
#
#
# if __name__ == '__main__':
#     main()
