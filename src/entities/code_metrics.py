from entities.entity_base import EntityBase
import logging
import config
import time

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)


# TODO: Handle 1-language-multipe-modules
# class CRModules:
#     pass
#     def __init__(self):


class CodeMetricsLanguage(EntityBase):
    label = "LanguageCodeMetrics"

    def __init__(self,
                 package_version=None,
                 blank_lines=None, code_lines=None, comment_lines=None,
                 files_count=None, language=None, average_cyclomatic_complexity=None,
                 average_function_lines_of_code=None, average_function_parameters_count=None,
                 average_halstead_effort=None, cost_change=None, first_order_density=None):
        super(CodeMetricsLanguage, self).__init__()

        self.package_version = package_version

        # basic metrics
        self.blank_lines = blank_lines or -1 # jsl.NumberField(required=True)
        self.code_lines = code_lines or -1  # jsl.NumberField(required=True)
        self.comment_lines = comment_lines or -1  # jsl.NumberField(required=True)
        self.files_count = files_count or -1  # jsl.NumberField(required=True)
        self.language = language or -1  # jsl.StringField(required=True)

        # Might be language-specific once we add support for new languages, leave it generic for now
        # self.metrics = metrics  # jsl.DictField(required=False, additional_properties=True)

        self.average_cyclomatic_complexity = average_cyclomatic_complexity or -1
        self.average_function_lines_of_code = average_function_lines_of_code or -1
        self.average_function_parameters_count = average_function_parameters_count or -1
        self.average_halstead_effort = average_halstead_effort or -1
        self.cost_change = cost_change or -1
        self.first_order_density = first_order_density or -1
        self.last_updated= None

    def create(self):
        try:
            ts = time.time()
            results = self.g().addV(self.label). \
                property('vertex_label', self.label). \
                property('blank_lines', self.blank_lines). \
                property('code_lines', self.code_lines). \
                property('comment_lines', self.comment_lines). \
                property('files_count', self.files_count). \
                property('language', self.language). \
                property('average_cyclomatic_complexity', self.average_cyclomatic_complexity). \
                property('average_function_lines_of_code', self.average_function_lines_of_code). \
                property('average_function_parameters_count', self.average_function_parameters_count). \
                property('average_halstead_effort', self.average_halstead_effort). \
                property('cost_change', self.cost_change). \
                property('first_order_density', self.first_order_density). \
                property('last_updated', ts).\
                toList()

            logger.debug("create() CodeMetricsLanguage - results: %s" % results)

            self.last_updated = ts
            self.id = results[0].id
            logger.info("Vertex ID : %s, CodeMetricsLanguage: %s" % (self.id, self))

            return self.id

        except Exception as e:
            logger.error("update() failed: %s" % e)
            return None

    def update(self):
        try:
            ts = time.time()
            results = self.g().V(self.id). \
                property('vertex_label', self.label). \
                property('blank_lines', self.blank_lines). \
                property('code_lines', self.code_lines). \
                property('comment_lines', self.comment_lines). \
                property('files_count', self.files_count). \
                property('language', self.language). \
                property('average_cyclomatic_complexity', self.average_cyclomatic_complexity). \
                property('average_function_lines_of_code', self.average_function_lines_of_code). \
                property('average_function_parameters_count', self.average_function_parameters_count). \
                property('average_halstead_effort', self.average_halstead_effort). \
                property('cost_change', self.cost_change). \
                property('first_order_density', self.first_order_density). \
                property('last_updated', ts).\
                toList()

            self.last_updated = ts
            logger.debug("update() CodeMetricsLanguage - results: %s" % results)
            logger.info("Vertex ID : %s, CodeMetricsLanguage: %s" % (self.id, self))
            return self.id

        except Exception as e:
            logger.error("update() failed: %s" % e)
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
    def delete_all(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()).drop().toList()

        except Exception as e:
            logger.error("delete all() failed: %s" % e)
            return None


class CodeMetricsDetails:
    def __init__(self, languages=[]):
        self.languages = languages  # jsl.ArrayField(jsl.DocumentField(CodeMetricsLanguage, as_ref=True), required=True)
        self.last_updated = None

class CodeMetricsSummary:
    def __init__(self, blank_lines=None, code_lines=None, comment_lines=None,
                 total_files=None, total_lines=None):
        self.blank_lines = blank_lines  # jsl.NumberField(required=True)
        self.code_lines = code_lines  # jsl.NumberField(required=True)
        self.comment_lines = comment_lines  # jsl.NumberField(required=True)
        self.total_files = total_files  # jsl.NumberField(required=True)
        self.total_lines = total_lines  # jsl.NumberField(required=True)
        self.last_updated = None

class CodeMetricsResult(EntityBase):
    label = "CodeMetrics"

    def __init__(self, package_version, status=None, details=None, summary=None):
        super(CodeMetricsResult, self).__init__()
        self.package_version = package_version
        self.status = status  # jsl.StringField(enum=["success", "error"], required=True)
        self.summary = summary  # jsl.DocumentField(CodeMetricsSummary, as_ref=True, required=True)
        self.details = details  # jsl.DocumentField(CodeMetricsDetails, as_ref=True, required=True)
        self.last_updated = None

    @classmethod
    def load_from_json(cls, code_metrics_data):
        status = code_metrics_data["status"]
        code_metrics_result = None
        if status == "success":
            summary_data = code_metrics_data["summary"]
            blank_lines = summary_data.get("blank_lines")
            code_lines = summary_data.get("code_lines")
            comment_lines = summary_data.get("comment_lines")
            total_files = summary_data.get("total_files")
            total_lines = summary_data.get("total_lines")

            summary = CodeMetricsSummary(blank_lines=blank_lines,
                                         code_lines=code_lines,
                                         comment_lines=comment_lines,
                                         total_files=total_files,
                                         total_lines=total_lines)

            details_data = code_metrics_data["details"]
            languages_data = details_data.get("languages", [])
            languages = []

            for language_data in languages_data:
                blank_lines = language_data.get("blank_lines")
                code_lines = language_data.get("code_lines")
                comment_lines = language_data.get("comment_lines")
                files_count = language_data.get("files_count")
                language = language_data.get("language")
                metrics = language_data.get("metrics", {})

                average_cyclomatic_complexity = metrics.get("average_cyclomatic_complexity")
                average_function_lines_of_code = metrics.get("average_function_lines_of_code")
                average_function_parameters_count = metrics.get("average_function_parameters_count")
                average_halstead_effort = metrics.get("average_halstead_effort")
                cost_change = metrics.get("cost_change")
                first_order_density = metrics.get("first_order_density")

                l = CodeMetricsLanguage(blank_lines=blank_lines,
                                        code_lines=code_lines,
                                        comment_lines=comment_lines,
                                        files_count=files_count,
                                        language=language,
                                        # metrics=metrics,
                                        average_cyclomatic_complexity=average_cyclomatic_complexity,
                                        average_function_lines_of_code=average_function_lines_of_code,
                                        average_function_parameters_count=average_function_parameters_count,
                                        average_halstead_effort=average_halstead_effort,
                                        cost_change=cost_change,
                                        first_order_density=first_order_density
                                        )

                languages.append(l)

            details = CodeMetricsDetails(languages=languages)

            code_metrics_result = CodeMetricsResult(None, status=status, summary=summary, details=details)

        return code_metrics_result

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
    def delete_all(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()).drop().toList()

        except Exception as e:
            logger.error("delete all() failed: %s" % e)
            return None

    def create(self):
        try:
            ts = time.time()
            results = self.g().addV(self.label). \
                property('vertex_label', self.label). \
                property('total_lines', self.summary.total_lines). \
                property('blank_lines', self.summary.blank_lines). \
                property('last_updated', ts).\
                toList()

            logger.debug("create() CodeMetricsResult - results: %s" % results)

            self.last_updated = ts
            self.id = results[0].id
            logger.info("Vertex ID : %s, CodeMetricsResult: %s" % (self.id, self))

            for lang in self.details.languages:
                lang.save()
                self.create_language_metrics_edge(lang)

            return self.id

        except Exception as e:
            logger.error("update() failed: %s" % e)
            return None

    def create_language_metrics_edge(self, v):
        try:
            g = self.g()
            return g.V(self.id).addE("has_language_metrics").property('last_updated', time.time()).to(g.V(v.id)).toList()

        except Exception as e:
            logger.error("create_language_metrics_edge() failed: %s" % e)
            return None

    def update(self):
        try:
            ts = time.time()
            results = self.g().V(self.id). \
                property('vertex_label', self.label). \
                property('total_lines', self.summary.total_lines). \
                property('blank_lines', self.summary.blank_lines). \
                property('last_updated', ts).\
                toList()

            self.last_updated = ts

            try:
                query = self.g().V(self.id).outE('has_language_metrics').inV().drop()
                result = query.toList()

                #Re add the language nodes again, so set their ids to null
                for lang in self.details.languages:
                    lang.id = None

                for lang in self.details.languages:
                    lang.save()
                    logger.debug("update() CodeMetricsLanguage - results: %s" % lang.to_json())
                    self.create_language_metrics_edge(lang)

                logger.debug("update() CodeMetricsResult - results: %s" % results)
                logger.info("Vertex ID : %s, CodeMetricsResult: %s" % (self.id, self))
                return self.id
            except Exception as e:
                raise Exception('Failed to delete and update the language code metric')
                
        except Exception as e:
            logger.error("update() failed: %s" % e)
            return None
