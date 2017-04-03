from entities.package import Package
from entities.version import Version
from entities.utils import get_values as gv
from entities.code_metrics import CodeMetricsResult, CodeMetricsLanguage
import set_logging as log

npm_crumb_data = gv.read_from_file('test/data/npm-crumb-4.0.0.json')


def test_code_metrics_non_empty():
    code_metrics = CodeMetricsResult.load_from_json(
        npm_crumb_data["analyses"]["code_metrics"])
    assert(code_metrics is not None)
    assert(code_metrics.status == "success")
    assert(code_metrics.summary is not None)
    assert(code_metrics.summary.total_lines == 1351)
    assert(code_metrics.summary.blank_lines == 358)
    assert(code_metrics.details.languages is not None)
    assert(len(code_metrics.details.languages) == 6)

    yaml_metrics = code_metrics.details.languages[0]
    assert(yaml_metrics.language == "YAML")
    assert(yaml_metrics.average_cyclomatic_complexity == -1)

    js_metrics = code_metrics.details.languages[4]

    assert(js_metrics.language == "JavaScript")
    assert(js_metrics.average_cyclomatic_complexity == 2.196360153256705)

    log.logger.debug("js_lang_metrics: %s" %
                 js_metrics.average_cyclomatic_complexity)


def test_add_code_metrics_non_empty():
    p = Package.load_from_json(npm_crumb_data)
    p.save()
    v = Version.load_from_json(npm_crumb_data, package=p)
    v.save()
    p.create_version_edge(v)
    assert p.last_updated is not None
    assert v.last_updated is not None
    code_metrics_data = npm_crumb_data["analyses"]["code_metrics"]
    code_metrics = CodeMetricsResult.load_from_json(code_metrics_data)
    assert code_metrics.last_updated is None
    assert code_metrics.id is None

    v.add_code_metrics_edge(code_metrics)
    assert code_metrics.id >= 0
    assert code_metrics.last_updated is not None
    assert code_metrics.last_updated > v.last_updated
    assert (CodeMetricsResult.count() == 1)
    assert (CodeMetricsLanguage.count() == 6)

    count_before = len(v.get_version_out_edge('has_code_metrics'))
    assert count_before == 1

    #try adding the edge again, should not let this happen
    results2 = v.add_code_metrics_edge(code_metrics)

    count_after = len(v.get_version_out_edge('has_code_metrics'))
    assert count_after == count_before
    assert CodeMetricsLanguage.count() == 6

    lang_nodes = CodeMetricsLanguage.find_all()

    for lang_node in lang_nodes:
        CodeMetricsLanguage.delete_by_id(lang_node.id)   

    CodeMetricsLanguage.delete_by_id(code_metrics.id)
    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)


