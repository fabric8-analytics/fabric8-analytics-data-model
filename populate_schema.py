#!/usr/bin/env python
"""Populate graph schema."""

import logging
import time

from src.graph_manager import BayesianGraph


logger = logging.getLogger('schema')


def run():
    """Populate graph schema."""
    logger.info('Populating graph schema...')
    status, json_result = BayesianGraph.populate_schema()
    if not status:
        logger.error(json_result)
        raise RuntimeError('Failed to setup graph schema')
    # to prevent weird "parallelMutate" errors
    time.sleep(10)


if __name__ == '__main__':
    run()
