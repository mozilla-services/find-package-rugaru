# -*- coding: utf-8 -*-

import argparse
import json
import pathlib
import pickle
from typing import Callable, Any

import pytest

import context

import fpr.pipelines
from fpr.pipelines import pipelines


def load_test_fixture(filename: str, load_fn: Callable) -> Any:
    tests_dir = pathlib.Path(__file__).parent / ".."
    with (tests_dir / "fixtures" / filename).open("r+b") as fin:
        return load_fn(fin)


@pytest.mark.parametrize("pipeline", pipelines, ids=lambda p: p.name)
def test_serialize_returns_audit_result(pipeline):
    if pipeline.name == "save_to_db":
        return pytest.xfail("save to DB doesn't write output")

    unserialized = load_test_fixture(
        "{}_unserialized.pickle".format(pipeline.name), pickle.load
    )
    expected_serialized = load_test_fixture(
        "{}_serialized.json".format(pipeline.name), json.load
    )

    args = []
    if pipeline.name == "fetch_package_data":
        args += ["fetch_npmsio_scores"]

    default_args = pipeline.argparser(argparse.ArgumentParser()).parse_args(args)
    serialized = pipeline.serializer(default_args, unserialized)
    for field in sorted(pipeline.fields):
        assert field in serialized
        assert field in expected_serialized
        assert serialized[field] == expected_serialized[field]

    assert serialized == expected_serialized
