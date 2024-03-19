# Copyright 2021 - 2023 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
# for the German Human Genome-Phenome Archive (GHGA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Fixtures that are used in both integration and unit tests"""

from collections.abc import AsyncGenerator
from typing import NamedTuple

import pytest_asyncio
from ghga_service_commons.api.testing import AsyncTestClient
from ghga_service_commons.utils.jwt_helpers import (
    generate_jwk,
    sign_and_serialize_token,
)
from hexkit.custom_types import PytestScope
from hexkit.providers.akafka.testutils import KafkaFixture
from hexkit.providers.mongodb.testutils import MongoDbFixture
from pytest import fixture

from ars.config import Config
from ars.inject import prepare_core, prepare_rest_app

__all__ = [
    "AUTH_KEY_PAIR",
    "AUTH_CLAIMS_DOE",
    "AUTH_CLAIMS_STEWARD",
    "fixture_auth_headers_doe",
    "fixture_auth_headers_steward",
    "fixture_auth_headers_doe_inactive",
    "fixture_auth_headers_steward_inactive",
    "get_joint_fixture",
    "JointFixture",
    "headers_for_token",
]


AUTH_KEY_PAIR = generate_jwk()

AUTH_CLAIMS_DOE = {
    "name": "John Doe",
    "email": "john@home.org",
    "title": "Dr.",
    "id": "id-of-john-doe@ghga.de",
    "status": "active",
}

AUTH_CLAIMS_STEWARD = {
    "name": "Rod Steward",
    "email": "steward@ghga.de",
    "id": "id-of-rod-steward@ghga.de",
    "status": "active",
    "role": "data_steward@ghga.de",
}


def headers_for_token(token: str) -> dict[str, str]:
    """Get the Authorization headers for the given token."""
    return {"Authorization": f"Bearer {token}"}


@fixture(name="auth_headers_doe_inactive")
def fixture_auth_headers_doe_inactive() -> dict[str, str]:
    """Get auth headers for an inactive user requesting access"""
    claims_inactive = {**AUTH_CLAIMS_DOE, "status": "inactive"}
    token = sign_and_serialize_token(claims_inactive, AUTH_KEY_PAIR)
    return headers_for_token(token)


@fixture(name="auth_headers_steward_inactive")
def fixture_auth_headers_steward_inactive() -> dict[str, str]:
    """Get auth headers for an inactive data steward granting access"""
    claims_inactive = {**AUTH_CLAIMS_STEWARD, "status": "inactive"}
    token = sign_and_serialize_token(claims_inactive, AUTH_KEY_PAIR)
    return headers_for_token(token)


@fixture(name="auth_headers_doe")
def fixture_auth_headers_doe() -> dict[str, str]:
    """Get auth headers for a user requesting access"""
    token = sign_and_serialize_token(AUTH_CLAIMS_DOE, AUTH_KEY_PAIR)
    return headers_for_token(token)


@fixture(name="auth_headers_steward")
def fixture_auth_headers_steward() -> dict[str, str]:
    """Get auth headers for a data steward granting access"""
    token = sign_and_serialize_token(AUTH_CLAIMS_STEWARD, AUTH_KEY_PAIR)
    return headers_for_token(token)


class AccessRequestDetails(NamedTuple):
    """Hashable version of the AccessRequestDetails event schema"""

    user_id: str
    dataset_id: str


class JointFixture(NamedTuple):
    """Joint fixture object."""

    config: Config
    kafka: KafkaFixture
    mongodb: MongoDbFixture
    rest_client: AsyncTestClient


async def joint_fixture_function(
    mongodb_fixture: MongoDbFixture, kafka_fixture: KafkaFixture
) -> AsyncGenerator[JointFixture, None]:
    """A fixture that embeds all other fixtures for API-level integration testing

    **Do not call directly** Instead, use get_joint_fixture().
    """
    config = Config(
        auth_key=AUTH_KEY_PAIR.export_public(),  # pyright: ignore
        download_access_url="http://access",
        **kafka_fixture.config.model_dump(),
        **mongodb_fixture.config.model_dump(),
    )
    async with prepare_core(config=config) as core:
        async with (
            prepare_rest_app(config=config, core_override=core) as app,
        ):
            async with AsyncTestClient(app=app) as rest_client:
                yield JointFixture(
                    config=config,
                    kafka=kafka_fixture,
                    mongodb=mongodb_fixture,
                    rest_client=rest_client,
                )


def get_joint_fixture(scope: PytestScope = "function"):
    """Produce a joint fixture with desired scope"""
    return pytest_asyncio.fixture(joint_fixture_function, scope=scope)
