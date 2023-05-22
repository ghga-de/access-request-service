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
#

"""Integration test using the REST API of the access request service"""

import json
import re
from datetime import datetime, timedelta
from typing import NamedTuple, Sequence, cast

from ghga_service_commons.api.testing import AsyncTestClient
from ghga_service_commons.utils.utc_dates import now_as_utc
from hexkit.providers.akafka.testutils import (  # noqa: F401 # pylint: disable=unused-import
    KafkaFixture,
    RecordedEvent,
    kafka_fixture,
)
from hexkit.providers.mongodb.testutils import (  # noqa: F401 # pylint: disable=unused-import
    mongodb_fixture,
)
from pytest import mark
from pytest_httpx import HTTPXMock

from .fixtures import (  # noqa: F401 # pylint: disable=unused-import
    fixture_auth_headers_doe,
    fixture_auth_headers_doe_inactive,
    fixture_auth_headers_steward,
    fixture_auth_headers_steward_inactive,
    fixture_client,
    fixture_container,
    non_mocked_hosts,
)

DATE_NOW = now_as_utc()
ONE_YEAR = timedelta(days=365)

CREATION_DATA = {
    "user_id": "id-of-john-doe@ghga.de",
    "dataset_id": "some-dataset",
    "email": "me@john-doe.name",
    "request_text": "Can I access some dataset?",
    "access_starts": DATE_NOW.isoformat(),
    "access_ends": (DATE_NOW + ONE_YEAR).isoformat(),
}


def assert_is_uuid(value: str) -> None:
    """Assert that the given value is a UUID"""
    assert isinstance(value, str)
    assert value.isascii()
    assert len(value) == 36
    assert value.count("-") == 4


def iso2timestamp(iso_date: str) -> float:
    """Get timestamp from given date in iso format."""
    return datetime.fromisoformat(iso_date).timestamp()


def assert_same_datetime(date1: str, date2: str, max_diff_seconds=5) -> None:
    """Assert that the two given dates in iso format are very close."""
    assert abs((iso2timestamp(date2) - iso2timestamp(date1))) < max_diff_seconds


class NotificationPayload(NamedTuple):
    """Class that stores an expected notification event payload."""

    email: str
    name: str
    subject: str  # regex pattern
    text: str  # regex pattern


def assert_recorded_events(
    recorded_events: Sequence[RecordedEvent],
    expected_payloads: list[NotificationPayload],
) -> None:
    """Assert that the recorded events are as expected."""
    assert len(recorded_events) == len(expected_payloads)
    for event, expected in zip(recorded_events, expected_payloads):
        assert event.type_ == "notification"
        assert event.key == expected.email
        got = event.payload
        assert isinstance(got, dict)
        assert got["recipient_email"] == expected.email
        assert got["email_cc"] == []
        assert got["email_bcc"] == []
        assert got["recipient_name"] == expected.name
        assert re.search(expected.subject, cast(str, got["subject"]))
        assert re.search(expected.text, cast(str, got["plaintext_body"]))


@mark.asyncio
async def test_health_check(client: AsyncTestClient):
    """Test that the health check endpoint works."""

    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "OK"}


@mark.asyncio
async def test_create_access_request(
    client: AsyncTestClient,
    auth_headers_doe: dict[str, str],
    kafka_fixture: KafkaFixture,  # noqa: F811 # pylint: disable=redefined-outer-name
):
    """Test that an active user can create an access request."""

    async with kafka_fixture.record_events(in_topic="notifications") as recorder:
        response = await client.post(
            "/access-requests", json=CREATION_DATA, headers=auth_headers_doe
        )

    assert response.status_code == 201

    access_request_id = response.json()
    assert_is_uuid(access_request_id)

    # check that notifications have been sent
    assert_recorded_events(
        recorder.recorded_events,
        [
            NotificationPayload(
                "steward@ghga.de",
                "Data Steward",
                "A data download access request has been created",
                "Dr. John Doe requested to download the dataset some-dataset",
            ),
            NotificationPayload(
                "me@john-doe.name",
                "Dr. John Doe",
                "Your data download access request has been registered",
                "Your request to download the dataset some-dataset has been registered",
            ),
        ],
    )


@mark.asyncio
async def test_create_access_request_unauthorized(
    client: AsyncTestClient,
    auth_headers_doe: dict[str, str],
    auth_headers_doe_inactive: dict[str, str],
):
    """Test that creating an access request needs authorization."""

    # test without authentication
    response = await client.post("/access-requests", json=CREATION_DATA)
    assert response.status_code == 403
    # test with inactive user
    response = await client.post(
        "/access-requests", json=CREATION_DATA, headers=auth_headers_doe_inactive
    )
    assert response.status_code == 403
    # test creating an access request for another user
    response = await client.post(
        "/access-requests",
        json={**CREATION_DATA, "user_id": "some-other-user@ghga.de"},
        headers=auth_headers_doe,
    )
    assert response.status_code == 403


@mark.asyncio
async def test_create_access_request_that_is_too_long(
    client: AsyncTestClient, auth_headers_doe: dict[str, str]
):
    """Test that an access request that is too long cannot be created."""

    response = await client.post(
        "/access-requests",
        json={
            **CREATION_DATA,
            "access_ends": (DATE_NOW + 3 * ONE_YEAR).isoformat(),
        },
        headers=auth_headers_doe,
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Access end date is invalid"


@mark.asyncio
async def test_get_access_requests(
    client: AsyncTestClient,
    auth_headers_doe: dict[str, str],
    auth_headers_steward: dict[str, str],
):
    """Test that users can get their access requests."""

    # create two access requests for different users
    response = await client.post(
        "/access-requests", json=CREATION_DATA, headers=auth_headers_doe
    )
    assert response.status_code == 201
    access_request_id = response.json()
    assert_is_uuid(access_request_id)
    response = await client.post(
        "/access-requests",
        json={**CREATION_DATA, "user_id": "id-of-rod-steward@ghga.de"},
        headers=auth_headers_steward,
    )
    assert response.status_code == 201
    another_access_request_id = response.json()
    assert_is_uuid(another_access_request_id)
    assert another_access_request_id != access_request_id

    # get own requests as user
    response = await client.get("/access-requests", headers=auth_headers_doe)

    assert response.status_code == 200
    requests = response.json()

    assert isinstance(requests, list)
    assert len(requests) == 1
    request = requests[0]
    assert request["id"] == access_request_id
    assert request["user_id"] == "id-of-john-doe@ghga.de"
    assert request["dataset_id"] == "some-dataset"
    assert request["status"] == "pending"

    # get all requests as data steward
    response = await client.get("/access-requests", headers=auth_headers_steward)

    assert response.status_code == 200
    requests = response.json()

    assert isinstance(requests, list)
    assert len(requests) == 2
    request = requests[0]
    # last made request comes first
    assert request["id"] == another_access_request_id
    assert request["user_id"] == "id-of-rod-steward@ghga.de"
    assert request["dataset_id"] == "some-dataset"
    assert request["status"] == "pending"
    request = requests[1]
    assert request["id"] == access_request_id
    assert request["user_id"] == "id-of-john-doe@ghga.de"
    assert request["dataset_id"] == "some-dataset"
    assert request["status"] == "pending"


@mark.asyncio
async def test_get_access_requests_unauthorized(
    client: AsyncTestClient, auth_headers_doe_inactive: dict[str, str]
):
    """Test that getting access requests needs authorization."""

    # test unauthenticated
    response = await client.get("/access-requests")
    assert response.status_code == 403

    # test with inactive user
    response = await client.get("/access-requests", headers=auth_headers_doe_inactive)
    assert response.status_code == 403


@mark.asyncio
async def test_filter_access_requests(
    client: AsyncTestClient,
    auth_headers_doe: dict[str, str],
    auth_headers_steward: dict[str, str],
):
    """Test that when getting access requests these can be filtered."""

    # create an access request
    response = await client.post(
        "/access-requests", json=CREATION_DATA, headers=auth_headers_doe
    )
    assert response.status_code == 201

    # without filter
    response = await client.get("/access-requests", headers=auth_headers_doe)
    assert response.status_code == 200
    assert len(response.json()) == 1

    # various filters
    response = await client.get(
        "/access-requests?user_id=id-of-john-doe@ghga.de", headers=auth_headers_doe
    )
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = await client.get(
        "/access-requests?user_id=somebody-else@ghga.de", headers=auth_headers_doe
    )
    assert response.status_code == 403  # only data steward can filter for other users

    response = await client.get(
        "/access-requests?user_id=somebody-else@ghga.de", headers=auth_headers_steward
    )
    assert response.status_code == 200
    assert len(response.json()) == 0

    response = await client.get(
        "/access-requests?dataset_id=some-dataset", headers=auth_headers_doe
    )
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = await client.get(
        "/access-requests?dataset_id=another-dataset", headers=auth_headers_doe
    )
    assert response.status_code == 200
    assert len(response.json()) == 0

    response = await client.get(
        "/access-requests?status=pending", headers=auth_headers_doe
    )
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = await client.get(
        "/access-requests?status=allowed", headers=auth_headers_doe
    )
    assert response.status_code == 200
    assert len(response.json()) == 0

    # combined filter
    response = await client.get(
        "/access-requests?"
        "user_id=id-of-john-doe@ghga.de&dataset_id=some-dataset&status=pending",
        headers=auth_headers_doe,
    )
    assert response.status_code == 200
    assert len(response.json()) == 1


@mark.asyncio
async def test_patch_access_request(
    client: AsyncTestClient,
    auth_headers_doe: dict[str, str],
    auth_headers_steward: dict[str, str],
    kafka_fixture: KafkaFixture,  # noqa: F811 # pylint: disable=redefined-outer-name
    httpx_mock: HTTPXMock,
):
    """Test that data stewards can change the status of access requests."""

    # mock setting the the access grant
    httpx_mock.add_response(
        method="POST",
        url="http://access/users/id-of-john-doe@ghga.de/datasets/some-dataset",
        status_code=204,
    )

    # create access request as user
    response = await client.post(
        "/access-requests", json=CREATION_DATA, headers=auth_headers_doe
    )
    assert response.status_code == 201
    access_request_id = response.json()
    assert_is_uuid(access_request_id)

    # set status to allowed as data steward
    async with kafka_fixture.record_events(in_topic="notifications") as recorder:
        response = await client.patch(
            f"/access-requests/{access_request_id}",
            json={"status": "allowed"},
            headers=auth_headers_steward,
        )
        assert response.status_code == 204

    # check that access has been granted
    request = httpx_mock.get_request()
    assert request
    validity = json.loads(request.content)
    # validity period may start a bit later because integration tests can be slow
    assert_same_datetime(validity["valid_from"], CREATION_DATA["access_starts"], 300)
    assert validity["valid_until"] == CREATION_DATA["access_ends"]

    # check that notifications have been sent
    assert_recorded_events(
        recorder.recorded_events,
        [
            NotificationPayload(
                "steward@ghga.de",
                "Data Steward",
                "Data download access has been allowed",
                "some-dataset has now been registered as allowed",
            ),
            NotificationPayload(
                "me@john-doe.name",
                "Dr. John Doe",
                "Your data download access request has been accepted",
                "You can now start download the dataset",
            ),
        ],
    )

    # get request as user
    response = await client.get("/access-requests", headers=auth_headers_doe)

    assert response.status_code == 200
    requests = response.json()

    assert isinstance(requests, list)
    assert len(requests) == 1
    request = requests[0]
    assert request["id"] == access_request_id
    assert request["user_id"] == "id-of-john-doe@ghga.de"
    assert request["dataset_id"] == "some-dataset"
    assert request["status"] == "allowed"
    assert request["status_changed"]
    assert request["changed_by"] is None  # cannot see internals

    # get request as data steward
    response = await client.get("/access-requests", headers=auth_headers_steward)

    assert response.status_code == 200
    requests = response.json()

    assert isinstance(requests, list)
    assert len(requests) == 1
    request = requests[0]
    assert request["id"] == access_request_id
    assert request["user_id"] == "id-of-john-doe@ghga.de"
    assert request["dataset_id"] == "some-dataset"
    assert request["status"] == "allowed"
    assert request["status_changed"]
    assert request["changed_by"] == "id-of-rod-steward@ghga.de"  # can see internals


@mark.asyncio
async def test_must_be_data_steward_to_patch_access_request(
    client: AsyncTestClient,
    auth_headers_doe: dict[str, str],
):
    """Test that only data stewards can change the status of access requests."""

    # create access request as user
    response = await client.post(
        "/access-requests", json=CREATION_DATA, headers=auth_headers_doe
    )
    assert response.status_code == 201
    access_request_id = response.json()
    assert_is_uuid(access_request_id)

    # set status without authentication
    response = await client.patch(
        f"/access-requests/{access_request_id}",
        json={"status": "allowed"},
    )
    assert response.status_code == 403
    # set status to allowed as the same user
    response = await client.patch(
        f"/access-requests/{access_request_id}",
        json={"status": "allowed"},
        headers=auth_headers_doe,
    )
    assert response.status_code == 403


@mark.asyncio
async def test_patch_non_existing_access_request(
    client: AsyncTestClient,
    auth_headers_steward: dict[str, str],
):
    """Test that data stewards get an error when patching non-existing requests."""
    response = await client.patch(
        "/access-requests/some-non-existing-request",
        json={"status": "allowed"},
        headers=auth_headers_steward,
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Access request not found"
