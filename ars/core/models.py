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

"""Defines dataclasses for business-logic data as well as request/reply models for use
in the API."""


from ghga_service_commons.utils.utc_dates import DateTimeUTC
from pydantic import BaseModel, Field

__all__ = ["AccessRequestCreationData", "AccessRequestData", "AccessRequest"]


class BaseDto(BaseModel):
    """Base model pre-configured for use as Dto."""

    class Config:  # pylint: disable=missing-class-docstring
        extra = "forbid"
        frozen = True


class AccessRequestCreationData(BaseDto):
    """All data necessary to create an access request."""

    user_id: str
    dataset_id: str
    # ... add remaining fields


class AccessRequestData(AccessRequestCreationData):
    """All data that describes an access request."""

    request_created: DateTimeUTC = Field(
        default=..., description="Creation date of the access request"
    )
    # ... add remaining fields


class AccessRequest(AccessRequestData):
    """An access request including a unique identifier."""

    id: str = Field(default=..., description="ID of the access request")
