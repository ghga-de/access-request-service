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

"""A repository for access requests."""

from ghga_service_commons.auth.ghga import AuthContext
from pydantic import BaseSettings, Field

from ars.core.models import AccessRequestCreationData
from ars.ports.inbound.repository import AccessRequestRepositoryPort
from ars.ports.outbound.dao import AccessRequestDaoPort

__all__ = ["AccessRequestConfig", "AccessRequestRepository"]


class AccessRequestConfig(BaseSettings):
    """Config parameters needed for the AccessRequestRepository."""

    access_requests_collection: str = Field(
        "accessRequests",
        description="The name of the database collection for access requests",
    )


class AccessRequestRepository(AccessRequestRepositoryPort):
    """A repository for work packages."""

    def __init__(
        self,
        *,
        config: AccessRequestConfig,
        access_request_dao: AccessRequestDaoPort,
    ):
        """Initialize with specific configuration and outbound adapter."""
        self._config = config
        self._dao = access_request_dao

    async def create(
        self, *, creation_data: AccessRequestCreationData, auth_context: AuthContext
    ) -> None:
        """Create an access request and store it in the repository"""

        raise NotImplementedError
