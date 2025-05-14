# Copyright 2021 - 2025 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

"""Database migration logic for ARS"""

from hexkit.correlation import new_correlation_id
from hexkit.providers.mongodb.migrations import (
    Document,
    MigrationDefinition,
    Reversible,
)


class V2Migration(MigrationDefinition, Reversible):
    """Populate new AccessRequest fields with empty string or `None` as appropriate."""

    version = 2

    async def apply(self):
        """Perform the migration and set the DB to version 2.

        Changes for existing docs in "accessRequests" collection:
        - Populate the required `dataset_title` and `dac_alias` fields with empty string
        - Populate `__metadata__` field for outbox with "published=True" and made-up
          correlation ID (since we don't know what was originally used).
        - Add `dataset_description`, `ticket_id`, `internal_note`,
          and `note_to_requester` with `None` because they are optional fields.
        """

        async def update_access_request_doc(doc: Document) -> Document:
            """Populate the required fields for access request docs"""
            doc["__metadata__"] = {
                "correlation_id": new_correlation_id(),
                "published": True,
                "deleted": False,
            }
            doc["dataset_title"] = ""
            doc["dac_alias"] = ""
            for optional_field in [
                "dataset_description",
                "ticket_id",
                "internal_note",
                "note_to_requester",
            ]:
                doc[optional_field] = None
            return doc

        # Migrate the accessRequests collection and auto-finalize (replace old collection)
        async with self.auto_finalize(coll_names="accessRequests", copy_indexes=False):
            await self.migrate_docs_in_collection(
                coll_name="accessRequests",
                change_function=update_access_request_doc,
            )

    async def unapply(self):
        """Reverse the migration so the DB will be back at version 1.

        Changes for "accessRequests" collection:
        - Remove `__metadata__` field
        - Remove `dataset_title`, `dataset_description`, `dac_alias`, `ticket_id`,
          `internal_note`, and `note_to_requester`
        """

        async def remove_access_request_fields(doc: Document) -> Document:
            """Remove the aforementioned fields"""
            for key in [
                "__metadata__",
                "dataset_title",
                "dataset_description",
                "dac_alias",
                "ticket_id",
                "internal_note",
                "note_to_requester",
            ]:
                doc.pop(key)
            return doc

        async with self.auto_finalize(coll_names="accessRequests", copy_indexes=False):
            await self.migrate_docs_in_collection(
                coll_name="accessRequests",
                change_function=remove_access_request_fields,
            )
