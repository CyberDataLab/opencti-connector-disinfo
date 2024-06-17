# import os
import sys
import time

import stix2
from lib.external_import import ExternalImportConnector

import pandas as pd
import requests
import uuid

class CustomConnector(ExternalImportConnector):
    def __init__(self):
        """Initialization of the connector

        Note that additional attributes for the connector can be set after the super() call.

        Standardized way to grab attributes from environment variables is as follows:

        >>>         ...
        >>>         super().__init__()
        >>>         self.my_attribute = os.environ.get("MY_ATTRIBUTE", "INFO")

        This will make use of the `os.environ.get` method to grab the environment variable and set a default value (in the example "INFO") if it is not set.
        Additional tunning can be made to the connector by adding additional environment variables.

        Raising ValueErrors or similar might be useful for tracking down issues with the connector initialization.
        """
        super().__init__()

    def _collect_intelligence(self) -> []:
        """Collects intelligence from channels

        Add your code depending on the use case as stated at https://docs.opencti.io/latest/development/connectors/.
        Some sample code is provided as a guide to add a specific observable and a reference to the main object.
        Consider adding additional methods to the class to make the code more readable.

        Returns:
            stix_objects: A list of STIX2 objects."""
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        stix_objects = []

        # ===========================
        # === Add your code below ===
        # ===========================
        self.helper.log_debug("Creating a sample reference using STIX2...")
        main_reference = stix2.ExternalReference(
            source_name="GitHub",
            url="https://github.com/OpenCTI-Platform/connectors",
            description="A sample external reference used by the connector.",
        )

        self.helper.log_debug("Creating an observable for the IPv4...")
        ipv4_observable = stix2.IPv4Address(
            value="2.2.2.2",
            object_marking_refs=[stix2.TLP_GREEN],
            custom_properties={
                "description": "A sample observable created for the tutorial.",
                "labels": ["test", "tutorial"],
                "x_opencti_create_indicator": False,
                "external_references": [main_reference],
            },
        )

        self.helper.log_debug("Creating new object...")
        # Define the URL to download the XLS file
        xls_url = "https://github.com/DISARMFoundation/DISARMframeworks/raw/main/DISARM_MASTER_DATA/DISARM_DATA_MASTER.xlsx"
        self.helper.log_debug(f"Downloading the XLS file from {xls_url}...")

        response = requests.get(xls_url)
        if response.status_code != 200:
            self.helper.log_error(f"Failed to download the XLS file: {response.status_code}")
            return stix_objects

        xls_data = BytesIO(response.content)
        df = pd.read_excel(xls_data, sheet_name="incidents")

       # Replace NaN or infinite values with None to make them JSON serializable
        df = df.replace({float('inf'): None, float('-inf'): None})
        df = df.where(pd.notnull(df), None)

        # Custom namespace UUID for generating STIX IDs 
        # (now incidents with the same disarm_id will have the same STIX ID)
        NAMESPACE_UUID = uuid.UUID('12345678-1234-5678-1234-567812345678')

        # available columns are: 
        # disarm_id, name, objecttype, summary, year_started, attributions_seen, 
        # found_in_country, urls, notes, when_added, found_via, longname

        for _, row in df.iterrows():
            location = stix2.Location(
                country=row["found_in_country"]
            )
            
            incident = stix2.Incident(
                # Crear un UUID basado en el disarm_id
                id = f"incident--{uuid.uuid5(NAMESPACE_UUID, str(row['disarm_id']))}",

                name=row["name"],
                description=row["summary"],
                object_marking_refs=[stix2.TLP_GREEN],
                labels=["incident"],
                custom_properties={
                    "objecttype": row["objecttype"],
                    "year_started": row["year_started"],
                    "attributions_seen": row["attributions_seen"],
                    "found_in_country": row["found_in_country"],
                    "urls": row["urls"],
                    "notes": row["notes"],
                    "when_added": row["when_added"],
                    "found_via": row["found_via"],
                    "longname": row["longname"],
                }
            )
            
        stix_objects.append(ipv4_observable)
        # ===========================
        # === Add your code above ===
        # ===========================

        self.helper.log_info(
            f"{len(stix_objects)} STIX2 objects have been compiled by {self.helper.connect_name} connector. "
        )
        return stix_objects


if __name__ == "__main__":
    try:
        connector = CustomConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
