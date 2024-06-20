# import os
import sys
import time

import stix2
from lib.external_import import ExternalImportConnector

from io import BytesIO
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

        # Here the plan is to create associations between incidents, techniques and actors.
        # We will create relationships between incidents and techniques, and between incidents and actors.
        self.helper.log_debug("Creating disinformation STIX objects...")
        for index, row in df.iterrows():
            # Now for this incident we also can get the techniques associated to this incident ID in the incidenttechniques sheet and create relationships to the threat actor (country):
            # incidentstechniques sheet header: disarm_id, name, incident_id, technique_ids, summary


            # Create the targeted country object (separated by commas)
            country_objects = []
            countries = row['found_in_country']
            if countries:
                countries = countries.split(",")
            for country in countries:
                country_id = country
                country_name = country
                country_object = stix2.Location(
                    id="location--" + str(uuid.uuid5(NAMESPACE_UUID, country_id)),
                    name=country_name,
                    country=country
                )
                country_objects.append(country_object)


            # Create the actor object (separated by commas or not present)
            actor_objects = []
            actors = ['Unknown']
            if row['attributions_seen']:
                actors = row['attributions_seen'].split(",")
            for actor in actors:
                # Create the threat actor object
                actor_id = actor
                actor_name = actor + " State"
                threat_actor = stix2.ThreatActor(
                    id="threat-actor--" + str(uuid.uuid5(NAMESPACE_UUID, actor_id)),
                    name=actor_name,
                    threat_actor_types = ["nation-state"],
                    labels=["threat-actor"]
                )
                actor_objects.append(threat_actor)
                

            # Get the techniques associated with this incident
            technique_objects = []
            campaign_id = row['disarm_id']
            techniques = pd.read_excel(xls_data, sheet_name="incidenttechniques")
            techniques = techniques.where(pd.notnull(techniques), None)
            incident_techniques = techniques[techniques['incident_id'] == campaign_id]
            for tech_index, tech_row in incident_techniques.iterrows():
                technique_id = tech_row['technique_ids']
                if technique_id:
                    attack_pattern = stix2.AttackPattern(
                        id="attack-pattern--" + str(uuid.uuid5(NAMESPACE_UUID, technique_id)), 
                        name=tech_row['technique_ids'],
                        description=tech_row['summary'],
                        labels=["attack-pattern"]
                    )

                    # Create the relationship between the actors, locations and techniques
                    for actor_object in actor_objects:
                        relationship_actor = stix2.Relationship(
                            source_ref=threat_actor.id,
                            relationship_type="uses",
                            target_ref=attack_pattern.id
                        )
                        stix_objects.append(relationship_actor)
                    for country in country_objects:
                        relationship_country = stix2.Relationship(
                            source_ref=attack_pattern.id,
                            relationship_type="targets",
                            target_ref=country_object.id
                        )
                        stix_objects.append(relationship_country)

                    technique_objects.append(attack_pattern)

            # Create a campaign object to represent the incident (campaign is the closest object to an incident in STIX)
            # Relate the campaign with the actors, locations and techniques.
            campaign_id = row['disarm_id']
            campaign_name = row['name']
            campaign_description = row['summary']
            campaign_object = stix2.Campaign(
                id="campaign--" + str(uuid.uuid5(NAMESPACE_UUID, campaign_id)),
                name=campaign_name,
                description=campaign_description,
                labels=["campaign", "disinformation"]
            )


            # Create the relationship between the used techniques and the incident
            for technique in technique_objects:
                relationship_technique = stix2.Relationship(
                    source_ref=campaign_object.id,
                    relationship_type="uses",
                    target_ref=technique.id
                )
                stix_objects.append(relationship_technique)

            # Create the relationship between the actors and the incident
            for actor in actor_objects:
                relationship_actor = stix2.Relationship(
                    source_ref=campaign_object.id,
                    relationship_type="attributed-to",
                    target_ref=actor.id
                )
                stix_objects.append(relationship_actor)

            # Create the relationship between the locations and the incident
            for country in country_objects:
                relationship_country = stix2.Relationship(
                    source_ref=campaign_object.id,
                    relationship_type="targets",
                    target_ref=country.id
                )
                stix_objects.append(relationship_country)

            stix_objects.append(campaign_object)
            stix_objects.extend(actor_objects)
            stix_objects.extend(country_objects)
            stix_objects.extend(technique_objects)

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
        time.sleep(10000) # 166 mins may be adecuate for debugging
        sys.exit(0)
