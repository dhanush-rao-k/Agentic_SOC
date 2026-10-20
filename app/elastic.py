
import os

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

url = os.getenv(
    "ELASTICSEARCH_URL",
    "http://127.0.0.1:9200",
)
username = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
password = os.getenv("ELASTICSEARCH_PASSWORD")

if not password:
    raise RuntimeError(
        "ELASTICSEARCH_PASSWORD is missing from .env"
    )

es = Elasticsearch(
    url,
    basic_auth=(username, password),
    request_timeout=10,
)


def check_connection() -> dict:
    info = es.info()

    return {
        "connected": True,
        "cluster_name": info["cluster_name"],
        "version": info["version"]["number"],
    }


def search_ssh_failures(size: int = 10) -> list[dict]:
    response = es.search(
        index="logs-*",
        size=size,
        sort=[{"@timestamp": {"order": "desc"}}],
        query={
            "bool": {
                "filter": [
                    {"term": {"data_stream.dataset": "system.auth"}},
                    {
                        "bool": {
                            "should": [
                                {
                                    "match_phrase": {
                                        "message": "authentication failure"
                                    }
                                },
                                {
                                    "match_phrase": {
                                        "message": "Failed password"
                                    }
                                },
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ]
            }
        },
    )

    return [
        {
            "timestamp": hit["_source"].get("@timestamp"),
            "host": hit["_source"].get("host", {}).get("name"),
            "process": hit["_source"].get("process", {}).get("name"),
            "message": hit["_source"].get("message"),
            "dataset": hit["_source"].get("data_stream", {}).get("dataset"),
        }
        for hit in response["hits"]["hits"]
    ]
