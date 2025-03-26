# LangGraph state object
from dataclasses import dataclass

@dataclass
class WorkflowState:
    lambda_functions: list
    logs: dict = None
    processed_logs: dict = None
    error_counts: dict = None
    s3_links: dict = None
    llm: object = None
    s3_client: object = None
    sns_client: object = None

    def __post_init__(self):
        self.logs = self.logs or {}
        self.processed_logs = self.processed_logs or {}
        self.error_counts = self.error_counts or {}
        self.s3_links = self.s3_links or {}

