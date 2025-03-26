# Amazon Bedrock LLM logic
from langchain_community.llms import Bedrock
import re
import json
import streamlit as st

def init_model(bedrock_client):
    if not bedrock_client:
        st.error("Bedrock client is not initialized.")
        return None
    try:
        return Bedrock(model_id="amazon.titan-text-express-v1", client=bedrock_client)
    except Exception as e:
        st.error(f"Model init failed: {e}")
        return None

def process_logs(state):
    llm = state.llm
    if not llm:
        st.error("LLM not initialized!")
        return state

    processed_logs, error_counts = {}, {}

    for function_name, logs in state.logs.items():
        prompt = f"""Analyze logs for Lambda function: {function_name} and classify errors by severity (CRITICAL, WARNING, INFO), then summarize."""
        try:
            response = llm.generate([prompt])
            raw_output = response.generations[0][0].text.strip()
            counts = {
                "Critical": len(re.findall(r"\bCRITICAL\b", raw_output, re.IGNORECASE)),
                "Warning": len(re.findall(r"\bWARNING\b", raw_output, re.IGNORECASE)),
                "Info": len(re.findall(r"\bINFO\b", raw_output, re.IGNORECASE)),
            }
            processed_logs[function_name] = raw_output
            error_counts[function_name] = counts
        except Exception as e:
            st.error(f"Log processing failed for {function_name}: {e}")
            processed_logs[function_name] = "Error"
            error_counts[function_name] = {"Critical": 0, "Warning": 0, "Info": 0}

    state.processed_logs = processed_logs
    state.error_counts = error_counts
    return state

