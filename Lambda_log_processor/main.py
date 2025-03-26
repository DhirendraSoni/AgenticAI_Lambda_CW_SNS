# Entry point for Streamlit app

import streamlit as st
from langgraph.graph import StateGraph
from state import WorkflowState
from ui import render_inputs, show_lambda_functions
from app_logic import init_clients, find_lambda_functions_by_prefix, read_cloudwatch_logs, store_logs_in_s3, send_sns_notification
from llm import init_model, process_logs

aws_access_key_id, aws_secret_access_key, aws_region, lambda_prefix = render_inputs()

if aws_access_key_id and aws_secret_access_key and aws_region:
    sns_client, s3_client, logs_client, lambda_client, bedrock_client = init_clients(
        aws_access_key_id, aws_secret_access_key, aws_region
    )
    llm = init_model(bedrock_client)

    if st.button("Find Lambda Functions"):
        functions = find_lambda_functions_by_prefix(lambda_prefix, lambda_client)
        show_lambda_functions(functions)

        if functions:
            workflow = StateGraph(WorkflowState)
            workflow.add_node("read_logs", lambda state: read_cloudwatch_logs(state, logs_client))
            workflow.add_node("process_logs", process_logs)
            workflow.add_node("store_logs", lambda state: store_logs_in_s3(state))
            workflow.add_node("send_notification", lambda state: send_sns_notification(state, "arn:aws:sns:us-east-1:050451365316:testsnstopic"))

            workflow.add_edge("read_logs", "process_logs")
            workflow.add_edge("process_logs", "store_logs")
            workflow.add_edge("store_logs", "send_notification")
            workflow.set_entry_point("read_logs")

            compiled_workflow = workflow.compile()

            try:
                st.image(compiled_workflow.get_graph().draw_mermaid_png())
            except Exception as e:
                st.warning(f"Mermaid rendering failed: {e}")
                st.code(compiled_workflow.get_graph().draw_mermaid(), language="mermaid")

            compiled_workflow.invoke(WorkflowState(
                lambda_functions=functions,
                llm=llm,
                s3_client=s3_client,
                sns_client=sns_client
            ))

