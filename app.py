import streamlit as st
from langgraph.graph import StateGraph
from dataclasses import dataclass
from langchain_community.llms import Bedrock
import boto3
import json
import os
from dotenv import load_dotenv

# Streamlit App Interface
st.title("AWS Lambda Log Processor")

# Input for AWS API keys at runtime
aws_access_key_id = st.text_input("Enter your AWS Access Key ID", type="password")
aws_secret_access_key = st.text_input("Enter your AWS Secret Access Key", type="password")
aws_region = st.text_input("Enter your AWS Region", "us-east-1")
llm = None

# os.environ["AWS_ACCESS_KEY_ID"]=os.getenv("AWS_ACCESS_KEY_ID")
# os.environ["AWS_SECRET_ACCESS_KEY"]=os.getenv("AWS_SECRET_ACCESS_KEY")
# os.environ["AWS_REGION"]=os.getenv("AWS_REGION")

@dataclass
class WorkflowState:
    lambda_functions: list
    logs: dict = None
    processed_logs: dict = None
    s3_links: dict = None
    llm: object = None
    s3_client: object = None
    sns_client: object = None

    def __post_init__(self):
        if self.logs is None:
            self.logs = {}
        if self.processed_logs is None:
            self.processed_logs = {}
        if self.s3_links is None:
            self.s3_links = {}  

# Function to create a session using provided API keys
# def create_aws_session():
#     return boto3.Session(
#         aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
#         aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
#         region_name=os.environ["AWS_REGION"]
#     )

def create_aws_session(aws_access_key_id, aws_secret_access_key, aws_region):
    return boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=aws_region
    )


# AWS Client Initialization
def init_clients(aws_access_key_id, aws_secret_access_key, aws_region):
    try:
        session = create_aws_session(aws_access_key_id, aws_secret_access_key, aws_region)

        sns_client = session.client("sns")
        s3_client = session.client("s3")
        logs_client = session.client("logs")
        lambda_client = session.client("lambda")
        bedrock_client = session.client("bedrock-runtime")

        # Debug: Verify client initialization
        st.write("AWS session and clients initialized successfully.")
        st.write(f"sns_client: {sns_client is not None}")
        st.write(f"s3_client: {s3_client is not None}")
        st.write(f"logs_client: {logs_client is not None}")
        st.write(f"lambda_client: {lambda_client is not None}")
        st.write(f"bedrock_client: {bedrock_client is not None}")

        return sns_client, s3_client, logs_client, lambda_client, bedrock_client

    except Exception as e:
        st.error(f"Error initializing AWS clients: {e}")
        return None, None, None, None, None

# Amazon Titan Model
def init_model(bedrock_client):
    try:
        # Initialize the Bedrock model
        if bedrock_client is None:
            st.error("Bedrock client is not initialized. Check AWS credentials.")
            return None
        
        llm = Bedrock(
            model_id="amazon.titan-text-express-v1",
            client=bedrock_client
        )
        
        st.write(llm)

        if llm is None:
            st.error("Failed to initialize the Bedrock model.")
        return llm
    except Exception as e:
        st.error(f"Error initializing the model: {e}")
        return None
  

# Step 1: Find Lambda Functions by Prefix
def find_lambda_functions_by_prefix(prefix="test", lambda_client=None):
    functions = []
    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for function in page.get("Functions", []):
            function_name = function["FunctionName"]
            if function_name.startswith(prefix):
                functions.append(function_name)
    return functions

# Step 2: Read CloudWatch Logs for Each Lambda Function
def read_cloudwatch_logs(state, logs_client=None):
    logs_dict = {}
    for function_name in state.lambda_functions:
        log_group_name = f"/aws/lambda/{function_name}"
        try:
            response = logs_client.describe_log_streams(logGroupName=log_group_name)
            log_streams = response.get("logStreams", [])
            if log_streams:
                log_stream_name = log_streams[-1]["logStreamName"]
                log_events = logs_client.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=log_stream_name
                )
                logs = "\n".join([event["message"] for event in log_events["events"]])
            else:
                logs = "No logs found."
            logs_dict[function_name] = logs
        except Exception as e:
            logs_dict[function_name] = f"Error retrieving logs: {str(e)}"
    
    state.logs = logs_dict
    return state

# Step 3: Process Logs with LLM
st.write("****************")
st.write(llm)

def process_logs(state):
    llm = state.llm
    if llm is None:
        st.error("LLM (model) is not initialized in state!")
        return state
    
    processed_logs = {}
    for function_name, logs in state.logs.items():
        prompt = f"""Analyze the following CloudWatch logs and categorize errors as Critical, Warning, or Info. 
        Provide a summary of the errors found for function {function_name}. Logs:
        {logs}"""

        try:
            response = llm.generate([prompt])
            processed_logs[function_name] = response.generations[0][0].text  # Extract first response
        except Exception as e:
            st.error(f"Error during log processing for {function_name}: {e}")
            processed_logs[function_name] = "Error processing logs"
    
    state.processed_logs = processed_logs
    return state

# Step 4: Store Logs in S3
def store_logs_in_s3(state):
    s3_client = state.s3_client
    if s3_client is None:
        st.error("S3 client is not initialized!")
        return state

    bucket_name = "testbucket-cw-logstore"  # replace with your actual bucket
    s3_links = {}

    for function_name, processed_log in state.processed_logs.items():
        key = f"logs/{function_name}_log_summary.txt"
        try:
            s3_client.put_object(
                Bucket=bucket_name,
                Key=key,
                Body=processed_log.encode("utf-8")
            )
            link = f"https://{bucket_name}.s3.amazonaws.com/{key}"
            s3_links[function_name] = link
        except Exception as e:
            st.error(f"Failed to upload logs for {function_name} to S3: {e}")
            s3_links[function_name] = "Upload failed"

    state.s3_links = s3_links
    return state

# Step 5: SNS Notification
def send_sns_notification(state):
    sns_client = state.sns_client
    if sns_client is None:
        st.error("SNS client is not initialized!")
        return state

    warning_logs = []
    critical_logs = []

    # Categorizing logs
    for function_name, processed_log in state.processed_logs.items():
        if "WARNING" in processed_log:
            warning_logs.append((function_name, processed_log))
        if "CRITICAL" in processed_log:
            critical_logs.append((function_name, processed_log))

    # Table
    message = "### CloudWatch Error Summary \n\n"
    message += "| Severity  | Lambda Function  | Log Details  |\n"
    message += "|-----------|-----------------|--------------|\n"

    for function_name, log_details in warning_logs:
        message += f"| WARNING   | {function_name} | {log_details} |\n"

    for function_name, log_details in critical_logs:
        message += f"| CRITICAL  | {function_name} | {log_details} |\n"

    message += "\n### 🔍 Full logs stored in S3:\n"
    
    # Add S3 Links for reference
    for function_name, link in state.s3_links.items():
        message += f"- [{function_name}]({link})\n"

    # Send Email via SNS
    try:
        response = sns_client.publish(
            TopicArn="arn:aws:sns:us-east-1:050451365316:testsnstopic",
            Message=message,
            Subject="AWS Lambda Warning & Critical Logs",
            MessageStructure="string"
        )
        st.success(f"SNS Message Sent! Message ID: {response['MessageId']}")
    except Exception as e:
        st.error(f"Error sending SNS notification: {e}")

    return state

# Streamlit UI Logic
lambda_prefix = st.text_input("Enter Lambda function prefix", "test1")


if aws_access_key_id and aws_secret_access_key and aws_region:
    sns_client, s3_client, logs_client, lambda_client, bedrock_client = init_clients(
        aws_access_key_id, aws_secret_access_key, aws_region
    )
    llm = init_model(bedrock_client)
    st.write(f"find all the lambda functions...{llm}")
    if sns_client and llm:
        if st.button("Find Lambda Functions"):
            lambda_functions = find_lambda_functions_by_prefix(lambda_prefix, lambda_client)
            st.write(f"Found Lambda functions: {lambda_functions}")
            
            if lambda_functions:
                workflow = StateGraph(WorkflowState)
                workflow.add_node("read_logs", read_cloudwatch_logs)
                workflow.add_node("process_logs", process_logs)
                workflow.add_node("store_logs", store_logs_in_s3)
                workflow.add_node("send_notification", send_sns_notification)

                workflow.add_edge("read_logs", "process_logs")
                workflow.add_edge("process_logs", "store_logs")
                workflow.add_edge("store_logs", "send_notification")

                workflow.set_entry_point("read_logs")
                compiled_workflow = workflow.compile()

                # Display workflow graph
                #st.image(compiled_workflow.get_graph().draw_mermaid_png())

                try:
                    st.image(compiled_workflow.get_graph().draw_mermaid_png())
                except Exception as e:
                    st.warning(f"Mermaid rendering failed: {e}")
                    st.code(compiled_workflow.get_graph().draw_mermaid(), language="mermaid")



                # Invoke the workflow with found Lambda functions
                compiled_workflow.invoke(
                    WorkflowState(
                        lambda_functions=lambda_functions,
                        logs={},
                        processed_logs={},
                        s3_links={},
                        llm=llm,
                        s3_client=s3_client,
                        sns_client=sns_client
                    )
                )
                st.success("Workflow complete and SNS notification sent!")

else:
    st.warning("Please provide valid AWS Access Key ID, Secret Access Key, and Region.")
