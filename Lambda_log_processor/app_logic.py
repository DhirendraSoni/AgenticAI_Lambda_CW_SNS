# App logic
import boto3
import streamlit as st

def create_aws_session(aws_access_key_id, aws_secret_access_key, aws_region):
    return boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=aws_region
    )

def init_clients(aws_access_key_id, aws_secret_access_key, aws_region):
    session = create_aws_session(aws_access_key_id, aws_secret_access_key, aws_region)
    return (
        session.client("sns"),
        session.client("s3"),
        session.client("logs"),
        session.client("lambda"),
        session.client("bedrock-runtime")
    )

def find_lambda_functions_by_prefix(prefix, lambda_client):
    functions = []
    paginator = lambda_client.get_paginator("list_functions")
    for page in paginator.paginate():
        for function in page.get("Functions", []):
            if function["FunctionName"].startswith(prefix):
                functions.append(function["FunctionName"])
    return functions

def read_cloudwatch_logs(state, logs_client):
    logs = {}
    for fn in state.lambda_functions:
        log_group = f"/aws/lambda/{fn}"
        try:
            streams = logs_client.describe_log_streams(logGroupName=log_group).get("logStreams", [])
            if streams:
                events = logs_client.get_log_events(
                    logGroupName=log_group,
                    logStreamName=streams[-1]["logStreamName"]
                )["events"]
                logs[fn] = "\n".join(event["message"] for event in events)
            else:
                logs[fn] = "No logs found."
        except Exception as e:
            logs[fn] = f"Log fetch error: {str(e)}"
    state.logs = logs
    return state

def store_logs_in_s3(state, bucket_name="testbucket-cw-logstore"):
    s3 = state.s3_client
    s3_links = {}
    for fn, log in state.processed_logs.items():
        key = f"logs/{fn}_summary.txt"
        try:
            s3.put_object(Bucket=bucket_name, Key=key, Body=log.encode("utf-8"))
            s3_links[fn] = f"https://{bucket_name}.s3.amazonaws.com/{key}"
        except Exception as e:
            s3_links[fn] = "Upload failed"
    state.s3_links = s3_links
    return state

def send_sns_notification(state, topic_arn):
    sns = state.sns_client
    message = "### AWS Lambda CloudWatch Report\n\n"
    message += "| Function | Critical | Warning | Info | Summary |\n"
    message += "|----------|----------|---------|------|---------|\n"

    for fn in state.lambda_functions:
        counts = state.error_counts.get(fn, {})
        summary = state.processed_logs.get(fn, "").replace("\n", " ")
        message += f"| {fn} | {counts.get('Critical', 0)} | {counts.get('Warning', 0)} | {counts.get('Info', 0)} | {summary} |\n"

    message += "\n### Logs in S3:\n"
    for fn, link in state.s3_links.items():
        message += f"- [{fn}]({link})\n"

    try:
        response = sns.publish(
            TopicArn=topic_arn,
            Message=message,
            Subject="Lambda Error Summary"
        )
        st.success(f"SNS message sent: {response['MessageId']}")
    except Exception as e:
        st.error(f"SNS failed: {e}")
    return state

