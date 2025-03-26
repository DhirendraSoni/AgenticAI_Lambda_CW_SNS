# Streamlit UI logic
import streamlit as st

def render_inputs():
    st.title("AWS Lambda Log Processor")
    aws_access_key_id = st.text_input("Enter your AWS Access Key ID", type="password")
    aws_secret_access_key = st.text_input("Enter your AWS Secret Access Key", type="password")
    aws_region = st.text_input("Enter your AWS Region", "us-east-1")
    lambda_prefix = st.text_input("Enter Lambda function prefix", "test")
    return aws_access_key_id, aws_secret_access_key, aws_region, lambda_prefix

def show_lambda_functions(functions):
    st.write(f"Found Lambda functions: {functions}")

def show_message(message, success=True):
    if success:
        st.success(message)
    else:
        st.error(message)

