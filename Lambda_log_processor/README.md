# Lambda Log Analyzer with Streamlit + LangGraph + Amazon Bedrock

A modular Streamlit application that:
- Fetches AWS Lambda logs from CloudWatch
- Processes them using Amazon Bedrock Titan LLM
- Categorizes errors by severity
- Uploads results to S3
- Sends a summary via SNS notification

## How to Run

```bash
pip install -r requirements.txt
streamlit run main.py
```

##AWS Credentials

Make sure to provide valid AWS credentials with access to:
- Lambda
- CloudWatch Logs
- SNS
- S3
- Bedrock

## 📦 Project Structure

- `main.py`: Streamlit entry and orchestration
- `ui.py`: Streamlit widgets and display
- `llm.py`: LLM model initialization and log parsing
- `app_logic.py`: AWS API logic (CloudWatch, S3, SNS)
- `state.py`: Workflow state object
