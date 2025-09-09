# Package declaration for lambda logs access control
package raia.policies.lambda_logs_deny

import rego.v1

# Policy metadata
policy_name := "Lambda Logs Access Denial"
description := "Deny users access to any Lambda-related logs and outputs"
phase := "post"

# Main decision rule
decision := "deny" if {
    is_lambda_related_content
}

decision := "allow" if {
    not is_lambda_related_content
}

# Check if content contains Lambda-related information
is_lambda_related_content if {
    contains_lambda_logs
}

is_lambda_related_content if {
    contains_lambda_function_output
}

is_lambda_related_content if {
    contains_cloudwatch_lambda_logs
}

# Detect Lambda function logs
contains_lambda_logs if {
    some log in input.response.logs
    contains(lower(log), "lambda")
}

contains_lambda_logs if {
    some log in input.response.logs
    contains(lower(log), "aws lambda")
}

contains_lambda_logs if {
    some log in input.response.logs
    regex.match(`/aws/lambda/.*`, lower(log))
}

# Detect Lambda function outputs or responses
contains_lambda_function_output if {
    response_text := lower(input.response.text)
    contains(response_text, "lambda function")
}

contains_lambda_function_output if {
    response_text := lower(input.response.text)
    contains(response_text, "function execution")
}

contains_lambda_function_output if {
    response_text := lower(input.response.text)
    regex.match(`.*lambda.*execution.*`, lower(input.response.text))
}

# Detect CloudWatch logs specifically for Lambda
contains_cloudwatch_lambda_logs if {
    response_text := lower(input.response.text)
    contains(response_text, "/aws/lambda/")
}

contains_cloudwatch_lambda_logs if {
    response_text := lower(input.response.text)
    contains(response_text, "cloudwatch")
    contains(response_text, "lambda")
}

# Check for Lambda-related API calls or ARNs
contains_cloudwatch_lambda_logs if {
    response_text := lower(input.response.text)
    regex.match(`.*arn:aws:lambda:.*`, response_text)
}

# Violation reasons for logging/auditing
violation_reasons contains "Lambda logs detected in response" if {
    contains_lambda_logs
}

violation_reasons contains "Lambda function output detected" if {
    contains_lambda_function_output
}

violation_reasons contains "CloudWatch Lambda logs detected" if {
    contains_cloudwatch_lambda_logs
}

# Redaction patterns to remove sensitive Lambda information
redaction_patterns := [
    {
        "pattern": "(?i)lambda function[^\\n]*",
        "replacement": "[LAMBDA FUNCTION REDACTED]"
    },
    {
        "pattern": "(?i)/aws/lambda/[^\\s]*",
        "replacement": "[LAMBDA LOG GROUP REDACTED]"
    },
    {
        "pattern": "(?i)arn:aws:lambda:[^\\s]*",
        "replacement": "[LAMBDA ARN REDACTED]"
    },
    {
        "pattern": "(?i)function execution[^\\n]*",
        "replacement": "[LAMBDA EXECUTION REDACTED]"
    }
]

# User-friendly message for denial
user_message := "⚠️ This response was blocked by policy [Lambda Logs Access Denial]. Lambda-related logs and function outputs are not permitted to be displayed."

# Confidence score (0-100)
confidence_score := 95 if {
    count(violation_reasons) > 0
}

confidence_score := 0 if {
    count(violation_reasons) == 0
}