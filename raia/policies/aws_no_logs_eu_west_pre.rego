package aws_logs_block_eu_west_1_pre

# Policy to block access to CloudWatch Logs in eu-west-1 region
# This policy denies any logs-related actions in the eu-west-1 region

import rego.v1
tool_cred_guid := "032b3350-657d-429c-95ee-e55e6bd4a950"

# Configuration
BLOCKED_REGION := "eu-west-1"
BLOCKED_ACTIONS := [
    "logs:CreateLogGroup",
    "logs:DeleteLogGroup", 
    "logs:DescribeLogGroups",
    "logs:CreateLogStream",
    "logs:DeleteLogStream",
    "logs:DescribeLogStreams",
    "logs:PutLogEvents",
    "logs:GetLogEvents",
    "logs:FilterLogEvents",
    "logs:DescribeSubscriptionFilters",
    "logs:PutSubscriptionFilter",
    "logs:DeleteSubscriptionFilter",
    "logs:DescribeMetricFilters",
    "logs:PutMetricFilter",
    "logs:DeleteMetricFilter",
    "logs:TestMetricFilter",
    "logs:DescribeExportTasks",
    "logs:CreateExportTask",
    "logs:DescribeDestinations",
    "logs:PutDestination",
    "logs:DeleteDestination"
]

# Main decision rule
decision := {
    "allowed": allowed,
    "reason": reason
}

# Allow by default unless logs action in blocked region
default allowed := true

# Deny if trying to access logs in eu-west-1
allowed := false if {
    is_logs_action_in_blocked_region
}

# Check if the action is a logs operation in the blocked region
is_logs_action_in_blocked_region if {
    # Check if action is logs-related
    action := input.action
    action in BLOCKED_ACTIONS
    
    # Check if region is eu-west-1
    region := get_region_from_input
    region == BLOCKED_REGION
}

# Extract region from different possible input formats
get_region_from_input := region if {
    # Direct region field
    region := input.region
} else := region if {
    # From AWS ARN
    arn := input.resource_arn
    arn_parts := split(arn, ":")
    count(arn_parts) >= 4
    region := arn_parts[3]
} else := region if {
    # From endpoint URL
    endpoint := input.endpoint
    contains(endpoint, "eu-west-1")
    region := "eu-west-1"
} else := region if {
    # From service URL pattern
    service_url := input.service_url
    regex.match(`.*\.eu-west-1\.amazonaws\.com.*`, service_url)
    region := "eu-west-1"
} else := "" {
    # Default if no region found
    true
}

# Provide detailed reason for blocking
reason := sprintf("Access to CloudWatch Logs denied: Action '%s' is not allowed in region '%s'", [input.action, BLOCKED_REGION]) if {
    not allowed
}

reason := "Access allowed" if {
    allowed
}