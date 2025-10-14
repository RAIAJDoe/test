package github.issue.protection

import rego.v1

# Default decision is to allow
default allow := true
default allow_redacted := false

tool_cred_guid := "3d7e3ff0-ab02-4c9c-9fc3-8ec63f785dfa"
# Block issue deletion operations
deny contains msg if {
    # Check if this is a GitHub API call
    input.request.url contains "api.github.com"
    
    # Check if this is an issue-related endpoint
    regex.match(`/repos/[^/]+/[^/]+/issues/\d+$`, input.request.path)
    
    # Block DELETE method on issues
    input.request.method == "DELETE"
    
    msg := {
        "violation": "issue_deletion_blocked",
        "message": "LLM is not permitted to delete GitHub issues",
        "severity": "high",
        "blocked_action": "DELETE issue",
        "endpoint": input.request.path
    }
}

# Block bulk issue operations that could include deletions
deny contains msg if {
    input.request.url contains "api.github.com"
    
    # Check for GraphQL mutations that might delete issues
    input.request.method == "POST"
    input.request.path contains "/graphql"
    
    # Check request body for issue deletion mutations
    request_body := json.unmarshal(input.request.body)
    query := request_body.query
    
    # Look for deleteIssue or similar mutations
    contains(lower(query), "deleteissue")
    
    msg := {
        "violation": "issue_deletion_via_graphql_blocked", 
        "message": "GraphQL mutations to delete issues are not permitted",
        "severity": "high",
        "blocked_action": "GraphQL deleteIssue mutation",
        "query_fragment": substring(query, 0, 100)
    }
}

# Block issue state changes to closed with certain patterns that might indicate deletion intent
deny contains msg if {
    input.request.url contains "api.github.com"
    regex.match(`/repos/[^/]+/[^/]+/issues/\d+$`, input.request.path)
    input.request.method == "PATCH"
    
    request_body := json.unmarshal(input.request.body)
    
    # Block closing issues with suspicious labels or titles
    request_body.state == "closed"
    
    # Check for deletion-related terms in the update
    some field, value in request_body
    is_string(value)
    deletion_terms := ["delete", "remove", "purge", "eliminate"]
    some term in deletion_terms
    contains(lower(value), term)
    
    msg := {
        "violation": "suspicious_issue_closure_blocked",
        "message": "Issue closure with deletion-related terms is not permitted", 
        "severity": "medium",
        "blocked_action": "PATCH issue with deletion terms",
        "suspicious_content": value
    }
}

# Allow other GitHub operations
allow if {
    input.request.url contains "api.github.com"
    not deny[_]
}

# Allow non-GitHub requests
allow if {
    not input.request.url contains "api.github.com"
}