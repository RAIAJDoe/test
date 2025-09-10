# AWS ECS Cluster Access Denial Policy
# Description: Denies all users access to view ECS clusters
# Phase: pre
# Connector: aws

package aws.ecs.cluster.deny

tool_cred_guid := "1ff2596e-e665-4e37-806d-c1701270fba6"

# Deny access to ECS cluster operations
deny[msg] {
    # Check if this is an ECS service call
    input.service == "ecs"
    
    # Check if the action is related to cluster operations
    cluster_actions := {
        "DescribeClusters",
        "ListClusters", 
        "CreateCluster",
        "DeleteCluster",
        "UpdateCluster",
        "PutClusterCapacityProviders",
        "TagResource",
        "UntagResource",
        "ListTagsForResource"
    }
    
    cluster_actions[input.action]
    
    msg := sprintf("Access denied: ECS cluster operation '%s' is not allowed for any user", [input.action])
}

# Deny access to any ECS resource that contains cluster ARN
deny[msg] {
    input.service == "ecs"
    
    # Check if any resource ARN contains cluster
    some resource in input.resources
    contains(resource, ":cluster/")
    
    msg := sprintf("Access denied: Cannot access ECS cluster resource '%s'", [resource])
}

# Additional protection - deny if cluster name is specified in parameters
deny[msg] {
    input.service == "ecs"
    
    # Check common parameter names that might contain cluster references
    cluster_params := {"cluster", "clusterName", "clusterArn", "clusters"}
    
    some param in cluster_params
    input.parameters[param]
    
    msg := sprintf("Access denied: ECS cluster parameter '%s' detected in request", [param])
}