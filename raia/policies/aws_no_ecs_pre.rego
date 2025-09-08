# AWS ECS Cluster Access Allow Policy
# Description: Allows all users access to view ECS clusters
# Phase: pre
# Connector: aws

package aws.ecs.cluster.allow

# Allow access to ECS cluster operations
allow[msg] {
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
    
    msg := sprintf("Access allowed: ECS cluster operation '%s' is permitted", [input.action])
}

# Allow access to any ECS resource that contains cluster ARN
allow[msg] {
    input.service == "ecs"
    
    # Check if any resource ARN contains cluster
    some resource in input.resources
    contains(resource, ":cluster/")
    
    msg := sprintf("Access allowed: ECS cluster resource '%s' is accessible", [resource])
}

# Allow if cluster name is specified in parameters
allow[msg] {
    input.service == "ecs"
    
    # Check common parameter names that might contain cluster references
    cluster_params := {"cluster", "clusterName", "clusterArn", "clusters"}
    
    some param in cluster_params
    input.parameters[param]
    
    msg := sprintf("Access allowed: ECS cluster parameter '%s' is permitted", [param])
}