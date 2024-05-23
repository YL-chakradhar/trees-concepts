def initiateBFSTraversal(node, visited, adj, result):
    Q = [node]
    visited[node] = True
    while Q:
        currNode = Q.pop(0)
        result.append(currNode)
 
        for neighbour in adj[currNode]:
            if visited[neighbour] == False:
                visited[neighbour] = True 
                Q.append(neighbour)
 
def printBFSTraversal(adj, n):
    visited = [False] * n 
    result = []
    for node in range(n):
        if visited[node] == False:
            initiateBFSTraversal(node,visited, adj, result)
    print("BFS Traversal is: ", result)