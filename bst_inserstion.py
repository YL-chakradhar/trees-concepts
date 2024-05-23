#Binary search Tree
#leetcode 701
# Definition for a binary tree node.
# class TreeNode:
#     def __init__(self, val=0, left=None, right=None):
#         self.val = val
#         self.left = left
#         self.right = right
# class Solution:
#     def insertIntoBST(self, root: Optional[TreeNode], val: int) -> Optional[TreeNode]:
#         if root == None:
#             return TreeNode(val)
#         elif root.val > val:
#             root.left = self.insertIntoBST(root.left, val)
#         else:
#             root.right = self.insertIntoBST(root.right, val)
#         return root

#<<<<<<<<-----Delete BST------>>>>>>>>>>
#leetcode 450, 700
#https://pastebin.com/tBYc8fJb

def findInorderPredessor(root):
    while root.left != None:
        root = root.left 
    return root.data

def deleteInBST(root, val):
    if root == None:
        return None 
    elif root.data > val:
        root.left = deleteInBST(root.left, val)
    elif root.data < val:
        root.right = deleteInBST(root.right, val)
    else:
        if root.left == None and root.right == None:
            return None 
        elif root.left == None:
            return root.right 
        elif root.right == None:
            return root.left 
        else:
            predessor = findInorderPredessor(root)
            root.data = predessor 
            root.right = deleteInBST(root.right, predessor)
        return root
    
#https://pastebin.com/yaQbBdU8
# 1. Insertion into BST
def insertIntoBST(root, val):
    if root == None:
        return TreeNode(val)
    elif root.data > val:
        root.left = insertIntoBST(root.left, val)
    else:
        root.right = insertIntoBST(root.right, val)
    return root
 
# 2. Deletion in BST
 
class Solution:
    def findInorderSuccessor(self, root):
        while root.left != None:
            root = root.left 
        return root.val
 
    def deleteNode(self, root: Optional[TreeNode], val: int) -> Optional[TreeNode]:
        if root == None:
            return None 
        elif root.val > val:
            root.left = self.deleteNode(root.left, val)
        elif root.val < val:
            root.right = self.deleteNode(root.right, val)
        else:
            if root.left == None and root.right == None:
                return None 
            elif root.left == None:
                return root.right 
            elif root.right == None:
                return root.left 
            else:
                successor = self.findInorderSuccessor(root.right)
                root.val = successor 
                root.right = self.deleteNode(root.right, successor)
        return root
 
# 3. Search element in given BST 
# Try on your own
 
 
 
 
# 4. Kth Largest Element in BST
 
class Solution:
 
    def collectInorder(self, root, arr):
        if root == None:
            return 
        self.collectInorder(root.left, arr)
        arr.append(root.data)
        self.collectInorder(root.right, arr)
 
    def kthLargest(self,root, k):
        arr = []
        self.collectInorder(root, arr)
        n = len(arr)
        return arr[n - k]
 
# 5. Kth smallest element in BST
 
class Solution:
 
    def collectInorder(self, root, arr):
        if root == None:
            return 
        self.collectInorder(root.left, arr)
        arr.append(root.data)
        self.collectInorder(root.right, arr)
 
    def KthSmallestElement(self,root, K):
        arr = []
        self.collectInorder(root, arr)
        n = len(arr)
        if n < K:
            return -1
        return arr[K - 1] 
 
 
# 6. Check whether given tree is a valid BST or not 
 
class Solution:
    def collectInorder(self, root, arr):
        if root == None:
            return 
        self.collectInorder(root.left, arr)
        arr.append(root.val)
        self.collectInorder(root.right, arr)
        
    def isValidBST(self, root: Optional[TreeNode]) -> bool:
        arr = []
        self.collectInorder(root, arr)
        n = len(arr)
        for index in range(1, n):
            if arr[index] <= arr[index - 1]:
                return False 
        return True