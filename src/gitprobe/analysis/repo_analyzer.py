"""
Repository Analyzer Module

This module provides functionality to analyze repository structures and generate
detailed file tree representations with filtering capabilities.
"""

import os
import fnmatch
import json
from pathlib import Path
from typing import Dict, List, Optional, Union
from gitprobe.utils.patterns import DEFAULT_IGNORE_PATTERNS, DEFAULT_INCLUDE_PATTERNS


class RepoAnalyzer:
    """
    A comprehensive repository analyzer that generates structured file trees.

    This class analyzes local repository directories and creates detailed file tree
    structures with metadata including file sizes, extensions, and estimated token counts.
    It supports flexible filtering through include/exclude patterns to focus on
    relevant files and directories.

    Attributes:
        include_patterns (List[str]): Glob patterns for files to include in analysis.
                                    If None, defaults to DEFAULT_INCLUDE_PATTERNS.
        exclude_patterns (List[str]): Glob patterns for files/directories to exclude.
                                    Merged with DEFAULT_IGNORE_PATTERNS.
    """

    def __init__(
        self,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize the RepoAnalyzer with custom filtering patterns.

        Args:
            include_patterns: List of glob patterns for files to include.
                            If None, uses DEFAULT_INCLUDE_PATTERNS.
            exclude_patterns: List of glob patterns for files/directories to exclude.
                            These are added to DEFAULT_IGNORE_PATTERNS.
        """
        self.include_patterns = (
            include_patterns if include_patterns is not None else DEFAULT_INCLUDE_PATTERNS
        )

        self.exclude_patterns = (
            list(DEFAULT_IGNORE_PATTERNS) + exclude_patterns
            if exclude_patterns is not None
            else list(DEFAULT_IGNORE_PATTERNS)
        )

    def analyze_repository_structure(self, repo_dir: str) -> Dict:
        """
        Perform complete analysis of repository structure.

        Analyzes the given repository directory and returns a comprehensive
        structure including the file tree and summary statistics.

        Args:
            repo_dir: Path to the repository directory to analyze.

        Returns:
            Dict containing:
                - file_tree: Nested dictionary representing the directory structure
                - summary: Dictionary with total_files and total_size_kb

        Raises:
            FileNotFoundError: If the specified repository directory doesn't exist.
            PermissionError: If access to the directory is denied.

        Example:
            >>> result = analyzer.analyze_repository_structure('/path/to/repo')
            >>> print(result['summary']['total_files'])
        """
        file_tree = self._build_file_tree(repo_dir)

        return {
            "file_tree": file_tree,
            "summary": {
                "total_files": self._count_files(file_tree),
                "total_size_kb": self._calculate_size(file_tree),
            },
        }

    def _build_file_tree(self, repo_dir: str) -> Dict:
        """
        Build hierarchical file tree structure with intelligent filtering.

        Creates a nested dictionary representation of the directory structure,
        applying include/exclude patterns to filter relevant files and directories.

        Args:
            repo_dir: Root directory path to analyze.

        Returns:
            Dict representing the file tree structure with metadata.
        """

        def build_tree(path: Path, base_path: Path) -> Optional[Dict]:
            """
            Recursively build tree structure for a given path.

            Args:
                path: Current path being processed.
                base_path: Root path for calculating relative paths.

            Returns:
                Dict representing the current path's tree structure, or None if excluded.
            """
            relative_path = path.relative_to(base_path)
            relative_path_str = str(relative_path)

            if self._should_exclude_path(relative_path_str, path.name):
                return None

            if path.is_file():
                if not self._should_include_file(relative_path_str, path.name):
                    return None

                size = path.stat().st_size
                return {
                    "type": "file",
                    "name": path.name,
                    "path": relative_path_str,
                    "extension": path.suffix,
                    "_size_bytes": size,
                }
            elif path.is_dir():
                children = []
                try:
                    for child in sorted(path.iterdir()):
                        child_tree = build_tree(child, base_path)
                        if child_tree is not None:
                            children.append(child_tree)
                except PermissionError:
                    pass

                if children or str(relative_path) == ".":
                    return {
                        "type": "directory",
                        "name": path.name,
                        "path": relative_path_str,
                        "children": children,
                    }
                return None
            else:
                return None

        return build_tree(Path(repo_dir), Path(repo_dir))

    def _should_exclude_path(self, path: str, filename: str) -> bool:
        """
        Determine if a path should be excluded based on exclusion patterns.

        Checks the given path and filename against all configured exclude patterns
        using various matching strategies including glob patterns and path prefixes.

        Args:
            path: Relative path of the file/directory.
            filename: Name of the file/directory.

        Returns:
            True if the path should be excluded, False otherwise.
        """
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(filename, pattern):
                return True

            if pattern.endswith("/"):
                if path.startswith(pattern.rstrip("/")):
                    return True
            else:
                if path.startswith(pattern + "/") or path == pattern:
                    return True

                path_parts = path.split("/")
                if pattern in path_parts:
                    return True
        return False

    def _should_include_file(self, path: str, filename: str) -> bool:
        """
        Determine if a file should be included based on inclusion patterns.

        If no include patterns are specified, all files are included by default.
        Otherwise, files must match at least one include pattern.

        Args:
            path: Relative path of the file.
            filename: Name of the file.

        Returns:
            True if the file should be included, False otherwise.
        """
        if not self.include_patterns:
            return True

        for pattern in self.include_patterns:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def _count_files(self, tree: Dict) -> int:
        """
        Recursively count total number of files in the tree structure.

        Args:
            tree: File tree dictionary to count files in.

        Returns:
            Total number of files in the tree.
        """
        if tree["type"] == "file":
            return 1
        return sum(self._count_files(child) for child in tree.get("children", []))

    def _calculate_size(self, tree: Dict) -> float:
        """
        Recursively calculate total size of all files in the tree structure.

        Args:
            tree: File tree dictionary to calculate size for.

        Returns:
            Total size in kilobytes of all files in the tree.
        """
        if tree["type"] == "file":
            return tree.get("_size_bytes", 0) / 1024
        return sum(self._calculate_size(child) for child in tree.get("children", []))
