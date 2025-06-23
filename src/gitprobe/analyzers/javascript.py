"""
Advanced JavaScript/TypeScript analyzer using Tree-sitter for accurate AST parsing.

This module provides proper AST-based analysis for JavaScript and TypeScript files,
replacing the regex-based approach with a more accurate tree-sitter implementation.
"""

import logging
from typing import List, Set, Optional
from pathlib import Path

from tree_sitter import Parser, Language
import tree_sitter_javascript
import tree_sitter_typescript

from gitprobe.models.core import Function, CallRelationship
from gitprobe.core.analysis_limits import AnalysisLimits, create_javascript_limits

logger = logging.getLogger(__name__)


class TreeSitterJSAnalyzer:
    """JavaScript analyzer using tree-sitter for proper AST parsing."""

    def __init__(self, file_path: str, content: str, limits: Optional[AnalysisLimits] = None):
        self.file_path = Path(file_path)
        self.content = content
        self.functions: List[Function] = []
        self.call_relationships: List[CallRelationship] = []
        self.limits = limits or create_javascript_limits()

        try:
            language_capsule = tree_sitter_javascript.language()
            self.js_language = Language(language_capsule)
            self.parser = Parser(self.js_language)
            logger.debug(
                f"JavaScript parser initialized with language object: {type(self.js_language)}"
            )

            test_code = "function test() { console.log('test'); }"
            test_tree = self.parser.parse(bytes(test_code, "utf8"))
            if test_tree is None or test_tree.root_node is None:
                raise RuntimeError("Parser setup test failed for JavaScript")
            logger.debug(
                f"JavaScript parser test successful - root node type: {test_tree.root_node.type}"
            )

        except Exception as e:
            logger.error(f"Failed to initialize JavaScript parser: {e}")
            self.parser = None
            self.js_language = None

        logger.info(f"TreeSitterJSAnalyzer initialized for {file_path} with limits: {self.limits}")

    def analyze(self) -> None:
        """Analyze the JavaScript content and extract functions and call relationships."""
        if not self.limits.start_new_file():
            logger.info(f"Skipping {self.file_path} - global limits reached")
            return

        if self.parser is None:
            logger.warning(f"Skipping {self.file_path} - parser initialization failed")
            return

        try:
            tree = self.parser.parse(bytes(self.content, "utf8"))
            root_node = tree.root_node

            logger.info(f"Parsed AST with root node type: {root_node.type}")

            self._extract_functions(root_node)

            if not self.limits.should_stop():
                self._extract_call_relationships(root_node)

            logger.info(
                f"Analysis complete: {len(self.functions)} functions, {len(self.call_relationships)} relationships, {self.limits.nodes_processed} nodes processed"
            )

        except Exception as e:
            logger.error(f"Error analyzing JavaScript file {self.file_path}: {e}", exc_info=True)

    def _extract_functions(self, node) -> None:
        """Extract all function definitions from the AST."""
        self._traverse_for_functions(node)
        self.functions.sort(key=lambda f: f.line_start)

    def _traverse_for_functions(self, node) -> None:
        """Recursively traverse AST nodes to find functions."""

        if node.type == "function_declaration":
            func = self._extract_function_declaration(node)
            if func and self._should_include_function(func):
                if self.limits.can_add_function():
                    self.functions.append(func)
                    if self.limits.add_function():
                        return
                else:
                    return

        elif node.type == "export_statement":
            func = self._extract_exported_function(node)
            if func and self._should_include_function(func):
                if self.limits.can_add_function():
                    self.functions.append(func)
                    if self.limits.add_function():
                        return
                else:
                    return

        elif node.type == "lexical_declaration":
            func = self._extract_arrow_function_from_declaration(node)
            if func and self._should_include_function(func):
                if self.limits.can_add_function():
                    self.functions.append(func)
                    if self.limits.add_function():
                        return
                else:
                    return

        elif node.type == "method_definition":
            func = self._extract_method_definition(node)
            if func and self._should_include_function(func):
                if self.limits.can_add_function():
                    self.functions.append(func)
                    if self.limits.add_function():
                        return
                else:
                    return

        elif node.type == "pair":
            func = self._extract_object_method(node)
            if func and self._should_include_function(func):
                if self.limits.can_add_function():
                    self.functions.append(func)
                    if self.limits.add_function():
                        return
                else:
                    return

        elif node.type == "assignment_expression":
            func = self._extract_assignment_function(node)
            if func and self._should_include_function(func):
                if self.limits.can_add_function():
                    self.functions.append(func)
                    if self.limits.add_function():
                        return
                else:
                    return

        for child in node.children:
            if self.limits.should_stop():
                break
            self._traverse_for_functions(child)

    def _extract_function_declaration(self, node) -> Optional[Function]:
        """Extract regular function declaration: function name() {}"""
        try:
            name_node = self._find_child_by_type(node, "identifier")
            if not name_node:
                return None

            func_name = self._get_node_text(name_node)
            line_start = node.start_point[0] + 1
            line_end = node.end_point[0] + 1
            parameters = self._extract_parameters(node)
            code_snippet = self._get_node_text(node)

            return Function(
                name=func_name,
                file_path=str(self.file_path),
                line_start=line_start,
                line_end=line_end,
                parameters=parameters,
                docstring=None,
                is_method=False,
                class_name=None,
                code_snippet=code_snippet,
            )
        except Exception as e:
            logger.warning(f"Error extracting function declaration: {e}")
            return None

    def _extract_exported_function(self, node) -> Optional[Function]:
        """Extract export function or export default function"""
        try:
            func_decl = self._find_child_by_type(node, "function_declaration")
            if func_decl:
                func = self._extract_function_declaration(func_decl)
                if func:
                    export_text = self._get_node_text(node)
                    if "export default" in export_text and "function (" in export_text:
                        func.name = "default"
                return func
        except Exception as e:
            logger.warning(f"Error extracting exported function: {e}")
        return None

    def _extract_arrow_function_from_declaration(self, node) -> Optional[Function]:
        """Extract arrow function or function expression from const/let/var declarations"""
        try:
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = self._find_child_by_type(child, "identifier")
                    func_node = self._find_child_by_type(
                        child, "arrow_function"
                    ) or self._find_child_by_type(child, "function_expression")

                    if name_node and func_node:
                        func_name = self._get_node_text(name_node)
                        line_start = func_node.start_point[0] + 1
                        line_end = func_node.end_point[0] + 1
                        parameters = self._extract_parameters(func_node)
                        code_snippet = self._get_node_text(child)

                        return Function(
                            name=func_name,
                            file_path=str(self.file_path),
                            line_start=line_start,
                            line_end=line_end,
                            parameters=parameters,
                            docstring=None,
                            is_method=False,
                            class_name=None,
                            code_snippet=code_snippet,
                        )
        except Exception as e:
            logger.warning(f"Error extracting function from declaration: {e}")
        return None

    def _extract_method_definition(self, node) -> Optional[Function]:
        """Extract class method definition"""
        try:
            property_name = self._find_child_by_type(node, "property_identifier")
            if not property_name:
                return None

            func_name = self._get_node_text(property_name)
            line_start = node.start_point[0] + 1
            line_end = node.end_point[0] + 1
            parameters = self._extract_parameters(node)
            code_snippet = self._get_node_text(node)
            class_name = self._find_containing_class_name(node)

            return Function(
                name=func_name,
                file_path=str(self.file_path),
                line_start=line_start,
                line_end=line_end,
                parameters=parameters,
                docstring=None,
                is_method=True,
                class_name=class_name,
                code_snippet=code_snippet,
            )
        except Exception as e:
            logger.warning(f"Error extracting method definition: {e}")
            return None

    def _should_include_function(self, func: Function) -> bool:
        """Determine if a function should be included in the analysis."""
        excluded_names = {
            "constructor",
        }

        if func.name.lower() in excluded_names:
            logger.debug(f"Skipping excluded function: {func.name}")
            return False

        return True

    def _extract_parameters(self, node) -> List[str]:
        """Extract parameter names from a function node."""
        parameters = []
        params_node = self._find_child_by_type(node, "formal_parameters")
        if params_node:
            for child in params_node.children:
                if child.type == "identifier":
                    parameters.append(self._get_node_text(child))
        return parameters

    def _extract_call_relationships(self, node) -> None:
        """Extract function call relationships from the AST."""
        func_ranges = {}
        for func in self.functions:
            for line in range(func.line_start, func.line_end + 1):
                func_ranges[line] = func

        self._traverse_for_calls(node, func_ranges)

    def _traverse_for_calls(self, node, func_ranges: dict) -> None:
        """Recursively find function calls."""

        if node.type == "call_expression":
            call_info = self._extract_call_from_node(node, func_ranges)
            if call_info:
                if self.limits.can_add_relationship():
                    self.call_relationships.append(call_info)
                    if self.limits.add_relationship():
                        return
                else:
                    return

        for child in node.children:
            if self.limits.should_stop():
                break
            self._traverse_for_calls(child, func_ranges)

    def _extract_call_from_node(self, node, func_ranges: dict) -> Optional[CallRelationship]:
        """Extract call relationship from a call_expression node."""
        try:
            call_line = node.start_point[0] + 1
            caller_func = func_ranges.get(call_line)

            if not caller_func:
                return None

            callee_name = self._extract_callee_name(node)
            if not callee_name or self._is_builtin_function(callee_name):
                return None

            caller_id = f"{self.file_path}:{caller_func.name}"
            return CallRelationship(
                caller=caller_id,
                callee=callee_name,
                call_line=call_line,
                is_resolved=False,
            )
        except Exception as e:
            logger.warning(f"Error extracting call relationship: {e}")
            return None

    def _extract_callee_name(self, call_node) -> Optional[str]:
        """Extract the name of the called function."""
        if call_node.children:
            callee_node = call_node.children[0]

            if callee_node.type == "identifier":
                return self._get_node_text(callee_node)
            elif callee_node.type == "member_expression":
                property_node = self._find_child_by_type(callee_node, "property_identifier")
                if property_node:
                    return self._get_node_text(property_node)
        return None

    def _is_builtin_function(self, name: str) -> bool:
        """Check if function name is a JavaScript built-in."""
        builtins = {
            "setTimeout",
            "setInterval",
            "clearTimeout",
            "clearInterval",
            "parseInt",
            "parseFloat",
            "isNaN",
            "isFinite",
            "encodeURIComponent",
            "decodeURIComponent",
            "eval",
            "require",
        }
        return name in builtins

    def _find_child_by_type(self, node, node_type: str):
        """Find first child node of specified type."""
        for child in node.children:
            if child.type == node_type:
                return child
        return None

    def _get_node_text(self, node) -> str:
        """Get the text content of a node."""
        start_byte = node.start_byte
        end_byte = node.end_byte
        return self.content.encode("utf8")[start_byte:end_byte].decode("utf8")

    def _find_containing_class_name(self, method_node) -> Optional[str]:
        """Find the name of the class containing a method."""
        current = method_node.parent
        while current:
            if current.type == "class_declaration":
                name_node = self._find_child_by_type(current, "identifier")
                if name_node:
                    return self._get_node_text(name_node)
            current = current.parent
        return None

    def _extract_object_method(self, node) -> Optional[Function]:
        """Extract method from object literal: { method() {} } or { method: function() {} }"""
        try:
            key_node = None
            value_node = None

            for child in node.children:
                if child.type in ["property_identifier", "identifier"]:
                    key_node = child
                elif child.type in ["function_expression", "arrow_function"]:
                    value_node = child
                elif child.type == "function_signature":
                    value_node = node

            if key_node and value_node:
                func_name = self._get_node_text(key_node)
                line_start = value_node.start_point[0] + 1
                line_end = value_node.end_point[0] + 1

                if value_node == node:
                    parameters = self._extract_parameters(node)
                else:
                    parameters = self._extract_parameters(value_node)

                code_snippet = self._get_node_text(node)

                return Function(
                    name=func_name,
                    file_path=str(self.file_path),
                    line_start=line_start,
                    line_end=line_end,
                    parameters=parameters,
                    docstring=None,
                    is_method=False,
                    class_name=None,
                    code_snippet=code_snippet,
                )
        except Exception as e:
            logger.warning(f"Error extracting object method: {e}")
        return None

    def _extract_assignment_function(self, node) -> Optional[Function]:
        """Extract function from assignment: obj.method = function() {}"""
        try:
            left_node = None
            right_node = None

            for child in node.children:
                if child.type in ["member_expression", "identifier"]:
                    left_node = child
                elif child.type in ["function_expression", "arrow_function"]:
                    right_node = child

            if left_node and right_node:
                func_name = self._extract_assignment_name(left_node)
                if func_name:
                    line_start = right_node.start_point[0] + 1
                    line_end = right_node.end_point[0] + 1
                    parameters = self._extract_parameters(right_node)
                    code_snippet = self._get_node_text(node)

                    return Function(
                        name=func_name,
                        file_path=str(self.file_path),
                        line_start=line_start,
                        line_end=line_end,
                        parameters=parameters,
                        docstring=None,
                        is_method=False,
                        class_name=None,
                        code_snippet=code_snippet,
                    )
        except Exception as e:
            logger.warning(f"Error extracting assignment function: {e}")
        return None

    def _extract_assignment_name(self, node) -> Optional[str]:
        """Extract function name from assignment left side."""
        if node.type == "identifier":
            return self._get_node_text(node)
        elif node.type == "member_expression":
            property_node = self._find_child_by_type(node, "property_identifier")
            if property_node:
                return self._get_node_text(property_node)
        return None


class TreeSitterTSAnalyzer(TreeSitterJSAnalyzer):
    """TypeScript analyzer using tree-sitter."""

    def __init__(self, file_path: str, content: str, limits: Optional[AnalysisLimits] = None):
        self.file_path = Path(file_path)
        self.content = content
        self.functions: List[Function] = []
        self.call_relationships: List[CallRelationship] = []
        self.limits = limits or create_javascript_limits()

        try:
            language_capsule = tree_sitter_typescript.language_typescript()
            self.ts_language = Language(language_capsule)
            self.parser = Parser(self.ts_language)
            logger.debug(
                f"TypeScript parser initialized with language object: {type(self.ts_language)}"
            )

            test_code = "function test(): void { console.log('test'); }"
            test_tree = self.parser.parse(bytes(test_code, "utf8"))
            if test_tree is None or test_tree.root_node is None:
                raise RuntimeError("Parser setup test failed for TypeScript")
            logger.debug(
                f"TypeScript parser test successful - root node type: {test_tree.root_node.type}"
            )

        except Exception as e:
            logger.error(f"Failed to initialize TypeScript parser: {e}")
            self.parser = None
            self.ts_language = None

        logger.info(f"TreeSitterTSAnalyzer initialized for {file_path} with limits: {self.limits}")


# Integration functions
def analyze_javascript_file_treesitter(
    file_path: str, content: str, limits: Optional[AnalysisLimits] = None
) -> tuple[List[Function], List[CallRelationship]]:
    """Analyze a JavaScript file using tree-sitter."""
    try:
        logger.info(f"Tree-sitter JS analysis for {file_path}")
        if limits is None:
            limits = create_javascript_limits()
        analyzer = TreeSitterJSAnalyzer(file_path, content, limits)
        analyzer.analyze()
        logger.info(
            f"Found {len(analyzer.functions)} functions, {len(analyzer.call_relationships)} calls, {limits.nodes_processed} nodes processed"
        )
        return analyzer.functions, analyzer.call_relationships
    except Exception as e:
        logger.error(f"Error in tree-sitter JS analysis for {file_path}: {e}", exc_info=True)
        return [], []


def analyze_typescript_file_treesitter(
    file_path: str, content: str, limits: Optional[AnalysisLimits] = None
) -> tuple[List[Function], List[CallRelationship]]:
    """Analyze a TypeScript file using tree-sitter."""
    try:
        logger.info(f"Tree-sitter TS analysis for {file_path}")
        if limits is None:
            limits = create_javascript_limits()
        analyzer = TreeSitterTSAnalyzer(file_path, content, limits)
        analyzer.analyze()
        logger.info(
            f"Found {len(analyzer.functions)} functions, {len(analyzer.call_relationships)} calls, {limits.nodes_processed} nodes processed"
        )
        return analyzer.functions, analyzer.call_relationships
    except Exception as e:
        logger.error(f"Error in tree-sitter TS analysis for {file_path}: {e}", exc_info=True)
        return [], []
