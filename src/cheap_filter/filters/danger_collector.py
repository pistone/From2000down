"""Danger Collector: find all deallocation and raw-pointer-use sites via Clang AST.

This is the "collect everything dangerous" half of the inverted filter.
The SafePatternExcluder then subtracts known-safe patterns.

Requires: pip install libclang
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

try:
    from clang.cindex import (
        Config,
        CursorKind,
        Index,
        TranslationUnit,
        TypeKind,
    )
except ImportError:
    raise ImportError(
        "libclang is required: pip install libclang\n"
        "You may also need to set the library path:\n"
        "  import clang.cindex; clang.cindex.Config.set_library_file('/path/to/libclang.so')"
    )

from .base import VulnClass

log = logging.getLogger(__name__)

# Functions that deallocate memory
DEALLOC_FUNCTIONS = frozenset({
    "free", "cfree", "realloc",
    "g_free", "g_slice_free",             # GLib
    "js_free", "JS_free",                 # SpiderMonkey
    "PR_Free", "PR_DELETE",               # NSPR (Mozilla)
    "moz_free", "free_",
})

# Methods on smart pointers / containers that release ownership
RELEASE_METHODS = frozenset({
    "release", "reset",
})

# Smart pointer types (we'll mark these as "safe owner")
SMART_PTR_TYPES = frozenset({
    "unique_ptr", "shared_ptr", "weak_ptr",
    "RefPtr", "nsCOMPtr", "nsRefPtr",     # Mozilla
    "UniquePtr", "RefCounted",
    "already_AddRefed",
})


@dataclass
class DangerousSite:
    """A single dangerous operation found in the AST."""
    file: Path
    line: int
    column: int
    kind: str                # "free", "delete", "raw_deref", "raw_ptr_decl"
    enclosing_function: str  # name of the function containing this site
    pointer_name: str | None = None  # name of the pointer involved, if known
    is_in_destructor: bool = False
    source_text: str = ""    # raw source text of the node (short)
    context: dict = field(default_factory=dict)  # extra info for the excluder


class DangerCollector:
    """Walk a Clang AST and collect all deallocation / raw-pointer-use sites."""

    def __init__(self, extra_args: list[str] | None = None) -> None:
        self._index = Index.create()
        self._extra_args = extra_args or ["-std=c++17", "-x", "c++"]

    def collect(self, path: Path) -> list[DangerousSite]:
        """Parse a single file and return all dangerous sites."""
        try:
            tu = self._index.parse(
                str(path),
                args=self._extra_args,
                options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
            )
        except Exception as e:
            log.warning("Failed to parse %s: %s", path, e)
            return []

        sites: list[DangerousSite] = []
        self._walk(tu.cursor, path, sites)
        return sites

    def _walk(self, cursor, source_path: Path, sites: list[DangerousSite]) -> None:
        """Recursive AST walk."""
        # Skip nodes from included headers
        if cursor.location.file and Path(str(cursor.location.file)).resolve() != source_path.resolve():
            # Still walk children — macros can expand from headers into our file
            for child in cursor.get_children():
                self._walk(child, source_path, sites)
            return

        # --- Check for dangerous operations ---

        if cursor.kind == CursorKind.CALL_EXPR:
            self._check_call(cursor, source_path, sites)

        elif cursor.kind == CursorKind.CXX_DELETE_EXPR:
            self._check_delete(cursor, source_path, sites)

        elif cursor.kind == CursorKind.VAR_DECL:
            self._check_raw_ptr_decl(cursor, source_path, sites)

        # Recurse into children
        for child in cursor.get_children():
            self._walk(child, source_path, sites)

    def _check_call(self, cursor, source_path: Path, sites: list[DangerousSite]) -> None:
        """Check if a CALL_EXPR is a deallocation function."""
        name = cursor.spelling or ""

        # Direct deallocation: free(), cfree(), etc.
        if name in DEALLOC_FUNCTIONS:
            ptr_name = self._get_first_arg_name(cursor)
            sites.append(DangerousSite(
                file=source_path,
                line=cursor.location.line,
                column=cursor.location.column,
                kind="free",
                enclosing_function=self._enclosing_func(cursor),
                pointer_name=ptr_name,
                is_in_destructor=self._is_in_destructor(cursor),
                source_text=self._node_text(cursor),
            ))

        # Smart pointer .release() / .reset() — ownership transfer, raw ptr exposed
        elif name in RELEASE_METHODS:
            sites.append(DangerousSite(
                file=source_path,
                line=cursor.location.line,
                column=cursor.location.column,
                kind="release",
                enclosing_function=self._enclosing_func(cursor),
                pointer_name=self._get_receiver_name(cursor),
                source_text=self._node_text(cursor),
                context={"method": name},
            ))

    def _check_delete(self, cursor, source_path: Path, sites: list[DangerousSite]) -> None:
        """Handle CXX_DELETE_EXPR."""
        ptr_name = self._get_first_child_name(cursor)
        sites.append(DangerousSite(
            file=source_path,
            line=cursor.location.line,
            column=cursor.location.column,
            kind="delete",
            enclosing_function=self._enclosing_func(cursor),
            pointer_name=ptr_name,
            is_in_destructor=self._is_in_destructor(cursor),
            source_text=self._node_text(cursor),
        ))

    def _check_raw_ptr_decl(self, cursor, source_path: Path, sites: list[DangerousSite]) -> None:
        """Check if a VAR_DECL is a raw pointer (not a smart pointer)."""
        ty = cursor.type
        if ty.kind != TypeKind.POINTER:
            return

        # Ignore if the pointee is const char* (string literals, harmless)
        pointee = ty.get_pointee()
        if pointee.is_const_qualified() and pointee.spelling in ("char", "const char"):
            return

        # Check if this is actually inside a smart pointer template — skip those
        type_spelling = ty.spelling
        if any(sp in type_spelling for sp in SMART_PTR_TYPES):
            return

        sites.append(DangerousSite(
            file=source_path,
            line=cursor.location.line,
            column=cursor.location.column,
            kind="raw_ptr_decl",
            enclosing_function=self._enclosing_func(cursor),
            pointer_name=cursor.spelling,
            source_text=self._node_text(cursor),
        ))

    # --- Helpers ---

    @staticmethod
    def _enclosing_func(cursor) -> str:
        """Walk up to find the enclosing function/method name."""
        parent = cursor.semantic_parent
        while parent:
            if parent.kind in (
                CursorKind.FUNCTION_DECL,
                CursorKind.CXX_METHOD,
                CursorKind.CONSTRUCTOR,
                CursorKind.DESTRUCTOR,
            ):
                return parent.spelling
            parent = parent.semantic_parent
        return "<global>"

    @staticmethod
    def _is_in_destructor(cursor) -> bool:
        parent = cursor.semantic_parent
        while parent:
            if parent.kind == CursorKind.DESTRUCTOR:
                return True
            parent = parent.semantic_parent
        return False

    @staticmethod
    def _get_first_arg_name(call_cursor) -> str | None:
        """Get the name of the first argument to a call (e.g., free(ptr) → 'ptr')."""
        children = list(call_cursor.get_children())
        if len(children) >= 2:
            arg = children[1]  # children[0] is the callee reference
            if arg.kind == CursorKind.DECL_REF_EXPR:
                return arg.spelling
            # Might be a cast or member expr — try deeper
            for sub in arg.get_children():
                if sub.kind == CursorKind.DECL_REF_EXPR:
                    return sub.spelling
        return None

    @staticmethod
    def _get_first_child_name(cursor) -> str | None:
        for child in cursor.get_children():
            if child.kind == CursorKind.DECL_REF_EXPR:
                return child.spelling
            for sub in child.get_children():
                if sub.kind == CursorKind.DECL_REF_EXPR:
                    return sub.spelling
        return None

    @staticmethod
    def _get_receiver_name(call_cursor) -> str | None:
        """For a method call obj.release(), get 'obj'."""
        for child in call_cursor.get_children():
            if child.kind == CursorKind.MEMBER_REF_EXPR:
                for sub in child.get_children():
                    if sub.kind == CursorKind.DECL_REF_EXPR:
                        return sub.spelling
        return None

    @staticmethod
    def _node_text(cursor) -> str:
        """Get a short text representation of the node."""
        if cursor.extent:
            try:
                tu = cursor.translation_unit
                start = cursor.extent.start.offset
                end = cursor.extent.end.offset
                content = Path(str(cursor.location.file)).read_bytes()
                text = content[start:end].decode("utf-8", errors="replace")
                return text[:120]
            except Exception:
                pass
        return cursor.spelling or ""
