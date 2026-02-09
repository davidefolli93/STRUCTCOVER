#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import html
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.dwarf_expr import DWARFExprParser

logger = logging.getLogger(__name__)


@dataclass
class MemberInfo:
    name: str
    type_name: str
    offset: Optional[int]
    size: Optional[int]


@dataclass
class HoleInfo:
    offset: int
    size: int
    kind: str  # hole or padding


@dataclass
class TypeInfo:
    type_id: str
    kind: str
    name: str
    display_name: str
    size: Optional[int]
    decl_file: Optional[Path]
    decl_line: Optional[int]
    members: List[MemberInfo] = field(default_factory=list)
    holes: List[HoleInfo] = field(default_factory=list)
    underlying: Optional[str] = None


@dataclass
class FileInfo:
    path: Path
    types: List[TypeInfo]


class TypeResolver:
    def __init__(self, dwarfinfo, preferred_names: Dict[int, str]):
        self.dwarfinfo = dwarfinfo
        self.preferred_names = preferred_names
        self.name_cache: Dict[int, str] = {}
        self.size_cache: Dict[int, Optional[int]] = {}

    def resolve_type_name(self, die) -> str:
        if die is None:
            return "void"
        if die.offset in self.name_cache:
            return self.name_cache[die.offset]
        tag = die.tag
        name = None
        if tag in {"DW_TAG_structure_type", "DW_TAG_union_type"}:
            name = self._named_struct(die, tag)
        elif tag == "DW_TAG_typedef":
            name = self._get_attr_str(die, "DW_AT_name") or "<anonymous typedef>"
        elif tag == "DW_TAG_pointer_type":
            base = self._resolve_type_attr(die)
            name = f"{base}*"
        elif tag == "DW_TAG_array_type":
            base = self._resolve_type_attr(die)
            count = self._array_count(die)
            suffix = "[]" if count is None else f"[{count}]"
            name = f"{base}{suffix}"
        elif tag == "DW_TAG_const_type":
            base = self._resolve_type_attr(die)
            name = f"const {base}"
        elif tag == "DW_TAG_volatile_type":
            base = self._resolve_type_attr(die)
            name = f"volatile {base}"
        elif tag == "DW_TAG_restrict_type":
            base = self._resolve_type_attr(die)
            name = f"restrict {base}"
        else:
            name = self._get_attr_str(die, "DW_AT_name") or tag.replace("DW_TAG_", "").replace("_type", "")
        self.name_cache[die.offset] = name
        return name

    def resolve_type_size(self, die, cu) -> Optional[int]:
        if die is None:
            return None
        if die.offset in self.size_cache:
            return self.size_cache[die.offset]
        size = None
        tag = die.tag
        if "DW_AT_byte_size" in die.attributes:
            size = die.attributes["DW_AT_byte_size"].value
        elif tag == "DW_TAG_pointer_type":
            size = cu.header["address_size"]
        elif tag == "DW_TAG_array_type":
            base_die = self._resolve_type_die(die)
            base_size = self.resolve_type_size(base_die, cu)
            count = self._array_count(die)
            if base_size is not None and count is not None:
                size = base_size * count
        elif tag in {"DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type", "DW_TAG_typedef"}:
            base_die = self._resolve_type_die(die)
            size = self.resolve_type_size(base_die, cu)
        self.size_cache[die.offset] = size
        return size

    def _resolve_type_attr(self, die) -> str:
        base_die = self._resolve_type_die(die)
        return self.resolve_type_name(base_die)

    def _resolve_type_die(self, die):
        attr = die.attributes.get("DW_AT_type")
        if not attr:
            return None
        return die.get_DIE_from_attribute("DW_AT_type")

    def _array_count(self, die) -> Optional[int]:
        for child in die.iter_children():
            if child.tag != "DW_TAG_subrange_type":
                continue
            count_attr = child.attributes.get("DW_AT_count")
            if count_attr is not None:
                return count_attr.value
            upper = child.attributes.get("DW_AT_upper_bound")
            if upper is not None:
                lower = child.attributes.get("DW_AT_lower_bound")
                lower_val = lower.value if lower is not None else 0
                return upper.value - lower_val + 1
        return None

    def _get_attr_str(self, die, attr) -> Optional[str]:
        if attr not in die.attributes:
            return None
        value = die.attributes[attr].value
        if isinstance(value, bytes):
            return value.decode(errors="replace")
        return str(value)

    def _named_struct(self, die, tag) -> str:
        name = self._get_attr_str(die, "DW_AT_name")
        if not name:
            preferred = self.preferred_names.get(die.offset)
            if preferred:
                return preferred
            label = "struct" if tag == "DW_TAG_structure_type" else "union"
            return f"<anonymous {label}>"
        return name


def parse_member_offset(attr, cu) -> Optional[int]:
    if attr is None:
        return None
    form_class = describe_form_class(attr.form)
    if form_class == "constant":
        return attr.value
    if form_class == "exprloc":
        parser = DWARFExprParser(cu.structs)
        ops = parser.parse_expr(attr.value)
        if len(ops) == 1 and ops[0].op_name in {"DW_OP_plus_uconst", "DW_OP_constu", "DW_OP_consts"}:
            return ops[0].args[0]
    return None


def type_id_for(cu_offset: int, die_offset: int) -> str:
    digest = hashlib.sha1(f"{cu_offset:x}:{die_offset:x}".encode()).hexdigest()
    return digest[:16]


def resolve_decl_path(cu, lineprog, file_index: int) -> Optional[Path]:
    if not lineprog or file_index == 0:
        return None
    file_entries = lineprog["file_entry"]
    if file_index - 1 >= len(file_entries):
        return None
    entry = file_entries[file_index - 1]
    name = entry.name.decode(errors="replace") if isinstance(entry.name, bytes) else str(entry.name)
    dir_name = ""
    if entry.dir_index != 0:
        dirs = lineprog["include_directory"]
        if entry.dir_index - 1 < len(dirs):
            dir_name = dirs[entry.dir_index - 1]
            if isinstance(dir_name, bytes):
                dir_name = dir_name.decode(errors="replace")
    comp_dir = cu.get_top_DIE().attributes.get("DW_AT_comp_dir")
    comp_dir_val = None
    if comp_dir:
        comp_dir_val = comp_dir.value.decode(errors="replace") if isinstance(comp_dir.value, bytes) else str(comp_dir.value)
    parts = []
    if dir_name:
        parts.append(dir_name)
    parts.append(name)
    path = Path(*parts)
    if not path.is_absolute() and comp_dir_val:
        path = Path(comp_dir_val) / path
    return path


def collect_types(elf_path: Path) -> Tuple[List[TypeInfo], Dict[int, str]]:
    with elf_path.open("rb") as handle:
        elf = ELFFile(handle)
        if not elf.has_dwarf_info():
            raise ValueError("ELF has no DWARF info")
        dwarfinfo = elf.get_dwarf_info()
        preferred_names: Dict[int, str] = {}
        typedef_targets: List[Tuple[int, str]] = []
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_typedef" and "DW_AT_type" in die.attributes:
                    target = die.get_DIE_from_attribute("DW_AT_type")
                    if target and target.tag in {"DW_TAG_structure_type", "DW_TAG_union_type"}:
                        name_attr = die.attributes.get("DW_AT_name")
                        if name_attr:
                            name = name_attr.value.decode(errors="replace") if isinstance(name_attr.value, bytes) else str(name_attr.value)
                            typedef_targets.append((target.offset, name))
        for offset, name in typedef_targets:
            preferred_names.setdefault(offset, name)

        resolver = TypeResolver(dwarfinfo, preferred_names)
        types: List[TypeInfo] = []

        for cu in dwarfinfo.iter_CUs():
            lineprog = dwarfinfo.line_program_for_CU(cu)
            for die in cu.iter_DIEs():
                if die.tag not in {"DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_typedef"}:
                    continue
                name = resolver.resolve_type_name(die)
                display_name = name
                size = resolver.resolve_type_size(die, cu)
                decl_file = None
                decl_line = None
                if "DW_AT_decl_file" in die.attributes:
                    decl_file = resolve_decl_path(cu, lineprog, die.attributes["DW_AT_decl_file"].value)
                if "DW_AT_decl_line" in die.attributes:
                    decl_line = die.attributes["DW_AT_decl_line"].value
                kind = "typedef" if die.tag == "DW_TAG_typedef" else "struct" if die.tag == "DW_TAG_structure_type" else "union"
                type_id = type_id_for(cu.cu_offset, die.offset)
                info = TypeInfo(
                    type_id=type_id,
                    kind=kind,
                    name=name,
                    display_name=display_name,
                    size=size,
                    decl_file=decl_file,
                    decl_line=decl_line,
                )
                if die.tag in {"DW_TAG_structure_type", "DW_TAG_union_type"}:
                    for child in die.iter_children():
                        if child.tag != "DW_TAG_member":
                            continue
                        member_name = resolver._get_attr_str(child, "DW_AT_name") or "<anon>"
                        member_type_die = child.get_DIE_from_attribute("DW_AT_type")
                        member_type_name = resolver.resolve_type_name(member_type_die)
                        member_size = resolver.resolve_type_size(member_type_die, cu)
                        offset = parse_member_offset(child.attributes.get("DW_AT_data_member_location"), cu)
                        info.members.append(
                            MemberInfo(
                                name=member_name,
                                type_name=member_type_name,
                                offset=offset,
                                size=member_size,
                            )
                        )
                    if info.kind == "struct":
                        info.holes = compute_holes(info.size, info.members)
                elif die.tag == "DW_TAG_typedef":
                    base_die = die.get_DIE_from_attribute("DW_AT_type")
                    info.underlying = resolver.resolve_type_name(base_die)
                types.append(info)
    return types, preferred_names


def compute_holes(struct_size: Optional[int], members: Iterable[MemberInfo]) -> List[HoleInfo]:
    if struct_size is None:
        return []
    spans = []
    for member in members:
        if member.offset is None or member.size is None:
            continue
        spans.append((member.offset, member.offset + member.size))
    if not spans:
        return []
    spans.sort()
    holes: List[HoleInfo] = []
    cursor = 0
    for start, end in spans:
        if start > cursor:
            hole_size = start - cursor
            kind = "hole"
            holes.append(HoleInfo(offset=cursor, size=hole_size, kind=kind))
        cursor = max(cursor, end)
    if cursor < struct_size:
        holes.append(HoleInfo(offset=cursor, size=struct_size - cursor, kind="padding"))
    return holes


def max_struct_size(types: Iterable[TypeInfo]) -> Optional[int]:
    sizes = [t.size for t in types if t.kind == "struct" and t.size is not None]
    return max(sizes) if sizes else None


def html_page(title: str, body: str) -> str:
    style = """
    <style>
    body { font-family: Arial, sans-serif; background:#111; color:#eee; margin:0; padding:0 24px; }
    a { color: #8ab4f8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0; }
    th, td { border-bottom: 1px solid #333; padding: 8px; text-align: left; }
    th { background: #1e1e1e; }
    .breadcrumbs { margin: 16px 0; font-size: 0.9em; color: #bbb; }
    .chip { padding: 2px 6px; border-radius: 4px; background: #333; font-size: 0.85em; }
    .hole { color: #ff7b7b; }
    .padding { color: #f2d675; }
    </style>
    """
    return f"""<!doctype html>
<html>
<head>
<meta charset=\"utf-8\" />
<title>{html.escape(title)}</title>
{style}
</head>
<body>
{body}
</body>
</html>"""


def render_breadcrumbs(items: List[Tuple[str, str]]) -> str:
    parts = []
    for label, href in items:
        parts.append(f"<a href=\"{href}\">{html.escape(label)}</a>")
    return f"<div class=\"breadcrumbs\">{' / '.join(parts)}</div>"


def render_index(out_dir: Path, has_tree: bool):
    links = ["<ul>"]
    if has_tree:
        links.append("<li><a href=\"dir/index.html\">Source tree</a></li>")
    links.append("<li><a href=\"external/index.html\">External types</a></li>")
    links.append("</ul>")
    body = render_breadcrumbs([("Index", "index.html")])
    body += "<h1>StructCover Report</h1>" + "\n".join(links)
    out_dir.joinpath("index.html").write_text(html_page("StructCover Report", body))


def render_external(out_dir: Path, external_types: List[TypeInfo]):
    rows = []
    for info in external_types[:200]:
        file_path = html.escape(str(info.decl_file) if info.decl_file else "—")
        size = "—" if info.size is None else str(info.size)
        rows.append(
            f"<tr><td>{file_path}</td><td>{html.escape(info.display_name)}</td><td>{info.kind}</td><td>{size}</td></tr>"
        )
    table = (
        "<table><thead><tr><th>File</th><th>Type</th><th>Kind</th><th>Size</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )
    body = render_breadcrumbs([("Index", "../index.html"), ("External types", "index.html")])
    body += "<h1>External types</h1>" + table
    out_path = out_dir / "external" / "index.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_page("External types", body))


def render_file_page(out_dir: Path, file_info: FileInfo, rel_path: Path):
    types = sorted(file_info.types, key=lambda t: (-(t.size or 0), t.display_name))
    rows = []
    for info in types:
        size = "—" if info.size is None else str(info.size)
        hole_count = len([h for h in info.holes if h.kind == "hole"]) if info.kind == "struct" else "—"
        rows.append(
            "<tr>"
            f"<td><a href=\"../type/{info.type_id}.html\">{html.escape(info.display_name)}</a></td>"
            f"<td>{info.kind}</td><td>{size}</td><td>{hole_count}</td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr><th>Type</th><th>Kind</th><th>Size</th><th>Holes</th></tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )
    body = render_breadcrumbs(
        [
            ("Index", "../index.html"),
            ("Source tree", "../dir/index.html"),
            (str(rel_path), f"../file/{rel_path.as_posix()}.html"),
        ]
    )
    body += f"<h1>{html.escape(str(rel_path))}</h1>" + table
    out_path = out_dir / "file" / rel_path
    out_path = out_path.with_suffix(out_path.suffix + ".html")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_page(f"File {rel_path}", body))


def render_type_page(out_dir: Path, info: TypeInfo):
    size = "—" if info.size is None else str(info.size)
    decl = "—"
    if info.decl_file:
        decl = html.escape(str(info.decl_file))
        if info.decl_line:
            decl += f":{info.decl_line}"
    body = render_breadcrumbs([("Index", "../index.html"), ("Type", f"../type/{info.type_id}.html")])
    body += f"<h1>{html.escape(info.display_name)}</h1>"
    body += (
        f"<p><span class=\"chip\">{info.kind}</span> Size: {size} bytes<br />"
        f"Declared at: {decl}</p>"
    )
    if info.kind == "typedef" and info.underlying:
        body += f"<p>Underlying type: {html.escape(info.underlying)}</p>"
    if info.members:
        rows = []
        for member in info.members:
            offset = "—" if member.offset is None else str(member.offset)
            msize = "—" if member.size is None else str(member.size)
            rows.append(
                "<tr>"
                f"<td>{html.escape(member.name)}</td><td>{html.escape(member.type_name)}</td>"
                f"<td>{offset}</td><td>{msize}</td>"
                "</tr>"
            )
        body += (
            "<h2>Members</h2>"
            "<table><thead><tr><th>Name</th><th>Type</th><th>Offset</th><th>Size</th></tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )
    if info.holes:
        rows = []
        for hole in info.holes:
            cls = "hole" if hole.kind == "hole" else "padding"
            rows.append(
                f"<tr class=\"{cls}\"><td>{hole.offset}</td><td>{hole.size}</td><td>{hole.kind}</td></tr>"
            )
        body += (
            "<h2>Holes & padding</h2>"
            "<table><thead><tr><th>Offset</th><th>Size</th><th>Kind</th></tr></thead><tbody>"
            + "\n".join(rows)
            + "</tbody></table>"
        )
    out_path = out_dir / "type" / f"{info.type_id}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_page(f"Type {info.display_name}", body))


def build_tree(src_root: Path, files: Dict[Path, FileInfo]) -> Dict[Path, Dict[str, List[Path]]]:
    tree: Dict[Path, Dict[str, List[Path]]] = {}
    for rel_path in files:
        current = Path(".")
        parts = rel_path.parts
        for idx, part in enumerate(parts[:-1]):
            current = current / part
            tree.setdefault(current, {"dirs": [], "files": []})
            next_dir = current / parts[idx + 1] if idx + 1 < len(parts) else None
            if next_dir and next_dir not in tree[current]["dirs"]:
                tree[current]["dirs"].append(next_dir)
        tree.setdefault(Path("."), {"dirs": [], "files": []})
        if rel_path.parent == Path("."):
            parent = Path(".")
        else:
            parent = rel_path.parent
        tree.setdefault(parent, {"dirs": [], "files": []})
        if rel_path not in tree[parent]["files"]:
            tree[parent]["files"].append(rel_path)
        for i in range(1, len(parts)):
            dir_path = Path(*parts[:i])
            tree.setdefault(dir_path, {"dirs": [], "files": []})
    if not tree:
        tree[Path(".")] = {"dirs": [], "files": []}
    return tree


def render_tree_pages(out_dir: Path, src_root: Path, files: Dict[Path, FileInfo]):
    tree = build_tree(src_root, files)
    dir_sizes: Dict[Path, Optional[int]] = {}

    for rel_path, info in files.items():
        size = max_struct_size(info.types)
        dir_sizes[rel_path] = size

    for dir_path in sorted(tree.keys(), key=lambda p: str(p)):
        max_size = None
        for file_rel, info in files.items():
            if dir_path == Path(".") or str(file_rel).startswith(str(dir_path)):
                file_max = max_struct_size(info.types)
                if file_max is not None:
                    max_size = file_max if max_size is None else max(max_size, file_max)
        dir_sizes[dir_path] = max_size

    for dir_path, content in tree.items():
        items = []
        for child_dir in sorted(content["dirs"], key=lambda p: str(p)):
            size = dir_sizes.get(child_dir)
            size_label = "—" if size is None else str(size)
            items.append(
                f"<tr><td><a href=\"../dir/{child_dir.as_posix()}/index.html\">{child_dir.name}/</a></td><td>{size_label}</td></tr>"
            )
        for file_rel in sorted(content["files"], key=lambda p: str(p)):
            size = max_struct_size(files[file_rel].types)
            size_label = "—" if size is None else str(size)
            items.append(
                f"<tr><td><a href=\"../file/{file_rel.as_posix()}.html\">{file_rel.name}</a></td><td>{size_label}</td></tr>"
            )
        table = (
            "<table><thead><tr><th>Name</th><th>Max struct size</th></tr></thead><tbody>"
            + "\n".join(items)
            + "</tbody></table>"
        )
        breadcrumbs = [("Index", "../index.html"), ("Source tree", "../dir/index.html")]
        if dir_path != Path("."):
            parts = dir_path.parts
            path_accum = Path(".")
            for part in parts:
                path_accum = path_accum / part
                breadcrumbs.append((part, f"../dir/{path_accum.as_posix()}/index.html"))
        body = render_breadcrumbs(breadcrumbs)
        display_name = "/" if dir_path == Path(".") else dir_path.as_posix()
        body += f"<h1>{html.escape(display_name)}</h1>" + table
        out_path = out_dir / "dir" / dir_path / "index.html"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(html_page(f"Dir {display_name}", body))


def build_report(
    elf_path: Path,
    out_dir: Path,
    src_root: Optional[Path],
    log_sample: int,
    log_paths: bool,
):
    types, _ = collect_types(elf_path)
    logger.info("Collected %d types from %s", len(types), elf_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    files: Dict[Path, FileInfo] = {}
    external_types: List[TypeInfo] = []
    if src_root:
        src_root = src_root.resolve()
        logger.info("Resolved src-root to %s", src_root)
    for info in types:
        if info.decl_file and src_root:
            try:
                rel = info.decl_file.resolve().relative_to(src_root)
            except ValueError:
                external_types.append(info)
                continue
            files.setdefault(rel, FileInfo(path=info.decl_file, types=[])).types.append(info)
        elif src_root:
            external_types.append(info)
        else:
            external_types.append(info)

    logger.info("Mapped %d source files", len(files))
    logger.info("Classified %d external types", len(external_types))
    if src_root and not files:
        logger.warning("No source files mapped under src-root; source tree will be empty.")
    if log_paths:
        for rel, info in files.items():
            logger.debug("Source file: %s (%d types)", rel, len(info.types))
        for idx, info in enumerate(external_types[:log_sample]):
            logger.debug(
                "External type sample [%d/%d]: %s (%s)",
                idx + 1,
                len(external_types),
                info.display_name,
                info.decl_file if info.decl_file else "no decl file",
            )

    for info in types:
        render_type_page(out_dir, info)

    if src_root:
        for rel_path, info in files.items():
            render_file_page(out_dir, info, rel_path)
        render_tree_pages(out_dir, src_root, files)
        logger.info("Rendered %d file pages and source tree", len(files))

    render_external(out_dir, external_types)
    render_index(out_dir, has_tree=bool(src_root))
    logger.info("Rendered external index and report index")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate struct layout report from DWARF info")
    parser.add_argument("elf", type=Path, help="Path to ELF file")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    parser.add_argument("--src-root", type=Path, help="Source root directory")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    parser.add_argument("--log-file", type=Path, help="Write logs to this file instead of stderr")
    parser.add_argument(
        "--log-sample",
        type=int,
        default=5,
        help="How many external type samples to log (default: 5)",
    )
    parser.add_argument(
        "--log-paths",
        action="store_true",
        help="Log mapped source file paths and external type samples",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.elf.exists():
        raise SystemExit(f"ELF not found: {args.elf}")
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        filename=str(args.log_file) if args.log_file else None,
        format="%(levelname)s %(message)s",
    )
    build_report(args.elf, args.out, args.src_root, args.log_sample, args.log_paths)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
