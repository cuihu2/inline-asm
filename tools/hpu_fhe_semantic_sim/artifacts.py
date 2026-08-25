from __future__ import annotations

from array import array
from dataclasses import dataclass
import hashlib
import json
import mmap
from os import PathLike
from pathlib import Path
import sys
from typing import Any, BinaryIO, Mapping


_REQUIRED_BINDING_FIELDS = frozenset(
    {
        "dma_index",
        "instruction_index",
        "direction",
        "line_offset",
        "line_count",
        "obj_id",
        "type_or_release",
        "flag",
        "payload_words",
    }
)
_OPTIONAL_BINDING_FIELDS = frozenset(
    {"domain", "role", "artifact_path", "expected_artifact"}
)
_INTEGER_BINDING_FIELDS = (
    "dma_index",
    "instruction_index",
    "line_offset",
    "line_count",
    "obj_id",
    "type_or_release",
    "flag",
    "payload_words",
)
_UINT32_MAX = (1 << 32) - 1
_WORDS_PER_LINE = 64
IO_CHUNK_BYTES = 4 * 1024 * 1024


def checksum_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(IO_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class WordDifference:
    word_index: int
    before: int
    after: int


@dataclass(frozen=True, slots=True)
class ArtifactDiff:
    size_bytes: int
    changed_words: int
    first_changed_word: int | None
    last_changed_word: int | None
    before_checksum: str
    after_checksum: str
    preview: tuple[WordDifference, ...]

    @property
    def identical(self) -> bool:
        return self.changed_words == 0


def _words_from_little_endian(raw: bytes) -> array[int]:
    words = array("I")
    if words.itemsize != 4:
        raise RuntimeError("array('I') does not use 32-bit elements on this platform")
    words.frombytes(raw)
    if sys.byteorder != "little":
        words.byteswap()
    return words


def _coerce_u32(values: Any) -> array[int]:
    words = array("I")
    if words.itemsize != 4:
        raise RuntimeError("array('I') does not use 32-bit elements on this platform")
    try:
        for index, value in enumerate(values):
            if type(value) is not int or not 0 <= value <= _UINT32_MAX:
                raise ValueError(f"word {index} must be an unsigned 32-bit integer")
            words.append(value)
    except TypeError as error:
        raise ValueError("u32 values must be an iterable of integers") from error
    return words


def _little_endian_bytes(words: array[int]) -> bytes:
    if sys.byteorder == "little":
        return words.tobytes()
    little_endian = array("I", words)
    little_endian.byteswap()
    return little_endian.tobytes()


def diff_files(
    before_path: str | Path,
    after_path: str | Path,
    preview_limit: int = 16,
) -> ArtifactDiff:
    if type(preview_limit) is not int or preview_limit < 0:
        raise ValueError("preview_limit must be a nonnegative integer")
    before_file_path = Path(before_path)
    after_file_path = Path(after_path)
    before_size = before_file_path.stat().st_size
    after_size = after_file_path.stat().st_size
    if before_size != after_size:
        raise ValueError("u32 images must have equal sizes for diff")
    if before_size % 4 != 0:
        raise ValueError("u32 image size must be a multiple of four bytes")

    before_digest = hashlib.sha256()
    after_digest = hashlib.sha256()
    changed_words = 0
    first_changed_word: int | None = None
    last_changed_word: int | None = None
    preview: list[WordDifference] = []
    byte_offset = 0
    with before_file_path.open("rb") as before_file:
        with after_file_path.open("rb") as after_file:
            while True:
                before_chunk = before_file.read(IO_CHUNK_BYTES)
                after_chunk = after_file.read(IO_CHUNK_BYTES)
                if not before_chunk:
                    break
                before_digest.update(before_chunk)
                after_digest.update(after_chunk)
                if before_chunk != after_chunk:
                    before_words = _words_from_little_endian(before_chunk)
                    after_words = _words_from_little_endian(after_chunk)
                    base_word = byte_offset // 4
                    for local_index, (before, after) in enumerate(
                        zip(before_words, after_words, strict=True)
                    ):
                        if before == after:
                            continue
                        word_index = base_word + local_index
                        changed_words += 1
                        if first_changed_word is None:
                            first_changed_word = word_index
                        last_changed_word = word_index
                        if len(preview) < preview_limit:
                            preview.append(WordDifference(word_index, before, after))
                byte_offset += len(before_chunk)

    return ArtifactDiff(
        size_bytes=before_size,
        changed_words=changed_words,
        first_changed_word=first_changed_word,
        last_changed_word=last_changed_word,
        before_checksum=before_digest.hexdigest(),
        after_checksum=after_digest.hexdigest(),
        preview=tuple(preview),
    )


def preview_hex(
    path: str | Path,
    start_word: int = 0,
    word_count: int = 16,
    words_per_row: int = 8,
) -> str:
    for field_name, value, allow_zero in (
        ("start_word", start_word, True),
        ("word_count", word_count, True),
        ("words_per_row", words_per_row, False),
    ):
        minimum = 0 if allow_zero else 1
        if type(value) is not int or value < minimum:
            raise ValueError(f"{field_name} must be an integer >= {minimum}")
    source_path = Path(path)
    size = source_path.stat().st_size
    if size % 4 != 0:
        raise ValueError("u32 file size must be a multiple of four bytes")
    total_words = size // 4
    if start_word > total_words:
        raise ValueError("start_word exceeds the u32 file")
    available_words = min(word_count, total_words - start_word)
    with source_path.open("rb") as source:
        source.seek(start_word * 4)
        raw = source.read(available_words * 4)
    words = _words_from_little_endian(raw)

    rows: list[str] = []
    for row_start in range(0, len(words), words_per_row):
        row = words[row_start : row_start + words_per_row]
        address = start_word + row_start
        rows.append(
            f"{address:08x}: " + " ".join(f"0x{word:08x}" for word in row)
        )
    return "\n".join(rows)


def read_u32(path: str | Path) -> array[int]:
    raw = Path(path).read_bytes()
    if len(raw) % 4 != 0:
        raise ValueError("u32 file size must be a multiple of four bytes")
    return _words_from_little_endian(raw)


def write_u32(path: str | Path, values: Any) -> None:
    words = _coerce_u32(values)
    with Path(path).open("xb") as output:
        output.write(_little_endian_bytes(words))


def _copy_with_mmap(source: Path, destination: Path) -> None:
    size = source.stat().st_size
    with source.open("rb") as source_file, destination.open("x+b") as destination_file:
        destination_file.truncate(size)
        with mmap.mmap(source_file.fileno(), 0, access=mmap.ACCESS_READ) as source_map:
            with mmap.mmap(
                destination_file.fileno(), 0, access=mmap.ACCESS_WRITE
            ) as destination_map:
                for offset in range(0, size, IO_CHUNK_BYTES):
                    end = min(offset + IO_CHUNK_BYTES, size)
                    destination_map[offset:end] = source_map[offset:end]
                destination_map.flush()


class ArtifactWorkspace:
    before_path: Path
    after_path: Path

    def __init__(
        self,
        before_path: Path,
        after_path: Path,
        after_file: BinaryIO,
        after_map: mmap.mmap,
    ) -> None:
        self.before_path = before_path
        self.after_path = after_path
        self._after_file = after_file
        self._after_map = after_map
        self._closed = False

    @classmethod
    def create(
        cls,
        source_image: str | Path,
        output_dir: str | Path,
    ) -> "ArtifactWorkspace":
        source_path = Path(source_image)
        if not source_path.is_file():
            raise ValueError(f"source image does not exist: {source_path}")
        source_size = source_path.stat().st_size
        if source_size == 0 or source_size % 4 != 0:
            raise ValueError("source image must contain one or more complete uint32 words")

        destination_dir = Path(output_dir)
        destination_dir.mkdir(exist_ok=False)
        before_path = destination_dir / "ddr_before.u32.bin"
        after_path = destination_dir / "ddr_after.u32.bin"
        _copy_with_mmap(source_path, before_path)
        _copy_with_mmap(before_path, after_path)

        after_file = after_path.open("r+b")
        try:
            after_map = mmap.mmap(after_file.fileno(), 0, access=mmap.ACCESS_WRITE)
        except Exception:
            after_file.close()
            raise
        return cls(before_path, after_path, after_file, after_map)

    def close(self) -> None:
        if self._closed:
            return
        self._after_map.flush()
        self._after_map.close()
        self._after_file.close()
        self._closed = True

    def _checked_span(self, line_offset: int, line_count: int) -> tuple[int, int]:
        if self._closed:
            raise ValueError("artifact workspace is closed")
        if type(line_offset) is not int or line_offset < 0:
            raise ValueError("line_offset must be a nonnegative integer")
        if type(line_count) is not int or line_count <= 0:
            raise ValueError("line_count must be a positive integer")
        start = line_offset * _WORDS_PER_LINE * 4
        end = start + line_count * _WORDS_PER_LINE * 4
        if end > len(self._after_map):
            raise ValueError("DMA span exceeds the current DDR image")
        return start, end

    def read_words(
        self,
        line_offset: int,
        line_count: int,
        payload_words: int | None = None,
    ) -> array[int]:
        start, _ = self._checked_span(line_offset, line_count)
        capacity_words = line_count * _WORDS_PER_LINE
        if payload_words is None:
            word_count = capacity_words
        else:
            if type(payload_words) is not int or not 0 <= payload_words <= capacity_words:
                raise ValueError("payload_words must fit inside the DMA span")
            word_count = payload_words
        raw = self._after_map[start : start + word_count * 4]
        return _words_from_little_endian(raw)

    def write_words(
        self,
        line_offset: int,
        line_count: int,
        values: Any,
    ) -> None:
        start, end = self._checked_span(line_offset, line_count)
        words = _coerce_u32(values)
        capacity_words = line_count * _WORDS_PER_LINE
        if not 1 <= len(words) <= capacity_words:
            raise ValueError("DSTORE words must be nonempty and fit inside the DMA span")
        raw = _little_endian_bytes(words)
        self._after_map[start : start + len(raw)] = raw
        padding_start = start + len(raw)
        if padding_start < end:
            zero_chunk = b"\x00" * min(IO_CHUNK_BYTES, end - padding_start)
            for offset in range(padding_start, end, len(zero_chunk)):
                chunk_end = min(offset + len(zero_chunk), end)
                self._after_map[offset:chunk_end] = zero_chunk[: chunk_end - offset]
        self._after_map.flush()


@dataclass(frozen=True, slots=True)
class ArtifactBinding:
    dma_index: int
    instruction_index: int
    direction: str
    line_offset: int
    line_count: int
    obj_id: int
    type_or_release: int
    flag: int
    payload_words: int
    domain: str = "raw"
    role: str = ""
    artifact_path: Path | None = None
    expected_artifact: Path | None = None

    def __post_init__(self) -> None:
        for field_name in _INTEGER_BINDING_FIELDS:
            if type(getattr(self, field_name)) is not int:
                raise ValueError(f"{field_name} must be an integer")
        if self.dma_index < 0:
            raise ValueError("dma_index must be nonnegative")
        if self.instruction_index < 0:
            raise ValueError("instruction_index must be nonnegative")
        if self.direction not in {"dload", "dstore"}:
            raise ValueError("direction must be dload or dstore")
        if not 0 <= self.line_offset <= _UINT32_MAX:
            raise ValueError("line_offset must fit uint32")
        if not 1 <= self.line_count <= _UINT32_MAX:
            raise ValueError("line_count must be a nonzero uint32")
        if not 0 <= self.obj_id <= 7:
            raise ValueError("obj_id must be in the range 0..7")
        if self.direction == "dload":
            if self.type_or_release not in {0, 1, 2}:
                raise ValueError("DLOAD type must be in the range 0..2")
            required_flag = 1 if self.type_or_release == 2 else 0
            if self.flag != required_flag:
                raise ValueError(
                    "DLOAD flag must select Bank 5 exactly for mod_ctx type 2"
                )
        else:
            if self.type_or_release not in {0, 1}:
                raise ValueError("DSTORE release must be 0 or 1")
            if self.flag != 0:
                raise ValueError("DSTORE flag must be zero")
        capacity_words = self.line_count * _WORDS_PER_LINE
        if not 1 <= self.payload_words <= capacity_words:
            raise ValueError(
                "payload_words must be positive and fit inside the DMA span"
            )
        if not isinstance(self.domain, str) or not self.domain.strip():
            raise ValueError("domain must be a nonempty string")
        if not isinstance(self.role, str):
            raise ValueError("role must be a string")
        for field_name in ("artifact_path", "expected_artifact"):
            path = getattr(self, field_name)
            if path is not None and (not isinstance(path, Path) or path == Path(".")):
                raise ValueError(f"{field_name} must name a file path or be null")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        base_dir: str | Path | None = None,
    ) -> "ArtifactBinding":
        if not isinstance(value, Mapping):
            raise ValueError("artifact binding must be a mapping")
        fields = set(value)
        missing = _REQUIRED_BINDING_FIELDS - fields
        unknown = fields - _REQUIRED_BINDING_FIELDS - _OPTIONAL_BINDING_FIELDS
        if missing:
            raise ValueError(
                "artifact binding is missing fields: " + ", ".join(sorted(missing))
            )
        if unknown:
            raise ValueError(
                "artifact binding has unknown fields: " + ", ".join(sorted(unknown))
            )
        for field_name in _INTEGER_BINDING_FIELDS:
            if type(value[field_name]) is not int:
                raise ValueError(f"{field_name} must be an integer")
        for field_name in ("direction", "domain", "role"):
            field_value = value.get(field_name, "")
            if not isinstance(field_value, str):
                raise ValueError(f"{field_name} must be a string")

        root = Path(base_dir) if base_dir is not None else None

        def optional_path(field_name: str) -> Path | None:
            raw_path = value.get(field_name)
            if raw_path is None:
                return None
            if not isinstance(raw_path, (str, PathLike)):
                raise ValueError(f"{field_name} must be a path string or null")
            if not str(raw_path).strip():
                raise ValueError(f"{field_name} must not be empty")
            path = Path(raw_path)
            if root is not None and not path.is_absolute():
                path = root / path
            return path

        return cls(
            dma_index=value["dma_index"],
            instruction_index=value["instruction_index"],
            direction=value["direction"],
            line_offset=value["line_offset"],
            line_count=value["line_count"],
            obj_id=value["obj_id"],
            type_or_release=value["type_or_release"],
            flag=value["flag"],
            payload_words=value["payload_words"],
            domain=value.get("domain", "raw"),
            role=value.get("role", ""),
            artifact_path=optional_path("artifact_path"),
            expected_artifact=optional_path("expected_artifact"),
        )


def load_bindings_json(path: str | Path) -> tuple[ArtifactBinding, ...]:
    manifest_path = Path(path)
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load binding JSON {manifest_path}: {error}") from error

    if isinstance(document, list):
        raw_bindings = document
    elif isinstance(document, dict):
        if set(document) != {"format_version", "bindings"}:
            raise ValueError(
                "binding JSON manifest fields must be format_version and bindings"
            )
        if type(document.get("format_version")) is not int or document["format_version"] != 1:
            raise ValueError("binding JSON object requires format_version 1 and bindings")
        raw_bindings = document["bindings"]
    else:
        raise ValueError("binding JSON must contain a list or manifest object")
    if not isinstance(raw_bindings, list):
        raise ValueError("bindings must be a list")

    bindings = tuple(
        ArtifactBinding.from_dict(raw, base_dir=manifest_path.parent)
        for raw in raw_bindings
    )
    previous_instruction_index = -1
    for expected_dma_index, binding in enumerate(bindings):
        if binding.dma_index != expected_dma_index:
            raise ValueError("dma_index values must be contiguous and start at zero")
        if binding.instruction_index <= previous_instruction_index:
            raise ValueError("instruction_index values must be strictly increasing")
        previous_instruction_index = binding.instruction_index
    return bindings
