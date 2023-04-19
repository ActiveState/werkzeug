from typing import Collection
from typing import FrozenSet
from typing import Iterable
from typing import Iterator
from typing import Optional
from typing import Set

class ETags(Collection[str]):
    _strong: FrozenSet[str]
    _weak: FrozenSet[str]
    star_tag: bool
    def __init__(
        self,
        strong_etags: Optional[Iterable[str]] = None,
        weak_etags: Optional[Iterable[str]] = None,
        star_tag: bool = False,
    ) -> None: ...
    def as_set(self, include_weak: bool = False) -> Set[str]: ...
    def is_weak(self, etag: str) -> bool: ...
    def is_strong(self, etag: str) -> bool: ...
    def contains_weak(self, etag: str) -> bool: ...
    def contains(self, etag: str) -> bool: ...
    def contains_raw(self, etag: str) -> bool: ...
    def to_header(self) -> str: ...
    def __call__(
        self,
        etag: Optional[str] = None,
        data: Optional[bytes] = None,
        include_weak: bool = False,
    ) -> bool: ...
    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[str]: ...
    def __contains__(self, item: str) -> bool: ...  # type: ignore
