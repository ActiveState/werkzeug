from typing import Any
from typing import Callable
from typing import Dict
from typing import Generic
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Mapping
from typing import NoReturn
from typing import Optional
from typing import overload
from typing import Set
from typing import Tuple
from typing import TypeVar
from typing import Union

from typing_extensions import Literal

from .mixins import (
    ImmutableDictMixin,
    ImmutableListMixin,
    ImmutableMultiDictMixin,
    UpdateDictMixin,
)

D = TypeVar("D")
K = TypeVar("K")
T = TypeVar("T")
V = TypeVar("V")
_CD = TypeVar("_CD", bound="CallbackDict")

def is_immutable(self: object) -> NoReturn: ...
def iter_multi_items(
    mapping: Union[Mapping[K, Union[V, Iterable[V]]], Iterable[Tuple[K, V]]]
) -> Iterator[Tuple[K, V]]: ...

class ImmutableList(ImmutableListMixin[V]): ...

class TypeConversionDict(Dict[K, V]):
    @overload
    def get(self, key: K, default: None = ..., type: None = ...) -> Optional[V]: ...
    @overload
    def get(self, key: K, default: D, type: None = ...) -> Union[D, V]: ...
    @overload
    def get(self, key: K, default: D, type: Callable[[V], T]) -> Union[D, T]: ...
    @overload
    def get(self, key: K, type: Callable[[V], T]) -> Optional[T]: ...

class ImmutableTypeConversionDict(ImmutableDictMixin[K, V], TypeConversionDict[K, V]):
    def copy(self) -> TypeConversionDict[K, V]: ...
    def __copy__(self) -> ImmutableTypeConversionDict: ...

class MultiDict(TypeConversionDict[K, V]):
    def __init__(
        self,
        mapping: Optional[
            Union[Mapping[K, Union[Iterable[V], V]], Iterable[Tuple[K, V]]]
        ] = None,
    ) -> None: ...
    def __getitem__(self, item: K) -> V: ...
    def __setitem__(self, key: K, value: V) -> None: ...
    def add(self, key: K, value: V) -> None: ...
    @overload
    def getlist(self, key: K) -> List[V]: ...
    @overload
    def getlist(self, key: K, type: Callable[[V], T] = ...) -> List[T]: ...
    def setlist(self, key: K, new_list: Iterable[V]) -> None: ...
    def setdefault(self, key: K, default: Optional[V] = None) -> V: ...
    def setlistdefault(
        self, key: K, default_list: Optional[Iterable[V]] = None
    ) -> List[V]: ...
    def items(self, multi: bool = False) -> Iterator[Tuple[K, V]]: ...  # type: ignore
    def lists(self) -> Iterator[Tuple[K, List[V]]]: ...
    def values(self) -> Iterator[V]: ...  # type: ignore
    def listvalues(self) -> Iterator[List[V]]: ...
    def copy(self) -> MultiDict[K, V]: ...
    def deepcopy(self, memo: Any = None) -> MultiDict[K, V]: ...
    @overload
    def to_dict(self) -> Dict[K, V]: ...
    @overload
    def to_dict(self, flat: Literal[False]) -> Dict[K, List[V]]: ...
    def update(  # type: ignore
        self, mapping: Union[Mapping[K, Union[Iterable[V], V]], Iterable[Tuple[K, V]]]
    ) -> None: ...
    @overload
    def pop(self, key: K) -> V: ...
    @overload
    def pop(self, key: K, default: Union[V, T] = ...) -> Union[V, T]: ...
    def popitem(self) -> Tuple[K, V]: ...
    def poplist(self, key: K) -> List[V]: ...
    def popitemlist(self) -> Tuple[K, List[V]]: ...
    def __copy__(self) -> MultiDict[K, V]: ...
    def __deepcopy__(self, memo: Any) -> MultiDict[K, V]: ...

class _omd_bucket(Generic[K, V]):
    prev: Optional[_omd_bucket]
    next: Optional[_omd_bucket]
    key: K
    value: V
    def __init__(self, omd: OrderedMultiDict, key: K, value: V) -> None: ...
    def unlink(self, omd: OrderedMultiDict) -> None: ...

class OrderedMultiDict(MultiDict[K, V]):
    _first_bucket: Optional[_omd_bucket]
    _last_bucket: Optional[_omd_bucket]
    def __init__(self, mapping: Optional[Mapping[K, V]] = None) -> None: ...
    def __eq__(self, other: object) -> bool: ...
    def __getitem__(self, key: K) -> V: ...
    def __setitem__(self, key: K, value: V) -> None: ...
    def __delitem__(self, key: K) -> None: ...
    def keys(self) -> Iterator[K]: ...  # type: ignore
    def __iter__(self) -> Iterator[K]: ...
    def values(self) -> Iterator[V]: ...  # type: ignore
    def items(self, multi: bool = False) -> Iterator[Tuple[K, V]]: ...  # type: ignore
    def lists(self) -> Iterator[Tuple[K, List[V]]]: ...
    def listvalues(self) -> Iterator[List[V]]: ...
    def add(self, key: K, value: V) -> None: ...
    @overload
    def getlist(self, key: K) -> List[V]: ...
    @overload
    def getlist(self, key: K, type: Callable[[V], T] = ...) -> List[T]: ...
    def setlist(self, key: K, new_list: Iterable[V]) -> None: ...
    def setlistdefault(
        self, key: K, default_list: Optional[Iterable[V]] = None
    ) -> List[V]: ...
    def update(  # type: ignore
        self, mapping: Union[Mapping[K, V], Iterable[Tuple[K, V]]]
    ) -> None: ...
    def poplist(self, key: K) -> List[V]: ...
    @overload
    def pop(self, key: K) -> V: ...
    @overload
    def pop(self, key: K, default: Union[V, T] = ...) -> Union[V, T]: ...
    def popitem(self) -> Tuple[K, V]: ...
    def popitemlist(self) -> Tuple[K, List[V]]: ...

HV = Union[str, int]

class CombinedMultiDict(ImmutableMultiDictMixin[K, V], MultiDict[K, V]):  # type: ignore
    dicts: List[MultiDict[K, V]]
    def __init__(self, dicts: Optional[Iterable[MultiDict[K, V]]]) -> None: ...
    @classmethod
    def fromkeys(cls, keys: Any, value: Any = None) -> NoReturn: ...
    def __getitem__(self, key: K) -> V: ...
    @overload  # type: ignore
    def get(self, key: K) -> Optional[V]: ...
    @overload
    def get(self, key: K, default: Union[V, T] = ...) -> Union[V, T]: ...
    @overload
    def get(
        self, key: K, default: Optional[T] = None, type: Callable[[V], T] = ...
    ) -> Optional[T]: ...
    @overload
    def getlist(self, key: K) -> List[V]: ...
    @overload
    def getlist(self, key: K, type: Callable[[V], T] = ...) -> List[T]: ...
    def _keys_impl(self) -> Set[K]: ...
    def keys(self) -> Set[K]: ...  # type: ignore
    def __iter__(self) -> Set[K]: ...  # type: ignore
    def items(self, multi: bool = False) -> Iterator[Tuple[K, V]]: ...  # type: ignore
    def values(self) -> Iterator[V]: ...  # type: ignore
    def lists(self) -> Iterator[Tuple[K, List[V]]]: ...
    def listvalues(self) -> Iterator[List[V]]: ...
    def copy(self) -> MultiDict[K, V]: ...
    @overload
    def to_dict(self) -> Dict[K, V]: ...
    @overload
    def to_dict(self, flat: Literal[False]) -> Dict[K, List[V]]: ...
    def __contains__(self, key: K) -> bool: ...  # type: ignore
    def has_key(self, key: K) -> bool: ...

class ImmutableDict(ImmutableDictMixin[K, V], Dict[K, V]):
    def copy(self) -> Dict[K, V]: ...
    def __copy__(self) -> ImmutableDict[K, V]: ...

class ImmutableMultiDict(  # type: ignore
    ImmutableMultiDictMixin[K, V], MultiDict[K, V]
):
    def copy(self) -> MultiDict[K, V]: ...
    def __copy__(self) -> ImmutableMultiDict[K, V]: ...

class ImmutableOrderedMultiDict(  # type: ignore
    ImmutableMultiDictMixin[K, V], OrderedMultiDict[K, V]
):
    def _iter_hashitems(self) -> Iterator[Tuple[int, Tuple[K, V]]]: ...
    def copy(self) -> OrderedMultiDict[K, V]: ...
    def __copy__(self) -> ImmutableOrderedMultiDict[K, V]: ...

class CallbackDict(UpdateDictMixin[K, V], Dict[K, V]):
    def __init__(
        self,
        initial: Optional[Union[Mapping[K, V], Iterable[Tuple[K, V]]]] = None,
        on_update: Optional[Callable[[_CD], None]] = None,
    ) -> None: ...

class HeaderSet(Set[str]):
    _headers: List[str]
    _set: Set[str]
    on_update: Optional[Callable[[HeaderSet], None]]
    def __init__(
        self,
        headers: Optional[Iterable[str]] = None,
        on_update: Optional[Callable[[HeaderSet], None]] = None,
    ) -> None: ...
    def add(self, header: str) -> None: ...
    def remove(self, header: str) -> None: ...
    def update(self, iterable: Iterable[str]) -> None: ...  # type: ignore
    def discard(self, header: str) -> None: ...
    def find(self, header: str) -> int: ...
    def index(self, header: str) -> int: ...
    def clear(self) -> None: ...
    def as_set(self, preserve_casing: bool = False) -> Set[str]: ...
    def to_header(self) -> str: ...
    def __getitem__(self, idx: int) -> str: ...
    def __delitem__(self, idx: int) -> None: ...
    def __setitem__(self, idx: int, value: str) -> None: ...
    def __contains__(self, header: str) -> bool: ...  # type: ignore
    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[str]: ...
