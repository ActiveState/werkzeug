from datetime import datetime
from os import PathLike
from typing import Any
from typing import Callable
from typing import Collection
from typing import Dict
from typing import FrozenSet
from typing import Generic
from typing import Hashable
from typing import IO
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Mapping
from typing import NoReturn
from typing import Optional
from typing import overload
from typing import Set
from typing import Tuple
from typing import Type
from typing import TypeVar
from typing import Union
from _typeshed.wsgi import WSGIEnvironment

from typing_extensions import Literal
from typing_extensions import SupportsIndex

K = TypeVar("K")
V = TypeVar("V")
T = TypeVar("T")
D = TypeVar("D")

def is_immutable(self: object) -> NoReturn: ...
def iter_multi_items(
    mapping: Union[Mapping[K, Union[V, Iterable[V]]], Iterable[Tuple[K, V]]]
) -> Iterator[Tuple[K, V]]: ...

class ImmutableListMixin(List[V]):
    _hash_cache: Optional[int]
    def __hash__(self) -> int: ...  # type: ignore
    def __delitem__(self, key: Union[SupportsIndex, slice]) -> NoReturn: ...
    def __iadd__(self, other: t.Any) -> NoReturn: ...  # type: ignore
    def __imul__(self, other: int) -> NoReturn: ...
    def __setitem__(  # type: ignore
        self, key: Union[int, slice], value: V
    ) -> NoReturn: ...
    def append(self, value: V) -> NoReturn: ...
    def remove(self, value: V) -> NoReturn: ...
    def extend(self, values: Iterable[V]) -> NoReturn: ...
    def insert(self, pos: int, value: V) -> NoReturn: ...
    def pop(self, index: int = -1) -> NoReturn: ...
    def reverse(self) -> NoReturn: ...
    def sort(
        self, key: Optional[Callable[[V], Any]] = None, reverse: bool = False
    ) -> NoReturn: ...

class ImmutableList(ImmutableListMixin[V]): ...

class ImmutableDictMixin(Dict[K, V]):
    _hash_cache: Optional[int]
    @classmethod
    def fromkeys(  # type: ignore
        cls, keys: Iterable[K], value: Optional[V] = None
    ) -> ImmutableDictMixin[K, V]: ...
    def _iter_hashitems(self) -> Iterable[Hashable]: ...
    def __hash__(self) -> int: ...  # type: ignore
    def setdefault(self, key: K, default: Optional[V] = None) -> NoReturn: ...
    def update(self, *args: Any, **kwargs: V) -> NoReturn: ...
    def pop(self, key: K, default: Optional[V] = None) -> NoReturn: ...  # type: ignore
    def popitem(self) -> NoReturn: ...
    def __setitem__(self, key: K, value: V) -> NoReturn: ...
    def __delitem__(self, key: K) -> NoReturn: ...
    def clear(self) -> NoReturn: ...

class ImmutableMultiDictMixin(ImmutableDictMixin[K, V]):
    def _iter_hashitems(self) -> Iterable[Hashable]: ...
    def add(self, key: K, value: V) -> NoReturn: ...
    def popitemlist(self) -> NoReturn: ...
    def poplist(self, key: K) -> NoReturn: ...
    def setlist(self, key: K, new_list: Iterable[V]) -> NoReturn: ...
    def setlistdefault(
        self, key: K, default_list: Optional[Iterable[V]] = None
    ) -> NoReturn: ...

def _calls_update(name: str) -> Callable[[UpdateDictMixin[K, V]], Any]: ...

class UpdateDictMixin(Dict[K, V]):
    on_update: Optional[Callable[[UpdateDictMixin[K, V]], None]]
    def setdefault(self, key: K, default: Optional[V] = None) -> V: ...
    @overload
    def pop(self, key: K) -> V: ...
    @overload
    def pop(self, key: K, default: Union[V, T] = ...) -> Union[V, T]: ...
    def __setitem__(self, key: K, value: V) -> None: ...
    def __delitem__(self, key: K) -> None: ...
    def clear(self) -> None: ...
    def popitem(self) -> Tuple[K, V]: ...
    def update(
        self, *args: Union[Mapping[K, V], Iterable[Tuple[K, V]]], **kwargs: V
    ) -> None: ...

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

def _options_header_vkw(
    value: str, kw: Mapping[str, Optional[Union[str, int]]]
) -> str: ...
def _unicodify_header_value(value: Union[str, int]) -> str: ...

HV = Union[str, int]

class Headers(Dict[str, str]):
    _list: List[Tuple[str, str]]
    def __init__(
        self,
        defaults: Optional[
            Union[Mapping[str, Union[HV, Iterable[HV]]], Iterable[Tuple[str, HV]]]
        ] = None,
    ) -> None: ...
    @overload
    def __getitem__(self, key: str) -> str: ...
    @overload
    def __getitem__(self, key: int) -> Tuple[str, str]: ...
    @overload
    def __getitem__(self, key: slice) -> Headers: ...
    @overload
    def __getitem__(self, key: str, _get_mode: Literal[True] = ...) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    @overload  # type: ignore
    def get(self, key: str, default: str) -> str: ...
    @overload
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]: ...
    @overload
    def get(
        self, key: str, default: Optional[T] = None, type: Callable[[str], T] = ...
    ) -> Optional[T]: ...
    @overload
    def getlist(self, key: str) -> List[str]: ...
    @overload
    def getlist(self, key: str, type: Callable[[str], T]) -> List[T]: ...
    def get_all(self, name: str) -> List[str]: ...
    def items(  # type: ignore
        self, lower: bool = False
    ) -> Iterator[Tuple[str, str]]: ...
    def keys(self, lower: bool = False) -> Iterator[str]: ...  # type: ignore
    def values(self) -> Iterator[str]: ...  # type: ignore
    def extend(
        self,
        *args: Union[Mapping[str, Union[HV, Iterable[HV]]], Iterable[Tuple[str, HV]]],
        **kwargs: Union[HV, Iterable[HV]],
    ) -> None: ...
    @overload
    def __delitem__(self, key: Union[str, int, slice]) -> None: ...
    @overload
    def __delitem__(self, key: str, _index_operation: Literal[False]) -> None: ...
    def remove(self, key: str) -> None: ...
    @overload  # type: ignore
    def pop(self, key: str, default: Optional[str] = None) -> str: ...
    @overload
    def pop(
        self, key: Optional[int] = None, default: Optional[Tuple[str, str]] = None
    ) -> Tuple[str, str]: ...
    def popitem(self) -> Tuple[str, str]: ...
    def __contains__(self, key: str) -> bool: ...  # type: ignore
    def has_key(self, key: str) -> bool: ...
    def __iter__(self) -> Iterator[Tuple[str, str]]: ...  # type: ignore
    def add(self, _key: str, _value: HV, **kw: HV) -> None: ...
    def _validate_value(self, value: str) -> None: ...
    def add_header(self, _key: str, _value: HV, **_kw: HV) -> None: ...
    def clear(self) -> None: ...
    def set(self, _key: str, _value: HV, **kw: HV) -> None: ...
    def setlist(self, key: str, values: Iterable[HV]) -> None: ...
    def setdefault(self, key: str, default: HV) -> str: ...  # type: ignore
    def setlistdefault(self, key: str, default: Iterable[HV]) -> None: ...
    @overload
    def __setitem__(self, key: str, value: HV) -> None: ...
    @overload
    def __setitem__(self, key: int, value: Tuple[str, HV]) -> None: ...
    @overload
    def __setitem__(self, key: slice, value: Iterable[Tuple[str, HV]]) -> None: ...
    def update(
        self,
        *args: Union[Mapping[str, HV], Iterable[Tuple[str, HV]]],
        **kwargs: Union[HV, Iterable[HV]],
    ) -> None: ...
    def to_wsgi_list(self) -> List[Tuple[str, str]]: ...
    def copy(self) -> Headers: ...
    def __copy__(self) -> Headers: ...

class ImmutableHeadersMixin(Headers):
    def __delitem__(self, key: Any, _index_operation: bool = True) -> NoReturn: ...
    def __setitem__(self, key: Any, value: Any) -> NoReturn: ...
    def set(self, _key: Any, _value: Any, **kw: Any) -> NoReturn: ...
    def setlist(self, key: Any, values: Any) -> NoReturn: ...
    def add(self, _key: Any, _value: Any, **kw: Any) -> NoReturn: ...
    def add_header(self, _key: Any, _value: Any, **_kw: Any) -> NoReturn: ...
    def remove(self, key: Any) -> NoReturn: ...
    def extend(self, *args: Any, **kwargs: Any) -> NoReturn: ...
    def update(self, *args: Any, **kwargs: Any) -> NoReturn: ...
    def insert(self, pos: Any, value: Any) -> NoReturn: ...
    def pop(self, key: Any = None, default: Any = ...) -> NoReturn: ...
    def popitem(self) -> NoReturn: ...
    def setdefault(self, key: Any, default: Any) -> NoReturn: ...  # type: ignore
    def setlistdefault(self, key: Any, default: Any) -> NoReturn: ...

class EnvironHeaders(ImmutableHeadersMixin, Headers):
    environ: WSGIEnvironment
    def __init__(self, environ: WSGIEnvironment) -> None: ...
    def __eq__(self, other: object) -> bool: ...
    def __getitem__(  # type: ignore
        self, key: str, _get_mode: Literal[False] = False
    ) -> str: ...
    def __iter__(self) -> Iterator[Tuple[str, str]]: ...  # type: ignore
    def copy(self) -> NoReturn: ...

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

class FileMultiDict(MultiDict[str, "FileStorage"]):
    def add_file(
        self,
        name: str,
        file: Union[FileStorage, str, IO[bytes]],
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> None: ...

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

class Accept(ImmutableList[Tuple[str, int]]):
    provided: bool
    def __init__(
        self, values: Optional[Union[Accept, Iterable[Tuple[str, float]]]] = None
    ) -> None: ...
    def _specificity(self, value: str) -> Tuple[bool, ...]: ...
    def _value_matches(self, value: str, item: str) -> bool: ...
    @overload  # type: ignore
    def __getitem__(self, key: str) -> int: ...
    @overload
    def __getitem__(self, key: int) -> Tuple[str, int]: ...
    @overload
    def __getitem__(self, key: slice) -> Iterable[Tuple[str, int]]: ...
    def quality(self, key: str) -> int: ...
    def __contains__(self, value: str) -> bool: ...  # type: ignore
    def index(self, key: str) -> int: ...  # type: ignore
    def find(self, key: str) -> int: ...
    def values(self) -> Iterator[str]: ...
    def to_header(self) -> str: ...
    def _best_single_match(self, match: str) -> Optional[Tuple[str, int]]: ...
    def best_match(
        self, matches: Iterable[str], default: Optional[str] = None
    ) -> Optional[str]: ...
    @property
    def best(self) -> str: ...

def _normalize_mime(value: str) -> List[str]: ...

class MIMEAccept(Accept):
    def _specificity(self, value: str) -> Tuple[bool, ...]: ...
    def _value_matches(self, value: str, item: str) -> bool: ...
    @property
    def accept_html(self) -> bool: ...
    @property
    def accept_xhtml(self) -> bool: ...
    @property
    def accept_json(self) -> bool: ...

def _normalize_lang(value: str) -> List[str]: ...

class LanguageAccept(Accept):
    def _value_matches(self, value: str, item: str) -> bool: ...
    def best_match(
        self, matches: Iterable[str], default: Optional[str] = None
    ) -> Optional[str]: ...

class CharsetAccept(Accept):
    def _value_matches(self, value: str, item: str) -> bool: ...

_CPT = TypeVar("_CPT", str, int, bool)
_OptCPT = Optional[_CPT]

def cache_property(key: str, empty: _OptCPT, type: Type[_CPT]) -> property: ...

class _CacheControl(UpdateDictMixin[str, _OptCPT], Dict[str, _OptCPT]):
    provided: bool
    def __init__(
        self,
        values: Union[Mapping[str, _OptCPT], Iterable[Tuple[str, _OptCPT]]] = (),
        on_update: Optional[Callable[[_CacheControl], None]] = None,
    ) -> None: ...
    @property
    def no_cache(self) -> Optional[bool]: ...
    @no_cache.setter
    def no_cache(self, value: Optional[bool]) -> None: ...
    @no_cache.deleter
    def no_cache(self) -> None: ...
    @property
    def no_store(self) -> Optional[bool]: ...
    @no_store.setter
    def no_store(self, value: Optional[bool]) -> None: ...
    @no_store.deleter
    def no_store(self) -> None: ...
    @property
    def max_age(self) -> Optional[int]: ...
    @max_age.setter
    def max_age(self, value: Optional[int]) -> None: ...
    @max_age.deleter
    def max_age(self) -> None: ...
    @property
    def no_transform(self) -> Optional[bool]: ...
    @no_transform.setter
    def no_transform(self, value: Optional[bool]) -> None: ...
    @no_transform.deleter
    def no_transform(self) -> None: ...
    def _get_cache_value(self, key: str, empty: Optional[T], type: Type[T]) -> T: ...
    def _set_cache_value(self, key: str, value: Optional[T], type: Type[T]) -> None: ...
    def _del_cache_value(self, key: str) -> None: ...
    def to_header(self) -> str: ...
    @staticmethod
    def cache_property(key: str, empty: _OptCPT, type: Type[_CPT]) -> property: ...

class RequestCacheControl(ImmutableDictMixin[str, _OptCPT], _CacheControl):
    @property
    def max_stale(self) -> Optional[int]: ...
    @max_stale.setter
    def max_stale(self, value: Optional[int]) -> None: ...
    @max_stale.deleter
    def max_stale(self) -> None: ...
    @property
    def min_fresh(self) -> Optional[int]: ...
    @min_fresh.setter
    def min_fresh(self, value: Optional[int]) -> None: ...
    @min_fresh.deleter
    def min_fresh(self) -> None: ...
    @property
    def only_if_cached(self) -> Optional[bool]: ...
    @only_if_cached.setter
    def only_if_cached(self, value: Optional[bool]) -> None: ...
    @only_if_cached.deleter
    def only_if_cached(self) -> None: ...

class ResponseCacheControl(_CacheControl):
    @property
    def public(self) -> Optional[bool]: ...
    @public.setter
    def public(self, value: Optional[bool]) -> None: ...
    @public.deleter
    def public(self) -> None: ...
    @property
    def private(self) -> Optional[bool]: ...
    @private.setter
    def private(self, value: Optional[bool]) -> None: ...
    @private.deleter
    def private(self) -> None: ...
    @property
    def must_revalidate(self) -> Optional[bool]: ...
    @must_revalidate.setter
    def must_revalidate(self, value: Optional[bool]) -> None: ...
    @must_revalidate.deleter
    def must_revalidate(self) -> None: ...
    @property
    def proxy_revalidate(self) -> Optional[bool]: ...
    @proxy_revalidate.setter
    def proxy_revalidate(self, value: Optional[bool]) -> None: ...
    @proxy_revalidate.deleter
    def proxy_revalidate(self) -> None: ...
    @property
    def s_maxage(self) -> Optional[int]: ...
    @s_maxage.setter
    def s_maxage(self, value: Optional[int]) -> None: ...
    @s_maxage.deleter
    def s_maxage(self) -> None: ...
    @property
    def immutable(self) -> Optional[bool]: ...
    @immutable.setter
    def immutable(self, value: Optional[bool]) -> None: ...
    @immutable.deleter
    def immutable(self) -> None: ...

def csp_property(key: str) -> property: ...

class ContentSecurityPolicy(UpdateDictMixin[str, str], Dict[str, str]):
    @property
    def base_uri(self) -> Optional[str]: ...
    @base_uri.setter
    def base_uri(self, value: Optional[str]) -> None: ...
    @base_uri.deleter
    def base_uri(self) -> None: ...
    @property
    def child_src(self) -> Optional[str]: ...
    @child_src.setter
    def child_src(self, value: Optional[str]) -> None: ...
    @child_src.deleter
    def child_src(self) -> None: ...
    @property
    def connect_src(self) -> Optional[str]: ...
    @connect_src.setter
    def connect_src(self, value: Optional[str]) -> None: ...
    @connect_src.deleter
    def connect_src(self) -> None: ...
    @property
    def default_src(self) -> Optional[str]: ...
    @default_src.setter
    def default_src(self, value: Optional[str]) -> None: ...
    @default_src.deleter
    def default_src(self) -> None: ...
    @property
    def font_src(self) -> Optional[str]: ...
    @font_src.setter
    def font_src(self, value: Optional[str]) -> None: ...
    @font_src.deleter
    def font_src(self) -> None: ...
    @property
    def form_action(self) -> Optional[str]: ...
    @form_action.setter
    def form_action(self, value: Optional[str]) -> None: ...
    @form_action.deleter
    def form_action(self) -> None: ...
    @property
    def frame_ancestors(self) -> Optional[str]: ...
    @frame_ancestors.setter
    def frame_ancestors(self, value: Optional[str]) -> None: ...
    @frame_ancestors.deleter
    def frame_ancestors(self) -> None: ...
    @property
    def frame_src(self) -> Optional[str]: ...
    @frame_src.setter
    def frame_src(self, value: Optional[str]) -> None: ...
    @frame_src.deleter
    def frame_src(self) -> None: ...
    @property
    def img_src(self) -> Optional[str]: ...
    @img_src.setter
    def img_src(self, value: Optional[str]) -> None: ...
    @img_src.deleter
    def img_src(self) -> None: ...
    @property
    def manifest_src(self) -> Optional[str]: ...
    @manifest_src.setter
    def manifest_src(self, value: Optional[str]) -> None: ...
    @manifest_src.deleter
    def manifest_src(self) -> None: ...
    @property
    def media_src(self) -> Optional[str]: ...
    @media_src.setter
    def media_src(self, value: Optional[str]) -> None: ...
    @media_src.deleter
    def media_src(self) -> None: ...
    @property
    def navigate_to(self) -> Optional[str]: ...
    @navigate_to.setter
    def navigate_to(self, value: Optional[str]) -> None: ...
    @navigate_to.deleter
    def navigate_to(self) -> None: ...
    @property
    def object_src(self) -> Optional[str]: ...
    @object_src.setter
    def object_src(self, value: Optional[str]) -> None: ...
    @object_src.deleter
    def object_src(self) -> None: ...
    @property
    def prefetch_src(self) -> Optional[str]: ...
    @prefetch_src.setter
    def prefetch_src(self, value: Optional[str]) -> None: ...
    @prefetch_src.deleter
    def prefetch_src(self) -> None: ...
    @property
    def plugin_types(self) -> Optional[str]: ...
    @plugin_types.setter
    def plugin_types(self, value: Optional[str]) -> None: ...
    @plugin_types.deleter
    def plugin_types(self) -> None: ...
    @property
    def report_to(self) -> Optional[str]: ...
    @report_to.setter
    def report_to(self, value: Optional[str]) -> None: ...
    @report_to.deleter
    def report_to(self) -> None: ...
    @property
    def report_uri(self) -> Optional[str]: ...
    @report_uri.setter
    def report_uri(self, value: Optional[str]) -> None: ...
    @report_uri.deleter
    def report_uri(self) -> None: ...
    @property
    def sandbox(self) -> Optional[str]: ...
    @sandbox.setter
    def sandbox(self, value: Optional[str]) -> None: ...
    @sandbox.deleter
    def sandbox(self) -> None: ...
    @property
    def script_src(self) -> Optional[str]: ...
    @script_src.setter
    def script_src(self, value: Optional[str]) -> None: ...
    @script_src.deleter
    def script_src(self) -> None: ...
    @property
    def script_src_attr(self) -> Optional[str]: ...
    @script_src_attr.setter
    def script_src_attr(self, value: Optional[str]) -> None: ...
    @script_src_attr.deleter
    def script_src_attr(self) -> None: ...
    @property
    def script_src_elem(self) -> Optional[str]: ...
    @script_src_elem.setter
    def script_src_elem(self, value: Optional[str]) -> None: ...
    @script_src_elem.deleter
    def script_src_elem(self) -> None: ...
    @property
    def style_src(self) -> Optional[str]: ...
    @style_src.setter
    def style_src(self, value: Optional[str]) -> None: ...
    @style_src.deleter
    def style_src(self) -> None: ...
    @property
    def style_src_attr(self) -> Optional[str]: ...
    @style_src_attr.setter
    def style_src_attr(self, value: Optional[str]) -> None: ...
    @style_src_attr.deleter
    def style_src_attr(self) -> None: ...
    @property
    def style_src_elem(self) -> Optional[str]: ...
    @style_src_elem.setter
    def style_src_elem(self, value: Optional[str]) -> None: ...
    @style_src_elem.deleter
    def style_src_elem(self) -> None: ...
    @property
    def worker_src(self) -> Optional[str]: ...
    @worker_src.setter
    def worker_src(self, value: Optional[str]) -> None: ...
    @worker_src.deleter
    def worker_src(self) -> None: ...
    provided: bool
    def __init__(
        self,
        values: Union[Mapping[str, str], Iterable[Tuple[str, str]]] = (),
        on_update: Optional[Callable[[ContentSecurityPolicy], None]] = None,
    ) -> None: ...
    def _get_value(self, key: str) -> Optional[str]: ...
    def _set_value(self, key: str, value: str) -> None: ...
    def _del_value(self, key: str) -> None: ...
    def to_header(self) -> str: ...

class CallbackDict(UpdateDictMixin[K, V], Dict[K, V]):
    def __init__(
        self,
        initial: Optional[Union[Mapping[K, V], Iterable[Tuple[K, V]]]] = None,
        on_update: Optional[Callable[[CallbackDict], None]] = None,
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

class IfRange:
    etag: Optional[str]
    date: Optional[datetime]
    def __init__(
        self, etag: Optional[str] = None, date: Optional[datetime] = None
    ) -> None: ...
    def to_header(self) -> str: ...

class Range:
    units: str
    ranges: List[Tuple[int, Optional[int]]]
    def __init__(self, units: str, ranges: List[Tuple[int, Optional[int]]]) -> None: ...
    def range_for_length(self, length: Optional[int]) -> Optional[Tuple[int, int]]: ...
    def make_content_range(self, length: Optional[int]) -> Optional[ContentRange]: ...
    def to_header(self) -> str: ...
    def to_content_range_header(self, length: Optional[int]) -> Optional[str]: ...

def _callback_property(name: str) -> property: ...

class ContentRange:
    on_update: Optional[Callable[[ContentRange], None]]
    def __init__(
        self,
        units: Optional[str],
        start: Optional[int],
        stop: Optional[int],
        length: Optional[int] = None,
        on_update: Optional[Callable[[ContentRange], None]] = None,
    ) -> None: ...
    @property
    def units(self) -> Optional[str]: ...
    @units.setter
    def units(self, value: Optional[str]) -> None: ...
    @property
    def start(self) -> Optional[int]: ...
    @start.setter
    def start(self, value: Optional[int]) -> None: ...
    @property
    def stop(self) -> Optional[int]: ...
    @stop.setter
    def stop(self, value: Optional[int]) -> None: ...
    @property
    def length(self) -> Optional[int]: ...
    @length.setter
    def length(self, value: Optional[int]) -> None: ...
    def set(
        self,
        start: Optional[int],
        stop: Optional[int],
        length: Optional[int] = None,
        units: Optional[str] = "bytes",
    ) -> None: ...
    def unset(self) -> None: ...
    def to_header(self) -> str: ...

class Authorization(ImmutableDictMixin[str, str], Dict[str, str]):
    type: str
    def __init__(
        self,
        auth_type: str,
        data: Optional[Union[Mapping[str, str], Iterable[Tuple[str, str]]]] = None,
    ) -> None: ...
    @property
    def username(self) -> Optional[str]: ...
    @property
    def password(self) -> Optional[str]: ...
    @property
    def realm(self) -> Optional[str]: ...
    @property
    def nonce(self) -> Optional[str]: ...
    @property
    def uri(self) -> Optional[str]: ...
    @property
    def nc(self) -> Optional[str]: ...
    @property
    def cnonce(self) -> Optional[str]: ...
    @property
    def response(self) -> Optional[str]: ...
    @property
    def opaque(self) -> Optional[str]: ...
    @property
    def qop(self) -> Optional[str]: ...
    def to_header(self) -> str: ...

def auth_property(name: str, doc: Optional[str] = None) -> property: ...
def _set_property(name: str, doc: Optional[str] = None) -> property: ...

class WWWAuthenticate(UpdateDictMixin[str, str], Dict[str, str]):
    _require_quoting: FrozenSet[str]
    def __init__(
        self,
        auth_type: Optional[str] = None,
        values: Optional[Union[Mapping[str, str], Iterable[Tuple[str, str]]]] = None,
        on_update: Optional[Callable[[WWWAuthenticate], None]] = None,
    ) -> None: ...
    def set_basic(self, realm: str = ...) -> None: ...
    def set_digest(
        self,
        realm: str,
        nonce: str,
        qop: Iterable[str] = ("auth",),
        opaque: Optional[str] = None,
        algorithm: Optional[str] = None,
        stale: bool = False,
    ) -> None: ...
    def to_header(self) -> str: ...
    @property
    def type(self) -> Optional[str]: ...
    @type.setter
    def type(self, value: Optional[str]) -> None: ...
    @property
    def realm(self) -> Optional[str]: ...
    @realm.setter
    def realm(self, value: Optional[str]) -> None: ...
    @property
    def domain(self) -> HeaderSet: ...
    @property
    def nonce(self) -> Optional[str]: ...
    @nonce.setter
    def nonce(self, value: Optional[str]) -> None: ...
    @property
    def opaque(self) -> Optional[str]: ...
    @opaque.setter
    def opaque(self, value: Optional[str]) -> None: ...
    @property
    def algorithm(self) -> Optional[str]: ...
    @algorithm.setter
    def algorithm(self, value: Optional[str]) -> None: ...
    @property
    def qop(self) -> HeaderSet: ...
    @property
    def stale(self) -> Optional[bool]: ...
    @stale.setter
    def stale(self, value: Optional[bool]) -> None: ...
    @staticmethod
    def auth_property(name: str, doc: Optional[str] = None) -> property: ...

class FileStorage:
    name: Optional[str]
    stream: IO[bytes]
    filename: Optional[str]
    headers: Headers
    _parsed_content_type: Tuple[str, Dict[str, str]]
    def __init__(
        self,
        stream: Optional[IO[bytes]] = None,
        filename: Optional[str] = None,
        name: Optional[str] = None,
        content_type: Optional[str] = None,
        content_length: Optional[int] = None,
        headers: Optional[Headers] = None,
    ) -> None: ...
    def _parse_content_type(self) -> None: ...
    @property
    def content_type(self) -> str: ...
    @property
    def content_length(self) -> int: ...
    @property
    def mimetype(self) -> str: ...
    @property
    def mimetype_params(self) -> Dict[str, str]: ...
    def save(
        self, dst: Union[str, PathLike, IO[bytes]], buffer_size: int = ...
    ) -> None: ...
    def close(self) -> None: ...
    def __bool__(self) -> bool: ...
    def __getattr__(self, name: str) -> Any: ...
    def __iter__(self) -> Iterator[bytes]: ...
    def __repr__(self) -> str: ...
