from abc import ABC, abstractmethod
from typing import Any, Dict, TypeVar, Generic

K = TypeVar("K")
T = TypeVar("T")


class Factory(ABC, Generic[K, T]):
    """Abstract factory."""

    @abstractmethod
    def _get_creators(self, param: Any) -> Dict[K, T]:
        pass

    def __init__(self, param: Any) -> None:
        self._creators = self._get_creators(param)

    def get_instance(self, key: K) -> T:
        if key not in self._creators.keys():
            raise ValueError("No instance for key found!")

        return self._creators[key]
