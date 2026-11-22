from __future__ import annotations

import functools
import itertools
import json
from collections import Counter, OrderedDict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Tuple

CALL_LOG = []


def logged(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        CALL_LOG.append(func.__name__)
        return func(*args, **kwargs)

    return wrapper


def repeat(times):
    def decorate(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = None
            for _ in range(times):
                result = func(*args, **kwargs)
            return result

        return wrapper

    return decorate


@dataclass(frozen=True)
class Point:
    x: float
    y: float

    def norm(self):
        return (self.x ** 2 + self.y ** 2) ** 0.5

    def shifted(self, dx, dy):
        return Point(self.x + dx, self.y + dy)

    def __add__(self, other):
        return Point(self.x + other.x, self.y + other.y)


@dataclass
class Node:
    name: str
    children: List["Node"] = field(default_factory=list)

    def walk(self):
        yield self.name
        for child in self.children:
            yield from child.walk()

    def depth(self):
        if not self.children:
            return 1
        return 1 + max(child.depth() for child in self.children)


class Color(Enum):
    RED = 1
    GREEN = 2
    BLUE = 3

    @classmethod
    def from_name(cls, name):
        for member in cls:
            if member.name.lower() == name.lower():
                return member
        raise ValueError("unknown colour: %s" % name)


class Shape:
    def area(self):
        raise NotImplementedError("subclass must implement area")

    def describe(self):
        return "%s area=%.2f" % (type(self).__name__.lower(), self.area())


class Rectangle(Shape):
    def __init__(self, width, height):
        self.width = width
        self.height = height

    def area(self):
        return self.width * self.height

    def scaled(self, factor):
        return Rectangle(self.width * factor, self.height * factor)


class Square(Rectangle):
    def __init__(self, side):
        super().__init__(side, side)

    def area(self):
        return super().area()


class Inventory:
    def __init__(self, items=None):
        self.items = dict(items or {})

    def add(self, name, quantity=1):
        self.items[name] = self.items.get(name, 0) + quantity
        return self.items[name]

    def remove(self, name, quantity=1):
        if name not in self.items:
            raise KeyError(name)
        if self.items[name] < quantity:
            raise ValueError("not enough %s" % name)
        self.items[name] -= quantity
        if self.items[name] == 0:
            del self.items[name]

    @property
    def total(self):
        return sum(self.items.values())

    @property
    def most_common(self):
        if not self.items:
            return None
        return max(sorted(self.items), key=lambda name: self.items[name])

    @classmethod
    def from_pairs(cls, pairs):
        inventory = cls()
        for name, quantity in pairs:
            inventory.add(name, quantity)
        return inventory

    @staticmethod
    def normalize(name):
        return name.strip().lower().replace(" ", "_")

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(sorted(self.items.items()))

    def __contains__(self, name):
        return name in self.items

    def __repr__(self):
        return "Inventory(%r)" % (self.items,)


def make_counter(start=0, step=1):
    value = start

    def counter():
        nonlocal value
        value += step
        return value

    def reset():
        nonlocal value
        value = start
        return value

    return counter, reset


def outer(value):
    def middle(scale):
        def inner(offset):
            return (value + offset) * scale

        return inner

    return middle


def compose(*functions):
    def composed(value):
        for function in reversed(functions):
            value = function(value)
        return value

    return composed


def fibonacci(limit):
    a, b = 0, 1
    while a < limit:
        yield a
        a, b = b, a + b


def chunked(items, size):
    chunk = []
    for item in items:
        chunk.append(item)
        if len(chunk) == size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def pairwise_sum(numbers):
    return [left + right for left, right in zip(numbers, numbers[1:])]


@contextmanager
def collecting(target):
    target.append("enter")
    try:
        yield target
    finally:
        target.append("exit")


class Timer:
    def __init__(self):
        self.entries = 0

    def __enter__(self):
        self.entries += 1
        return self

    def __exit__(self, exc_type, exc, tb):
        self.entries += 1
        return False


class BalanceError(Exception):
    def __init__(self, amount):
        super().__init__("balance would go negative: %d" % amount)
        self.amount = amount


def withdraw(balance, amount):
    if amount > balance:
        raise BalanceError(amount)
    return balance - amount


def describe(value):
    try:
        return "value=%d" % int(value)
    except (TypeError, ValueError) as exc:
        return "bad value: %s" % type(exc).__name__
    finally:
        CALL_LOG.append("describe")


def factorial(number):
    if number <= 1:
        return 1
    return number * factorial(number - 1)


def flatten(items):
    result = []
    for item in items:
        if isinstance(item, list):
            result.extend(flatten(item))
        else:
            result.append(item)
    return result


def binary_search(items, target, low=0, high=None):
    if high is None:
        high = len(items) - 1
    if low > high:
        return -1
    middle = (low + high) // 2
    if items[middle] == target:
        return middle
    if items[middle] < target:
        return binary_search(items, target, middle + 1, high)
    return binary_search(items, target, low, middle - 1)


def transform(values):
    squares = [value * value for value in values if value % 2 == 0]
    lookup = {value: value * 10 for value in values}
    unique = {value % 5 for value in values}
    pairs = [(value, value + 1) for value in values[:3]]
    total = sum(value for value in values if value > 2)
    return squares, lookup, unique, pairs, total


def group_by_length(words):
    grouped = {}
    for word in sorted(words):
        grouped.setdefault(len(word), []).append(word)
    return grouped


def merge(left, right):
    merged = list(itertools.chain(left, right))
    merged.sort()
    counts = Counter(merged)
    return merged, sorted(counts.items())


def rotate(values, amount):
    queue = deque(values)
    queue.rotate(amount)
    return list(queue)


def main():
    print("== points ==")
    origin = Point(0, 0)
    point = Point(3, 4)
    print("norm=%.2f" % point.norm())
    print("shifted=%s" % (point.shifted(1, -1),))
    print("sum=%s" % (point + origin,))

    print("== shapes ==")
    shapes = [Rectangle(3, 4), Square(3)]
    for shape in shapes:
        print(shape.describe())
    print("scaled=%.2f" % shapes[0].scaled(2).area())

    print("== inventory ==")
    inventory = Inventory.from_pairs([("bolt", 4), ("nut", 6), ("washer", 2)])
    inventory.add("bolt", 2)
    inventory.remove("washer")
    print("len=%d total=%d" % (len(inventory), inventory.total))
    print("contains bolt:", "bolt" in inventory)
    print("most common:", inventory.most_common)
    print("normalized:", Inventory.normalize("  Hex Bolt  "))
    print("items:", list(inventory))

    print("== closures ==")
    counter, reset = make_counter(10, 5)
    print("counter:", counter(), counter(), counter())
    print("reset:", reset(), counter())
    inner = outer(2)(3)
    print("nested:", inner(4), inner(10))
    pipeline = compose(lambda value: value + 1, lambda value: value * 2)
    print("composed:", pipeline(5))

    print("== generators ==")
    print("fib:", list(fibonacci(50)))
    print("chunks:", list(chunked(range(7), 3)))
    print("pairwise:", pairwise_sum([1, 2, 3, 4, 5]))

    print("== context ==")
    log = []
    with collecting(log) as target:
        target.append("body")
    print("collecting:", log)
    timer = Timer()
    with timer:
        pass
    print("timer entries:", timer.entries)

    print("== errors ==")
    print(describe("17"))
    print(describe("not a number"))
    try:
        withdraw(10, 4)
        withdraw(3, 9)
    except BalanceError as exc:
        print("caught:", exc, exc.amount)
    finally:
        print("withdraw finished")

    print("== recursion ==")
    print("factorial:", factorial(6))
    print("flatten:", flatten([1, [2, [3, [4]], 5]]))
    ordered = [1, 3, 5, 7, 9, 11]
    print("search:", binary_search(ordered, 7), binary_search(ordered, 4))

    print("== collections ==")
    squares, lookup, unique, pairs, total = transform([1, 2, 3, 4, 5, 6])
    print("squares:", squares)
    print("lookup:", sorted(lookup.items()))
    print("unique:", sorted(unique))
    print("pairs:", pairs)
    print("total:", total)
    print("grouped:", sorted(group_by_length(["pear", "fig", "apple", "kiwi"]).items()))
    print("merged:", merge([3, 1, 2], [2, 4]))
    print("rotated:", rotate([1, 2, 3, 4, 5], 2))

    print("== tree ==")
    tree = Node(
        "root",
        [
            Node("left", [Node("leaf-a"), Node("leaf-b")]),
            Node("right", [Node("leaf-c")]),
        ],
    )
    print("walk:", list(tree.walk()))
    print("depth:", tree.depth())

    print("== enums ==")
    print("colour:", Color.from_name("green").name, Color.BLUE.value)

    print("== json ==")
    payload = OrderedDict(
        [
            ("name", "fixture"),
            ("values", [1, 2, 3]),
            ("nested", {"ok": True, "count": 2}),
        ]
    )
    encoded = json.dumps(payload, sort_keys=True)
    decoded = json.loads(encoded)
    print("json:", encoded)
    print("roundtrip:", decoded["nested"]["count"])

    print("== calls ==")
    print("log:", sorted(set(CALL_LOG)))


if __name__ == "__main__":
    main()
