GREETING = "hello"


def greet(name):
    return "%s, %s!" % (GREETING, name)


class Counter:
    def __init__(self):
        self.value = 0

    def bump(self):
        self.value += 1
        return self.value


def main():
    print(greet("world"))
    counter = Counter()
    print(counter.bump(), counter.bump(), counter.bump())


if __name__ == "__main__":
    main()
