def add(left, right):
    return left + right


def main():
    total = 0
    for number in range(1, 6):
        total = add(total, number)
    print("total:", total)


if __name__ == "__main__":
    main()
