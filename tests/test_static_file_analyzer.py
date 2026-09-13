from detection.malware.static_file_analyzer import (
    StaticFileAnalyzer,
)


def main():
    analyzer = StaticFileAnalyzer()

    file_path = (
        r"C:\Users\T10002\Downloads"
        r"\sentinel_test\sample.txt"
    )

    result = analyzer.analyze(
        file_path
    )

    print()
    print("=" * 60)
    print("SENTINEL-X STATIC FILE ANALYSIS")
    print("=" * 60)

    for key, value in result.items():
        print(
            f"{key}: {value}"
        )


if __name__ == "__main__":
    main()