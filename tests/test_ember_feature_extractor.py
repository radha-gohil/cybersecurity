from detection.malware.ember_feature_extractor import (
    EmberFeatureExtractor,
)


def main():

    extractor = (
        EmberFeatureExtractor()
    )

    # Safe legitimate Windows executable
    file_path = (
        r"C:\Windows\System32\notepad.exe"
    )

    result = extractor.extract(
        file_path
    )

    print()
    print("=" * 70)
    print("SENTINEL-X EMBER RUNTIME FEATURE TEST")
    print("=" * 70)

    print(
        f"File          : {result['file_name']}"
    )

    print(
        f"Valid         : {result['valid']}"
    )

    print(
        f"Feature Count : {result['feature_count']}"
    )

    print(
        f"Error         : {result['error']}"
    )


    if result["valid"]:

        features = result[
            "features"
        ]

        print()
        print(
            f"Vector shape  : {features.shape}"
        )

        print()
        print(
            "First 10 features:"
        )

        print(
            features[:10]
        )


if __name__ == "__main__":

    main()