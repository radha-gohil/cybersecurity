from detection.malware.pe_feature_extractor import (
    PEFeatureExtractor,
)


def main():

    extractor = (
        PEFeatureExtractor()
    )

    # Use a normal legitimate Windows executable
    file_path = (
        r"C:\Windows\System32\notepad.exe"
    )

    result = extractor.extract(
        file_path
    )


    print()
    print("=" * 70)
    print("SENTINEL-X PE FEATURE EXTRACTION")
    print("=" * 70)


    for key, value in result.items():

        if key in {
            "sections",
            "imported_dlls",
            "suspicious_imports",
        }:

            continue

        print(
            f"{key}: {value}"
        )


    print()
    print("Imported DLLs:")

    for dll in result[
        "imported_dlls"
    ]:

        print(
            f"  - {dll}"
        )


    print()
    print("Suspicious API Imports:")

    if result[
        "suspicious_imports"
    ]:

        for api in result[
            "suspicious_imports"
        ]:

            print(
                f"  - {api}"
            )

    else:

        print(
            "  None detected"
        )


    print()
    print("PE Sections:")

    for section in result[
        "sections"
    ]:

        print(
            section
        )


if __name__ == "__main__":

    main()