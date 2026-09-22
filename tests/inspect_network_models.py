import json
import pickle
import sys
from pathlib import Path


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


# ================================================================
# OPTIONAL JOBLIB
# ================================================================

try:
    import joblib
except ImportError:
    joblib = None


# ================================================================
# SEARCH SETTINGS
# ================================================================

MODEL_EXTENSIONS = {
    ".pkl",
    ".joblib",
}

METADATA_EXTENSIONS = {
    ".json",
}

KEYWORDS = [
    "cic",
    "ids",
    "network",
    "attack",
    "random",
    "forest",
    "rf",
    "xgb",
    "xgboost",
    "model",
    "scaler",
    "encoder",
    "feature",
    "label",
]


# ================================================================
# HELPERS
# ================================================================

def separator():

    print(
        "\n"
        + "=" * 80
    )


def looks_relevant(
    path: Path,
):

    text = str(
        path
    ).lower()

    return any(
        keyword in text
        for keyword in KEYWORDS
    )


def load_model(
    path: Path,
):

    # ------------------------------------------------------------
    # TRY JOBLIB FIRST
    # ------------------------------------------------------------

    if joblib is not None:

        try:

            return (
                joblib.load(
                    path
                ),
                "joblib",
            )

        except Exception:
            pass

    # ------------------------------------------------------------
    # TRY PICKLE
    # ------------------------------------------------------------

    try:

        with open(
            path,
            "rb",
        ) as file:

            return (
                pickle.load(
                    file
                ),
                "pickle",
            )

    except Exception as error:

        return (
            None,
            f"FAILED: {error}",
        )


def print_model_information(
    path: Path,
):

    separator()

    print(
        "MODEL FILE"
    )

    print(
        "Path:",
        path,
    )

    print(
        "Size:",
        path.stat().st_size,
        "bytes",
    )

    model, loader = (
        load_model(
            path
        )
    )

    print(
        "Loader:",
        loader,
    )

    if model is None:

        print(
            "Could not load model."
        )

        return

    print(
        "Python type:",
        type(
            model
        ).__name__,
    )

    print(
        "Module:",
        type(
            model
        ).__module__,
    )

    # ------------------------------------------------------------
    # CLASSES
    # ------------------------------------------------------------

    if hasattr(
        model,
        "classes_",
    ):

        try:

            print(
                "Classes:",
                list(
                    model.classes_
                ),
            )

        except Exception as error:

            print(
                "Classes read error:",
                error,
            )

    # ------------------------------------------------------------
    # EXPECTED FEATURE COUNT
    # ------------------------------------------------------------

    if hasattr(
        model,
        "n_features_in_",
    ):

        try:

            print(
                "Expected feature count:",
                model.n_features_in_,
            )

        except Exception as error:

            print(
                "Feature-count read error:",
                error,
            )

    # ------------------------------------------------------------
    # FEATURE NAMES
    # ------------------------------------------------------------

    if hasattr(
        model,
        "feature_names_in_",
    ):

        try:

            features = list(
                model.feature_names_in_
            )

            print(
                "Feature names count:",
                len(
                    features
                ),
            )

            print(
                "\nFeature names:"
            )

            for index, feature in enumerate(
                features,
                start=1,
            ):

                print(
                    f"{index:03d}. {feature}"
                )

        except Exception as error:

            print(
                "Feature-name read error:",
                error,
            )

    # ------------------------------------------------------------
    # PIPELINE INFORMATION
    # ------------------------------------------------------------

    if hasattr(
        model,
        "named_steps",
    ):

        print(
            "\nPipeline steps:"
        )

        for name, step in (
            model.named_steps.items()
        ):

            print(
                f"  {name}: "
                f"{type(step).__name__}"
            )


def print_json_information(
    path: Path,
):

    separator()

    print(
        "JSON FILE"
    )

    print(
        "Path:",
        path,
    )

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(
                file
            )

    except Exception as error:

        print(
            "JSON read error:",
            error,
        )

        return

    print(
        "Type:",
        type(
            data
        ).__name__,
    )

    # ------------------------------------------------------------
    # LIST
    # ------------------------------------------------------------

    if isinstance(
        data,
        list,
    ):

        print(
            "Items:",
            len(
                data
            ),
        )

        if len(data) <= 100:

            for index, value in enumerate(
                data,
                start=1,
            ):

                print(
                    f"{index:03d}. {value}"
                )

        else:

            print(
                "First 30 items:"
            )

            for index, value in enumerate(
                data[:30],
                start=1,
            ):

                print(
                    f"{index:03d}. {value}"
                )

    # ------------------------------------------------------------
    # DICTIONARY
    # ------------------------------------------------------------

    elif isinstance(
        data,
        dict,
    ):

        print(
            "Keys:"
        )

        for key in data.keys():

            print(
                " -",
                key,
            )

        # --------------------------------------------------------
        # COMMON FEATURE KEYS
        # --------------------------------------------------------

        for feature_key in [
            "features",
            "feature_columns",
            "columns",
            "selected_features",
        ]:

            if (
                feature_key in data
                and isinstance(
                    data[
                        feature_key
                    ],
                    list,
                )
            ):

                features = (
                    data[
                        feature_key
                    ]
                )

                print(
                    f"\n{feature_key}:"
                )

                print(
                    "Count:",
                    len(
                        features
                    ),
                )

                for index, feature in enumerate(
                    features,
                    start=1,
                ):

                    print(
                        f"{index:03d}. {feature}"
                    )

        # --------------------------------------------------------
        # COMMON CLASS KEYS
        # --------------------------------------------------------

        for class_key in [
            "classes",
            "labels",
            "class_names",
            "class_mapping",
        ]:

            if class_key in data:

                print(
                    f"\n{class_key}:",
                    data[
                        class_key
                    ],
                )


# ================================================================
# MAIN
# ================================================================

def main():

    separator()

    print(
        "SENTINEL-X NETWORK ML MODEL INSPECTOR"
    )

    separator()

    print(
        "Project root:",
        PROJECT_ROOT,
    )

    # ------------------------------------------------------------
    # FIND CANDIDATE MODEL FILES
    # ------------------------------------------------------------

    model_files = []

    metadata_files = []

    for path in PROJECT_ROOT.rglob(
        "*"
    ):

        if not path.is_file():
            continue

        suffix = (
            path.suffix.lower()
        )

        if (
            suffix in MODEL_EXTENSIONS
            and looks_relevant(
                path
            )
        ):

            model_files.append(
                path
            )

        elif (
            suffix in METADATA_EXTENSIONS
            and looks_relevant(
                path
            )
        ):

            metadata_files.append(
                path
            )

    # ------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------

    print(
        "\nCandidate model files:",
        len(
            model_files
        ),
    )

    for path in model_files:

        print(
            " -",
            path,
        )

    print(
        "\nCandidate metadata files:",
        len(
            metadata_files
        ),
    )

    for path in metadata_files:

        print(
            " -",
            path,
        )

    # ------------------------------------------------------------
    # INSPECT MODELS
    # ------------------------------------------------------------

    for path in model_files:

        print_model_information(
            path
        )

    # ------------------------------------------------------------
    # INSPECT JSON METADATA
    # ------------------------------------------------------------

    for path in metadata_files:

        print_json_information(
            path
        )

    separator()

    print(
        "INSPECTION COMPLETE"
    )

    separator()


if __name__ == "__main__":

    main()