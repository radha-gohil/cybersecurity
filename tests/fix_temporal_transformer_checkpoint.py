from __future__ import annotations

import shutil
from collections import OrderedDict
from pathlib import Path
from typing import Any

import numpy as np
import torch

try:
    from torch.torch_version import TorchVersion
except ImportError:
    TorchVersion = ()  # type: ignore


# ================================================================
# SENTINEL-X TEMPORAL CHECKPOINT SAFETY MIGRATION
#
# Purpose:
#
# Older SENTINEL-X temporal checkpoint:
#
#   model_state_dict
#   model metadata
#   torch.__version__
#
# Newer PyTorch:
#
#   torch.load(..., weights_only=True)
#
# rejects torch.torch_version.TorchVersion contained in metadata.
#
# This utility:
#
#   1. Loads OUR OWN trusted local checkpoint once.
#   2. Converts metadata into weights-only-safe primitive values.
#   3. Preserves all learned tensor weights unchanged.
#   4. Verifies weights_only=True loading.
#   5. Backs up the original checkpoint.
#
# IMPORTANT:
#
# Do NOT use this utility on a downloaded/untrusted .pt file.
# ================================================================


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_process_temporal_transformer_v1.pt"
)


BACKUP_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_process_temporal_transformer_v1_pre_safe_fix.pt"
)


TEMP_PATH = (
    PROJECT_ROOT
    / "models"
    / "temporal"
    / "sentinelx_process_temporal_transformer_v1_safe_temp.pt"
)


# ================================================================
# SAFE PRIMITIVE CONVERSION
# ================================================================

def make_safe(
    value: Any,
):
    """
    Convert checkpoint metadata into types accepted by the
    restricted PyTorch weights-only loader.

    Learned torch.Tensor values are NEVER modified.
    """

    # ------------------------------------------------------------
    # Learned model tensors
    # ------------------------------------------------------------

    if isinstance(
        value,
        torch.Tensor,
    ):

        return value


    # ------------------------------------------------------------
    # PyTorch version object
    #
    # This is the object causing the current loading error.
    # ------------------------------------------------------------

    if TorchVersion and isinstance(
        value,
        TorchVersion,
    ):

        return str(
            value
        )


    # ------------------------------------------------------------
    # Standard primitive types
    # ------------------------------------------------------------

    if value is None:

        return None


    if isinstance(
        value,
        (
            str,
            int,
            float,
            bool,
        ),
    ):

        return value


    # ------------------------------------------------------------
    # NumPy scalar
    # ------------------------------------------------------------

    if isinstance(
        value,
        np.generic,
    ):

        return make_safe(
            value.item()
        )


    # ------------------------------------------------------------
    # NumPy array
    #
    # Metadata arrays become primitive Python lists.
    # ------------------------------------------------------------

    if isinstance(
        value,
        np.ndarray,
    ):

        return [
            make_safe(
                item
            )
            for item in value.tolist()
        ]


    # ------------------------------------------------------------
    # Path
    # ------------------------------------------------------------

    if isinstance(
        value,
        Path,
    ):

        return str(
            value
        )


    # ------------------------------------------------------------
    # torch.device
    # ------------------------------------------------------------

    if isinstance(
        value,
        torch.device,
    ):

        return str(
            value
        )


    # ------------------------------------------------------------
    # torch.dtype
    # ------------------------------------------------------------

    if isinstance(
        value,
        torch.dtype,
    ):

        return str(
            value
        )


    # ------------------------------------------------------------
    # OrderedDict
    #
    # state_dict normally uses OrderedDict.
    # Preserve ordering while recursively checking values.
    # ------------------------------------------------------------

    if isinstance(
        value,
        OrderedDict,
    ):

        return OrderedDict(
            (
                make_safe(
                    key
                ),
                make_safe(
                    item
                ),
            )
            for (
                key,
                item,
            ) in value.items()
        )


    # ------------------------------------------------------------
    # Normal dictionaries
    # ------------------------------------------------------------

    if isinstance(
        value,
        dict,
    ):

        return {
            make_safe(
                key
            ):
            make_safe(
                item
            )
            for (
                key,
                item,
            ) in value.items()
        }


    # ------------------------------------------------------------
    # Lists
    # ------------------------------------------------------------

    if isinstance(
        value,
        list,
    ):

        return [
            make_safe(
                item
            )
            for item in value
        ]


    # ------------------------------------------------------------
    # Tuples
    #
    # Lists are safer for checkpoint metadata.
    # ------------------------------------------------------------

    if isinstance(
        value,
        tuple,
    ):

        return [
            make_safe(
                item
            )
            for item in value
        ]


    # ------------------------------------------------------------
    # Sets
    # ------------------------------------------------------------

    if isinstance(
        value,
        set,
    ):

        return [
            make_safe(
                item
            )
            for item in sorted(
                value,
                key=str,
            )
        ]


    # ------------------------------------------------------------
    # Unknown metadata
    #
    # Convert to descriptive string instead of serializing an
    # arbitrary Python object into the checkpoint.
    # ------------------------------------------------------------

    return str(
        value
    )


# ================================================================
# CHECKPOINT SUMMARY
# ================================================================

def print_checkpoint_summary(
    artifact,
):

    print()

    print(
        "Checkpoint contents:"
    )

    print(
        "-" * 76
    )


    if not isinstance(
        artifact,
        dict,
    ):

        print(
            "Artifact type:",
            type(
                artifact
            ).__name__,
        )

        return


    for (
        key,
        value,
    ) in artifact.items():

        if key == "model_state_dict":

            tensor_count = sum(

                1

                for item in value.values()

                if isinstance(
                    item,
                    torch.Tensor,
                )
            )


            print(
                f"{key:<30}: "
                f"{tensor_count} tensors"
            )


        else:

            print(
                f"{key:<30}: "
                f"{type(value).__name__}"
            )


# ================================================================
# VERIFY MODEL WEIGHTS
# ================================================================

def compare_state_dicts(
    before,
    after,
):

    before_state = (
        before[
            "model_state_dict"
        ]
    )


    after_state = (
        after[
            "model_state_dict"
        ]
    )


    if (
        set(
            before_state.keys()
        )

        != set(
            after_state.keys()
        )
    ):

        raise RuntimeError(

            "State-dict parameter names changed "
            "during migration."
        )


    checked = 0


    for key in before_state:

        before_tensor = (
            before_state[
                key
            ]
        )


        after_tensor = (
            after_state[
                key
            ]
        )


        if not isinstance(
            before_tensor,
            torch.Tensor,
        ):

            raise RuntimeError(

                f"Unexpected non-tensor model state: {key}"
            )


        if not isinstance(
            after_tensor,
            torch.Tensor,
        ):

            raise RuntimeError(

                f"Converted state is no longer tensor: {key}"
            )


        if (
            before_tensor.shape

            != after_tensor.shape
        ):

            raise RuntimeError(

                f"Tensor shape changed: {key}"
            )


        if not torch.equal(
            before_tensor.cpu(),
            after_tensor.cpu(),
        ):

            raise RuntimeError(

                f"Tensor values changed: {key}"
            )


        checked += 1


    return checked


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 76
    )

    print(
        "SENTINEL-X TEMPORAL CHECKPOINT SAFETY FIX"
    )

    print(
        "=" * 76
    )


    print()

    print(
        "Checkpoint:"
    )

    print(
        MODEL_PATH
    )


    if not MODEL_PATH.exists():

        raise FileNotFoundError(

            "Temporal Transformer model was not found:\n"
            f"{MODEL_PATH}"
        )


    # ============================================================
    # 1. LOAD ORIGINAL
    #
    # weights_only=False is used ONLY here because this checkpoint
    # was generated locally by the SENTINEL-X trainer.
    # ============================================================

    print()

    print(
        "[1/6] Loading trusted local checkpoint..."
    )


    original = torch.load(

        MODEL_PATH,

        map_location=
            "cpu",

        weights_only=
            False,
    )


    if not isinstance(
        original,
        dict,
    ):

        raise RuntimeError(

            "Unexpected checkpoint structure."
        )


    required = {
        "model_state_dict",
        "model_name",
        "model_version",
        "config",
        "metadata",
    }


    missing = (
        required
        - set(
            original.keys()
        )
    )


    if missing:

        raise RuntimeError(

            "Checkpoint missing required fields: "
            f"{sorted(missing)}"
        )


    print(
        "Trusted checkpoint loaded."
    )


    print_checkpoint_summary(
        original
    )


    # ============================================================
    # 2. SANITIZE
    # ============================================================

    print()

    print(
        "[2/6] Converting metadata to safe primitive types..."
    )


    safe_artifact = (
        make_safe(
            original
        )
    )


    # Explicitly guarantee torch version is stored as a string.

    if isinstance(
        safe_artifact.get(
            "metadata"
        ),
        dict,
    ):

        runtime = (
            safe_artifact[
                "metadata"
            ].get(
                "runtime"
            )
        )


        if isinstance(
            runtime,
            dict,
        ):

            if "torch" in runtime:

                runtime[
                    "torch"
                ] = str(

                    runtime[
                        "torch"
                    ]
                )


    print(
        "Metadata conversion complete."
    )


    # ============================================================
    # 3. SAVE TEMPORARY SAFE CHECKPOINT
    # ============================================================

    print()

    print(
        "[3/6] Writing temporary safe checkpoint..."
    )


    if TEMP_PATH.exists():

        TEMP_PATH.unlink()


    torch.save(

        safe_artifact,

        TEMP_PATH,
    )


    print(
        "Temporary checkpoint created:"
    )

    print(
        TEMP_PATH
    )


    # ============================================================
    # 4. VERIFY RESTRICTED LOAD
    # ============================================================

    print()

    print(
        "[4/6] Verifying weights_only=True loading..."
    )


    verified = torch.load(

        TEMP_PATH,

        map_location=
            "cpu",

        weights_only=
            True,
    )


    print(
        "Restricted checkpoint load: PASS"
    )


    # ============================================================
    # 5. VERIFY WEIGHTS UNCHANGED
    # ============================================================

    print()

    print(
        "[5/6] Comparing trained model tensors..."
    )


    tensor_count = (
        compare_state_dicts(

            before=
                original,

            after=
                verified,
        )
    )


    print(
        "Model tensors verified:",
        tensor_count,
    )


    print(
        "Weights unchanged: PASS"
    )


    # ============================================================
    # 6. BACKUP + REPLACE
    # ============================================================

    print()

    print(
        "[6/6] Backing up and replacing checkpoint..."
    )


    if not BACKUP_PATH.exists():

        shutil.copy2(

            MODEL_PATH,

            BACKUP_PATH,
        )


        print(
            "Backup created:"
        )

        print(
            BACKUP_PATH
        )


    else:

        print(
            "Backup already exists:"
        )

        print(
            BACKUP_PATH
        )


    TEMP_PATH.replace(
        MODEL_PATH
    )


    # ============================================================
    # FINAL VERIFICATION
    # ============================================================

    final_artifact = torch.load(

        MODEL_PATH,

        map_location=
            "cpu",

        weights_only=
            True,
    )


    final_tensor_count = (
        compare_state_dicts(

            before=
                original,

            after=
                final_artifact,
        )
    )


    print()

    print(
        "=" * 76
    )

    print(
        "CHECKPOINT MIGRATION COMPLETE"
    )

    print(
        "=" * 76
    )


    print()

    print(
        "weights_only=True load : PASS"
    )


    print(
        "Model tensors preserved:",
        final_tensor_count,
    )


    print(
        "Original backup:"
    )

    print(
        BACKUP_PATH
    )


    print()

    print(
        "Safe checkpoint:"
    )

    print(
        MODEL_PATH
    )


    print()

    print(
        "No Transformer retraining is required."
    )


if __name__ == "__main__":

    main()