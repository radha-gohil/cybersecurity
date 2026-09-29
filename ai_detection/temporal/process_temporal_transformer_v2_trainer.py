from __future__ import annotations

import copy
import hashlib
import json
import platform
import random
import sys

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

from typing import (
    Any,
    Dict,
    Tuple,
)

import numpy as np
import torch

from torch import nn

from torch.utils.data import (
    DataLoader,
    TensorDataset,
)


# ================================================================
# SENTINEL-X TEMPORAL TRANSFORMER V2
#
# Self-supervised temporal representation learning.
#
#
# V1:
#
#       8 timesteps × 27 features
#
# Included:
#
#       process_age_seconds
#
#
# Live/train distribution diagnostic showed:
#
#       Shift Z ≈ 51.55
#       100% live values outside training P05-P95
#
#
# V2:
#
#       8 timesteps × 26 features
#
# Removes:
#
#       process_age_seconds
#
#
# Training objective:
#
#       Mask complete timesteps
#       ↓
#       Transformer reconstructs them
#
#
# No malicious / benign ground-truth labels are used.
# ================================================================


# ================================================================
# PROJECT PATHS
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)


DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "temporal"
    / "process_sequence_splits_v2.npz"
)


MODEL_DIRECTORY = (
    PROJECT_ROOT
    / "models"
    / "temporal"
)


MODEL_PATH = (
    MODEL_DIRECTORY
    / "sentinelx_process_temporal_transformer_v2.pt"
)


METADATA_PATH = (
    MODEL_DIRECTORY
    / "sentinelx_process_temporal_transformer_v2_metadata.json"
)


# ================================================================
# MODEL IDENTITY
# ================================================================

MODEL_NAME = (
    "sentinelx_process_temporal_transformer"
)


MODEL_VERSION = "v2"


MODEL_TYPE = (
    "SelfSupervisedMaskedTimestepTransformer"
)


SCHEMA_VERSION = (
    "process_temporal_schema_v2"
)


# ================================================================
# INPUT
# ================================================================

SEQUENCE_LENGTH = 8

INPUT_FEATURE_COUNT = 26


FORBIDDEN_FEATURE = (
    "process_age_seconds"
)


# ================================================================
# TRANSFORMER ARCHITECTURE
# ================================================================

D_MODEL = 64

NHEAD = 4

NUM_ENCODER_LAYERS = 2

DIM_FEEDFORWARD = 128

DROPOUT = 0.10


# ================================================================
# SELF-SUPERVISED MASKING
#
# V2 intentionally masks complete timesteps only.
#
# Example:
#
# t1 t2 t3 MASK t5 t6 t7 t8
#
# This directly teaches temporal context rather than random
# individual-feature reconstruction.
# ================================================================

TIMESTEP_MASK_PROBABILITY = 0.25


# ================================================================
# TRAINING
# ================================================================

BATCH_SIZE = 32

MAX_EPOCHS = 150

LEARNING_RATE = 1e-3

WEIGHT_DECAY = 1e-5

EARLY_STOPPING_PATIENCE = 18

LR_PATIENCE = 6

LR_FACTOR = 0.5

MIN_LEARNING_RATE = 1e-5

GRADIENT_CLIP_NORM = 1.0


# ================================================================
# DATA REQUIREMENTS
# ================================================================

MINIMUM_TRAIN_WINDOWS = 20

MINIMUM_VALIDATION_WINDOWS = 5


# ================================================================
# REPRESENTATION HEALTH
# ================================================================

REPRESENTATION_STD_THRESHOLD = 1e-4

MIN_ACTIVE_DIMENSION_PERCENT = 75.0

MIN_UNIQUE_REPRESENTATION_PERCENT = 50.0


# ================================================================
# RANDOMNESS
# ================================================================

RANDOM_STATE = 42

VALIDATION_MASK_SEED = 20260929


# ================================================================
# HELPERS
# ================================================================

def now_iso() -> str:

    return (
        datetime
        .now(
            timezone.utc
        )
        .isoformat()
    )


def set_random_seeds(
    seed: int = RANDOM_STATE,
) -> None:

    random.seed(
        seed
    )

    np.random.seed(
        seed
    )

    torch.manual_seed(
        seed
    )


    if torch.cuda.is_available():

        torch.cuda.manual_seed_all(
            seed
        )


def sha256_file(
    path: Path,
) -> str:

    digest = hashlib.sha256()


    with open(
        path,
        "rb",
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )


            if not chunk:

                break


            digest.update(
                chunk
            )


    return digest.hexdigest()


def percentile_statistics(
    values: np.ndarray,
) -> Dict[str, float]:

    values = np.asarray(

        values,

        dtype=np.float64,
    )


    if values.size == 0:

        return {}


    return {
        "min":
            float(
                np.min(
                    values
                )
            ),

        "max":
            float(
                np.max(
                    values
                )
            ),

        "mean":
            float(
                np.mean(
                    values
                )
            ),

        "std":
            float(
                np.std(
                    values
                )
            ),

        "p50":
            float(
                np.percentile(
                    values,
                    50,
                )
            ),

        "p75":
            float(
                np.percentile(
                    values,
                    75,
                )
            ),

        "p90":
            float(
                np.percentile(
                    values,
                    90,
                )
            ),

        "p95":
            float(
                np.percentile(
                    values,
                    95,
                )
            ),

        "p97":
            float(
                np.percentile(
                    values,
                    97,
                )
            ),

        "p99":
            float(
                np.percentile(
                    values,
                    99,
                )
            ),
    }


# ================================================================
# MODEL
# ================================================================

class ProcessTemporalTransformerV2(
    nn.Module,
):

    def __init__(
        self,
        input_feature_count: int = INPUT_FEATURE_COUNT,
        sequence_length: int = SEQUENCE_LENGTH,
        d_model: int = D_MODEL,
        nhead: int = NHEAD,
        num_encoder_layers: int = NUM_ENCODER_LAYERS,
        dim_feedforward: int = DIM_FEEDFORWARD,
        dropout: float = DROPOUT,
    ):

        super().__init__()


        self.input_feature_count = int(
            input_feature_count
        )


        self.sequence_length = int(
            sequence_length
        )


        self.d_model = int(
            d_model
        )


        self.nhead = int(
            nhead
        )


        self.num_encoder_layers = int(
            num_encoder_layers
        )


        self.dim_feedforward = int(
            dim_feedforward
        )


        self.dropout_value = float(
            dropout
        )


        # ========================================================
        # INPUT PROJECTION
        #
        # 26 raw normalized features
        #           ↓
        # 64-dimensional token
        # ========================================================

        self.input_projection = (
            nn.Linear(

                self.input_feature_count,

                self.d_model,
            )
        )


        # ========================================================
        # POSITIONAL EMBEDDING
        # ========================================================

        self.positional_embedding = (
            nn.Parameter(

                torch.zeros(

                    1,

                    self.sequence_length,

                    self.d_model,
                )
            )
        )


        nn.init.normal_(

            self.positional_embedding,

            mean=0.0,

            std=0.02,
        )


        # ========================================================
        # LEARNED MASK TOKEN
        #
        # V1 replaced masked input values with zero.
        #
       # V2 explicitly tells the Transformer:
        #
        #       "this timestep is missing"
        #
        # through a learned embedding.
        # ========================================================

        self.mask_token = (
            nn.Parameter(

                torch.zeros(

                    1,

                    1,

                    self.d_model,
                )
            )
        )


        nn.init.normal_(

            self.mask_token,

            mean=0.0,

            std=0.02,
        )


        # ========================================================
        # TRANSFORMER ENCODER
        # ========================================================

        encoder_layer = (
            nn.TransformerEncoderLayer(

                d_model=
                    self.d_model,

                nhead=
                    self.nhead,

                dim_feedforward=
                    self.dim_feedforward,

                dropout=
                    self.dropout_value,

                activation=
                    "gelu",

                batch_first=
                    True,

                norm_first=
                    False,
            )
        )


        self.encoder = (
            nn.TransformerEncoder(

                encoder_layer,

                num_layers=
                    self.num_encoder_layers,
            )
        )


        self.output_norm = (
            nn.LayerNorm(
                self.d_model
            )
        )


        # ========================================================
        # RECONSTRUCTION HEAD
        # ========================================================

        self.reconstruction_head = (
            nn.Sequential(

                nn.Linear(
                    self.d_model,
                    self.d_model,
                ),

                nn.GELU(),

                nn.Dropout(
                    self.dropout_value
                ),

                nn.Linear(
                    self.d_model,
                    self.input_feature_count,
                ),
            )
        )


    # ============================================================
    # ENCODE
    # ============================================================

    def encode(
        self,
        x: torch.Tensor,
        timestep_mask: torch.Tensor | None = None,
    ) -> Tuple[
        torch.Tensor,
        torch.Tensor,
    ]:

        if x.ndim != 3:

            raise RuntimeError(

                "Temporal Transformer input must have shape "
                "(batch, sequence, features)."
            )


        if (

            x.shape[
                1
            ]

            != self.sequence_length

        ):

            raise RuntimeError(

                "Unexpected temporal sequence length. "
                f"Expected {self.sequence_length}, "
                f"received {x.shape[1]}."
            )


        if (

            x.shape[
                2
            ]

            != self.input_feature_count

        ):

            raise RuntimeError(

                "Unexpected temporal feature count. "
                f"Expected {self.input_feature_count}, "
                f"received {x.shape[2]}."
            )


        tokens = (
            self.input_projection(
                x
            )
        )


        # ========================================================
        # APPLY LEARNED MASK TOKEN
        #
        # timestep_mask:
        #
        #       shape = (batch, sequence)
        #       True = hidden timestep
        # ========================================================

        if timestep_mask is not None:

            if timestep_mask.shape != (

                x.shape[
                    0
                ],

                x.shape[
                    1
                ],

            ):

                raise RuntimeError(

                    "Temporal mask shape mismatch."
                )


            mask = (

                timestep_mask

                .unsqueeze(
                    -1
                )
            )


            learned_mask = (
                self.mask_token.expand(

                    x.shape[
                        0
                    ],

                    x.shape[
                        1
                    ],

                    -1,
                )
            )


            tokens = torch.where(

                mask,

                learned_mask,

                tokens,
            )


        # ========================================================
        # POSITION
        # ========================================================

        tokens = (

            tokens

            + self.positional_embedding[
                :,
                :x.shape[
                    1
                ],
                :
            ]
        )


        # ========================================================
        # ENCODE
        # ========================================================

        encoded = (
            self.encoder(
                tokens
            )
        )


        encoded = (
            self.output_norm(
                encoded
            )
        )


        # ========================================================
        # SEQUENCE REPRESENTATION
        #
        # Mean pooling across all 8 contextualized timesteps.
        # ========================================================

        representation = (
            torch.mean(

                encoded,

                dim=1,
            )
        )


        return (
            encoded,
            representation,
        )


    # ============================================================
    # FORWARD
    # ============================================================

    def forward(
        self,
        x: torch.Tensor,
        timestep_mask: torch.Tensor | None = None,
    ):

        (
            encoded,
            representation,

        ) = self.encode(

            x,

            timestep_mask=
                timestep_mask,
        )


        reconstruction = (
            self.reconstruction_head(
                encoded
            )
        )


        return (
            reconstruction,
            encoded,
            representation,
        )


    # ============================================================
    # CONFIG
    # ============================================================

    def get_config(
        self,
    ) -> Dict[str, Any]:

        return {
            "input_feature_count":
                self.input_feature_count,

            "sequence_length":
                self.sequence_length,

            "d_model":
                self.d_model,

            "nhead":
                self.nhead,

            "num_encoder_layers":
                self.num_encoder_layers,

            "dim_feedforward":
                self.dim_feedforward,

            "dropout":
                self.dropout_value,

            "representation_dimension":
                self.d_model,

            "masking":
                "learned_timestep_mask_token",
        }


# ================================================================
# TRAINER
# ================================================================

class ProcessTemporalTransformerV2Trainer:

    def __init__(
        self,
    ):

        set_random_seeds()


        self.device = (
            torch.device(

                "cuda"

                if torch.cuda.is_available()

                else "cpu"
            )
        )


        self.model = (
            ProcessTemporalTransformerV2()
            .to(
                self.device
            )
        )


    # ============================================================
    # DIRECTORIES
    # ============================================================

    def ensure_directories(
        self,
    ):

        MODEL_DIRECTORY.mkdir(

            parents=True,

            exist_ok=True,
        )


    # ============================================================
    # LOAD DATASET
    # ============================================================

    def load_dataset(
        self,
    ) -> Dict[str, np.ndarray]:

        if not DATASET_PATH.exists():

            raise FileNotFoundError(

                "Temporal v2 split dataset does not exist:\n"
                f"{DATASET_PATH}\n\n"
                "Run:\n"
                "python -m "
                "ai_detection.temporal."
                "build_temporal_dataset_v3"
            )


        data = np.load(

            DATASET_PATH,

            allow_pickle=False,
        )


        required = {
            "X_train",
            "X_validation",
            "X_test",
            "temporal_feature_names",
        }


        missing = (

            required

            - set(
                data.files
            )
        )


        if missing:

            raise RuntimeError(

                "Temporal v2 dataset is missing arrays: "
                f"{sorted(missing)}"
            )


        return {

            name:
                np.asarray(
                    data[
                        name
                    ]
                )

            for name
            in data.files
        }


    # ============================================================
    # VALIDATE DATASET
    # ============================================================

    def validate_dataset(
        self,
        dataset: Dict[str, np.ndarray],
    ):

        feature_names = [

            str(
                name
            )

            for name
            in dataset[
                "temporal_feature_names"
            ].tolist()
        ]


        if len(
            feature_names
        ) != INPUT_FEATURE_COUNT:

            raise RuntimeError(

                "Temporal feature-name count mismatch. "
                f"Expected {INPUT_FEATURE_COUNT}, "
                f"received {len(feature_names)}."
            )


        if FORBIDDEN_FEATURE in feature_names:

            raise RuntimeError(

                "process_age_seconds is still present "
                "in the Temporal Transformer v2 schema."
            )


        for split_name in [

            "X_train",

            "X_validation",

            "X_test",

        ]:

            matrix = np.asarray(

                dataset[
                    split_name
                ]
            )


            if matrix.ndim != 3:

                raise RuntimeError(

                    f"{split_name} must have shape "
                    "(windows, sequence, features)."
                )


            if matrix.shape[
                1
            ] != SEQUENCE_LENGTH:

                raise RuntimeError(

                    f"{split_name} sequence length "
                    "does not equal 8."
                )


            if matrix.shape[
                2
            ] != INPUT_FEATURE_COUNT:

                raise RuntimeError(

                    f"{split_name} feature count "
                    f"must equal {INPUT_FEATURE_COUNT}."
                )


            if not np.all(
                np.isfinite(
                    matrix
                )
            ):

                raise RuntimeError(

                    f"{split_name} contains "
                    "NaN or infinity."
                )


        if (

            len(
                dataset[
                    "X_train"
                ]
            )

            < MINIMUM_TRAIN_WINDOWS

        ):

            raise RuntimeError(

                "Not enough temporal training windows."
            )


        if (

            len(
                dataset[
                    "X_validation"
                ]
            )

            < MINIMUM_VALIDATION_WINDOWS

        ):

            raise RuntimeError(

                "Not enough temporal validation windows."
            )


        return feature_names


    # ============================================================
    # DATA LOADERS
    # ============================================================

    def create_loaders(
        self,
        dataset,
    ):

        train_tensor = torch.tensor(

            dataset[
                "X_train"
            ],

            dtype=torch.float32,
        )


        validation_tensor = torch.tensor(

            dataset[
                "X_validation"
            ],

            dtype=torch.float32,
        )


        train_loader = (
            DataLoader(

                TensorDataset(
                    train_tensor
                ),

                batch_size=
                    BATCH_SIZE,

                shuffle=
                    True,

                drop_last=
                    False,
            )
        )


        validation_loader = (
            DataLoader(

                TensorDataset(
                    validation_tensor
                ),

                batch_size=
                    BATCH_SIZE,

                shuffle=
                    False,

                drop_last=
                    False,
            )
        )


        return (
            train_loader,
            validation_loader,
        )


    # ============================================================
    # TRAIN MASK
    # ============================================================

    def create_training_mask(
        self,
        batch: torch.Tensor,
    ) -> torch.Tensor:

        batch_size = (
            batch.shape[
                0
            ]
        )


        sequence_length = (
            batch.shape[
                1
            ]
        )


        mask = (

            torch.rand(

                (
                    batch_size,
                    sequence_length,
                ),

                device=
                    batch.device,
            )

            < TIMESTEP_MASK_PROBABILITY
        )


        # --------------------------------------------------------
        # Guarantee at least one masked timestep per sequence.
        # --------------------------------------------------------

        missing = (

            ~mask.any(
                dim=1
            )
        )


        indices = torch.nonzero(

            missing,

            as_tuple=False,
        ).flatten()


        if indices.numel() > 0:

            random_timesteps = torch.randint(

                low=0,

                high=
                    sequence_length,

                size=(
                    indices.numel(),
                ),

                device=
                    batch.device,
            )


            mask[
                indices,
                random_timesteps
            ] = True


        return mask


    # ============================================================
    # DETERMINISTIC VALIDATION MASK
    # ============================================================

    def create_validation_mask(
        self,
        batch_size: int,
        sequence_length: int,
        generator: torch.Generator,
    ):

        random_values = torch.rand(

            (
                batch_size,
                sequence_length,
            ),

            generator=
                generator,
        )


        mask = (

            random_values

            < TIMESTEP_MASK_PROBABILITY
        )


        for index in range(
            batch_size
        ):

            if not bool(
                mask[
                    index
                ].any()
            ):

                timestep = int(

                    torch.randint(

                        low=0,

                        high=
                            sequence_length,

                        size=(
                            1,
                        ),

                        generator=
                            generator,
                    ).item()
                )


                mask[
                    index,
                    timestep
                ] = True


        return mask


    # ============================================================
    # MASKED TIMESTEP LOSS
    # ============================================================

    def masked_timestep_mse(
        self,
        reconstruction: torch.Tensor,
        target: torch.Tensor,
        timestep_mask: torch.Tensor,
    ) -> torch.Tensor:

        squared_error = (

            reconstruction
            - target

        ) ** 2


        # --------------------------------------------------------
        # Mean across 26 features first.
        #
        # Result:
        #
        #       (batch, sequence)
        # --------------------------------------------------------

        timestep_error = torch.mean(

            squared_error,

            dim=2,
        )


        masked_errors = (

            timestep_error[
                timestep_mask
            ]
        )


        if masked_errors.numel() == 0:

            raise RuntimeError(

                "Masked timestep loss received "
                "an empty mask."
            )


        return torch.mean(
            masked_errors
        )


    # ============================================================
    # TRAIN EPOCH
    # ============================================================

    def train_epoch(
        self,
        loader,
        optimizer,
    ) -> float:

        self.model.train()


        losses = []


        for (
            batch,
        ) in loader:

            batch = (
                batch.to(
                    self.device
                )
            )


            mask = (
                self.create_training_mask(
                    batch
                )
            )


            (
                reconstruction,
                _,
                _,

            ) = self.model(

                batch,

                timestep_mask=
                    mask,
            )


            loss = (
                self.masked_timestep_mse(

                    reconstruction=
                        reconstruction,

                    target=
                        batch,

                    timestep_mask=
                        mask,
                )
            )


            optimizer.zero_grad(
                set_to_none=True
            )


            loss.backward()


            torch.nn.utils.clip_grad_norm_(

                self.model.parameters(),

                max_norm=
                    GRADIENT_CLIP_NORM,
            )


            optimizer.step()


            losses.append(

                float(
                    loss.detach().cpu()
                )
            )


        if not losses:

            raise RuntimeError(

                "Training loader produced no batches."
            )


        return float(
            np.mean(
                losses
            )
        )


    # ============================================================
    # VALIDATION LOSS
    # ============================================================

    def validation_loss(
        self,
        loader,
    ) -> float:

        self.model.eval()


        losses = []


        generator = (
            torch.Generator(
                device="cpu"
            )
        )


        generator.manual_seed(
            VALIDATION_MASK_SEED
        )


        with torch.no_grad():

            for (
                batch,
            ) in loader:

                mask_cpu = (
                    self.create_validation_mask(

                        batch_size=
                            batch.shape[
                                0
                            ],

                        sequence_length=
                            batch.shape[
                                1
                            ],

                        generator=
                            generator,
                    )
                )


                batch = (
                    batch.to(
                        self.device
                    )
                )


                mask = (
                    mask_cpu.to(
                        self.device
                    )
                )


                (
                    reconstruction,
                    _,
                    _,

                ) = self.model(

                    batch,

                    timestep_mask=
                        mask,
                )


                loss = (
                    self.masked_timestep_mse(

                        reconstruction=
                            reconstruction,

                        target=
                            batch,

                        timestep_mask=
                            mask,
                    )
                )


                losses.append(

                    float(
                        loss.detach().cpu()
                    )
                )


        if not losses:

            raise RuntimeError(

                "Validation loader produced no batches."
            )


        return float(
            np.mean(
                losses
            )
        )


    # ============================================================
    # TRAIN
    # ============================================================

    def train(
        self,
        dataset,
    ):

        (
            train_loader,
            validation_loader,

        ) = self.create_loaders(
            dataset
        )


        optimizer = (
            torch.optim.AdamW(

                self.model.parameters(),

                lr=
                    LEARNING_RATE,

                weight_decay=
                    WEIGHT_DECAY,
            )
        )


        scheduler = (
            torch.optim.lr_scheduler.ReduceLROnPlateau(

                optimizer,

                mode=
                    "min",

                factor=
                    LR_FACTOR,

                patience=
                    LR_PATIENCE,

                min_lr=
                    MIN_LEARNING_RATE,
            )
        )


        best_validation_loss = (
            float(
                "inf"
            )
        )


        best_epoch = 0

        best_state = None

        epochs_without_improvement = 0

        history = []


        print()

        print(

            f"{'Epoch':<8}"
            f"{'Train Loss':>14}"
            f"{'Val Loss':>14}"
            f"{'LR':>14}"
        )


        print(
            "-" * 52
        )


        for epoch in range(
            1,
            MAX_EPOCHS + 1,
        ):

            train_loss = (
                self.train_epoch(

                    loader=
                        train_loader,

                    optimizer=
                        optimizer,
                )
            )


            validation_loss = (
                self.validation_loss(
                    validation_loader
                )
            )


            scheduler.step(
                validation_loss
            )


            learning_rate = float(

                optimizer
                .param_groups[
                    0
                ][
                    "lr"
                ]
            )


            history.append(
                {
                    "epoch":
                        epoch,

                    "train_loss":
                        train_loss,

                    "validation_loss":
                        validation_loss,

                    "learning_rate":
                        learning_rate,
                }
            )


            print(

                f"{epoch:<8}"

                f"{train_loss:>14.6f}"

                f"{validation_loss:>14.6f}"

                f"{learning_rate:>14.8f}"
            )


            # ====================================================
            # BEST CHECKPOINT
            # ====================================================

            if (

                validation_loss

                < (
                    best_validation_loss
                    - 1e-6
                )

            ):

                best_validation_loss = (
                    validation_loss
                )


                best_epoch = (
                    epoch
                )


                best_state = copy.deepcopy(

                    self.model.state_dict()
                )


                epochs_without_improvement = 0


            else:

                epochs_without_improvement += 1


            # ====================================================
            # EARLY STOP
            # ====================================================

            if (

                epochs_without_improvement

                >= EARLY_STOPPING_PATIENCE

            ):

                print()

                print(
                    "Early stopping triggered."
                )

                break


        if best_state is None:

            raise RuntimeError(

                "No valid Transformer checkpoint "
                "was created."
            )


        self.model.load_state_dict(
            best_state
        )


        return {
            "best_epoch":
                best_epoch,

            "best_validation_loss":
                best_validation_loss,

            "epochs_completed":
                len(
                    history
                ),

            "history":
                history,
        }


    # ============================================================
    # LEAVE-ONE-TIMESTEP-OUT ERROR
    #
    # This becomes the anomaly signal in the next calibration step.
    # ============================================================

    def calculate_loto_errors(
        self,
        matrix: np.ndarray,
    ) -> np.ndarray:

        self.model.eval()


        tensor = torch.tensor(

            matrix,

            dtype=torch.float32,
        )


        loader = DataLoader(

            TensorDataset(
                tensor
            ),

            batch_size=
                BATCH_SIZE,

            shuffle=
                False,
        )


        sequence_errors = []


        with torch.no_grad():

            for (
                batch,
            ) in loader:

                batch = (
                    batch.to(
                        self.device
                    )
                )


                per_timestep = []


                for timestep in range(
                    SEQUENCE_LENGTH
                ):

                    mask = torch.zeros(

                        (
                            batch.shape[
                                0
                            ],

                            SEQUENCE_LENGTH,
                        ),

                        dtype=torch.bool,

                        device=
                            self.device,
                    )


                    mask[
                        :,
                        timestep
                    ] = True


                    (
                        reconstruction,
                        _,
                        _,

                    ) = self.model(

                        batch,

                        timestep_mask=
                            mask,
                    )


                    error = torch.mean(

                        (
                            reconstruction[
                                :,
                                timestep,
                                :
                            ]

                            - batch[
                                :,
                                timestep,
                                :
                            ]
                        )
                        ** 2,

                        dim=1,
                    )


                    per_timestep.append(
                        error
                    )


                stacked = torch.stack(

                    per_timestep,

                    dim=1,
                )


                averaged = torch.mean(

                    stacked,

                    dim=1,
                )


                sequence_errors.extend(

                    averaged
                    .detach()
                    .cpu()
                    .numpy()
                    .tolist()
                )


        return np.asarray(

            sequence_errors,

            dtype=np.float64,
        )


    # ============================================================
    # EXTRACT REPRESENTATIONS
    # ============================================================

    def extract_representations(
        self,
        matrix: np.ndarray,
    ):

        self.model.eval()


        tensor = torch.tensor(

            matrix,

            dtype=torch.float32,
        )


        loader = DataLoader(

            TensorDataset(
                tensor
            ),

            batch_size=
                BATCH_SIZE,

            shuffle=
                False,
        )


        representations = []


        with torch.no_grad():

            for (
                batch,
            ) in loader:

                batch = (
                    batch.to(
                        self.device
                    )
                )


                (
                    _,
                    representation,

                ) = self.model.encode(

                    batch,

                    timestep_mask=
                        None,
                )


                representations.append(

                    representation
                    .detach()
                    .cpu()
                    .numpy()
                )


        if not representations:

            raise RuntimeError(

                "No temporal representations generated."
            )


        return np.concatenate(

            representations,

            axis=0,
        )


    # ============================================================
    # REPRESENTATION HEALTH
    # ============================================================

    def analyze_representation_health(
        self,
        representations: np.ndarray,
    ):

        if representations.ndim != 2:

            raise RuntimeError(

                "Representation matrix must be 2D."
            )


        sample_count = int(

            representations.shape[
                0
            ]
        )


        dimension_count = int(

            representations.shape[
                1
            ]
        )


        dimension_stds = np.std(

            representations,

            axis=0,
        )


        active_mask = (

            dimension_stds

            > REPRESENTATION_STD_THRESHOLD
        )


        active_count = int(

            np.sum(
                active_mask
            )
        )


        active_percent = (

            active_count

            / max(
                dimension_count,
                1,
            )

            * 100.0
        )


        rounded = np.round(

            representations,

            decimals=5,
        )


        unique_count = len(
            {
                tuple(
                    row.tolist()
                )

                for row
                in rounded
            }
        )


        unique_percent = (

            unique_count

            / max(
                sample_count,
                1,
            )

            * 100.0
        )


        centered = (

            representations

            - np.mean(

                representations,

                axis=0,
            )
        )


        matrix_rank = int(

            np.linalg.matrix_rank(
                centered
            )
        )


        mean_std = float(

            np.mean(
                dimension_stds
            )
        )


        checks = {
            "active_dimensions":
                (
                    active_percent

                    >= MIN_ACTIVE_DIMENSION_PERCENT
                ),

            "representation_diversity":
                (
                    unique_percent

                    >= MIN_UNIQUE_REPRESENTATION_PERCENT
                ),

            "nonzero_variance":
                (
                    mean_std

                    > REPRESENTATION_STD_THRESHOLD
                ),
        }


        healthy = all(
            checks.values()
        )


        return {
            "healthy":
                healthy,

            "sample_count":
                sample_count,

            "dimension_count":
                dimension_count,

            "active_dimension_count":
                active_count,

            "active_dimension_percent":
                active_percent,

            "unique_representation_count":
                unique_count,

            "unique_representation_percent":
                unique_percent,

            "mean_dimension_std":
                mean_std,

            "minimum_dimension_std":
                float(
                    np.min(
                        dimension_stds
                    )
                ),

            "maximum_dimension_std":
                float(
                    np.max(
                        dimension_stds
                    )
                ),

            "matrix_rank":
                matrix_rank,

            "checks":
                checks,
        }


    # ============================================================
    # SAVE
    #
    # Important V2 improvement:
    #
    # The .pt checkpoint contains only:
    #
    #       tensors
    #       primitive strings/numbers/dicts
    #
    # torch.__version__ is converted to str.
    #
    # Therefore the checkpoint can be loaded using:
    #
    #       weights_only=True
    #
    # without the PyTorch 2.6 error encountered in V1.
    # ============================================================

    def save_artifacts(
        self,
        metadata,
    ):

        self.ensure_directories()


        # ========================================================
        # METADATA JSON
        # ========================================================

        with open(

            METADATA_PATH,

            "w",

            encoding="utf-8",

        ) as file:

            json.dump(

                metadata,

                file,

                indent=4,

                sort_keys=False,
            )


        # ========================================================
        # SAFE CHECKPOINT
        # ========================================================

        artifact = {
            "format_version":
                2,

            "model_state_dict":
                self.model.state_dict(),

            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,

            "model_type":
                MODEL_TYPE,

            "schema_version":
                SCHEMA_VERSION,

            "config":
                self.model.get_config(),

            "metadata_filename":
                METADATA_PATH.name,
        }


        torch.save(

            artifact,

            MODEL_PATH,
        )


        # ========================================================
        # IMMEDIATE RESTRICTED-LOADER VERIFICATION
        # ========================================================

        verification = torch.load(

            MODEL_PATH,

            map_location=
                "cpu",

            weights_only=
                True,
        )


        if (

            verification.get(
                "model_version"
            )

            != MODEL_VERSION

        ):

            raise RuntimeError(

                "Saved Transformer v2 checkpoint "
                "verification failed."
            )


    # ============================================================
    # RUN
    # ============================================================

    def run(
        self,
    ):

        self.ensure_directories()


        print()

        print(
            "=" * 92
        )

        print(
            "SENTINEL-X TEMPORAL TRANSFORMER V2"
        )

        print(
            "=" * 92
        )


        print()

        print(
            "Device:",
            self.device,
        )


        # ========================================================
        # 1
        # ========================================================

        print()

        print(
            "[1/8] Loading corrected temporal dataset..."
        )


        dataset = (
            self.load_dataset()
        )


        print(
            "Train      :",
            dataset[
                "X_train"
            ].shape,
        )


        print(
            "Validation :",
            dataset[
                "X_validation"
            ].shape,
        )


        print(
            "Test       :",
            dataset[
                "X_test"
            ].shape,
        )


        # ========================================================
        # 2
        # ========================================================

        print()

        print(
            "[2/8] Validating 26D temporal schema..."
        )


        feature_names = (
            self.validate_dataset(
                dataset
            )
        )


        print(
            "Feature count:",
            len(
                feature_names
            ),
        )


        print(
            "process_age_seconds present:",
            FORBIDDEN_FEATURE
            in feature_names,
        )


        print(
            "Dataset validation: PASS"
        )


        # ========================================================
        # 3
        # ========================================================

        print()

        print(
            "[3/8] Training Temporal Transformer v2..."
        )


        training = (
            self.train(
                dataset
            )
        )


        print()

        print(
            "Best epoch:",
            training[
                "best_epoch"
            ],
        )


        print(
            "Best validation loss:",
            round(
                training[
                    "best_validation_loss"
                ],
                8,
            ),
        )


        # ========================================================
        # 4
        # ========================================================

        print()

        print(
            "[4/8] Calculating train LOTO errors..."
        )


        train_errors = (
            self.calculate_loto_errors(

                dataset[
                    "X_train"
                ]
            )
        )


        train_error_stats = (
            percentile_statistics(
                train_errors
            )
        )


        print(
            "Train LOTO mean:",
            round(
                train_error_stats[
                    "mean"
                ],
                8,
            ),
        )


        print(
            "Train LOTO P95:",
            round(
                train_error_stats[
                    "p95"
                ],
                8,
            ),
        )


        # ========================================================
        # 5
        # ========================================================

        print()

        print(
            "[5/8] Calculating validation LOTO errors..."
        )


        validation_errors = (
            self.calculate_loto_errors(

                dataset[
                    "X_validation"
                ]
            )
        )


        validation_error_stats = (
            percentile_statistics(
                validation_errors
            )
        )


        print(
            "Validation LOTO mean:",
            round(
                validation_error_stats[
                    "mean"
                ],
                8,
            ),
        )


        print(
            "Validation P95:",
            round(
                validation_error_stats[
                    "p95"
                ],
                8,
            ),
        )


        print(
            "Validation P99:",
            round(
                validation_error_stats[
                    "p99"
                ],
                8,
            ),
        )


        # ========================================================
        # 6
        # ========================================================

        print()

        print(
            "[6/8] Checking temporal representation health..."
        )


        validation_representations = (
            self.extract_representations(

                dataset[
                    "X_validation"
                ]
            )
        )


        representation_health = (
            self.analyze_representation_health(
                validation_representations
            )
        )


        print(
            "Representation dimension:",
            representation_health[
                "dimension_count"
            ],
        )


        print(
            "Active dimensions:",
            (
                f"{representation_health['active_dimension_count']}"
                "/"
                f"{representation_health['dimension_count']}"
            ),
        )


        print(
            "Active dimension %:",
            round(
                representation_health[
                    "active_dimension_percent"
                ],
                2,
            ),
        )


        print(
            "Unique representations:",
            (
                f"{representation_health['unique_representation_percent']:.2f}%"
            ),
        )


        print(
            "Representation rank:",
            representation_health[
                "matrix_rank"
            ],
        )


        print(
            "Representation health:",
            (
                "PASS"

                if representation_health[
                    "healthy"
                ]

                else "REVIEW"
            ),
        )


        # ========================================================
        # 7
        #
        # BUILD METADATA
        #
        # IMPORTANT:
        #
        # TEST SPLIT STILL NOT EVALUATED.
        # ========================================================

        print()

        print(
            "[7/8] Building model metadata..."
        )


        metadata = {
            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,

            "model_type":
                MODEL_TYPE,

            "schema_version":
                SCHEMA_VERSION,

            "trained_at":
                now_iso(),

            "device_used":
                str(
                    self.device
                ),

            "source_dataset":
                str(
                    DATASET_PATH
                ),

            "source_dataset_sha256":
                sha256_file(
                    DATASET_PATH
                ),

            "architecture":
                self.model.get_config(),

            "feature_policy": {
                "input_feature_count":
                    INPUT_FEATURE_COUNT,

                "removed_feature":
                    FORBIDDEN_FEATURE,

                "reason":
                    (
                        "Live/train diagnostic measured severe "
                        "non-stationary distribution shift for "
                        "absolute process age."
                    ),
            },

            "self_supervised_objective": {
                "type":
                    "masked_complete_timestep_reconstruction",

                "timestep_mask_probability":
                    TIMESTEP_MASK_PROBABILITY,

                "mask_representation":
                    "learned_mask_token",

                "ground_truth_labels_used":
                    False,
            },

            "training": {
                "batch_size":
                    BATCH_SIZE,

                "maximum_epochs":
                    MAX_EPOCHS,

                "learning_rate":
                    LEARNING_RATE,

                "weight_decay":
                    WEIGHT_DECAY,

                "early_stopping_patience":
                    EARLY_STOPPING_PATIENCE,

                "best_epoch":
                    training[
                        "best_epoch"
                    ],

                "best_validation_loss":
                    training[
                        "best_validation_loss"
                    ],

                "epochs_completed":
                    training[
                        "epochs_completed"
                    ],

                "history":
                    training[
                        "history"
                    ],
            },

            "train_leave_one_timestep_out_error":
                train_error_stats,

            "validation_leave_one_timestep_out_error":
                validation_error_stats,

            "representation_health":
                representation_health,

            "temporal_feature_names":
                feature_names,

            "dataset_counts": {
                "train_windows":
                    int(
                        len(
                            dataset[
                                "X_train"
                            ]
                        )
                    ),

                "validation_windows":
                    int(
                        len(
                            dataset[
                                "X_validation"
                            ]
                        )
                    ),

                "test_windows_held_out":
                    int(
                        len(
                            dataset[
                                "X_test"
                            ]
                        )
                    ),
            },

            "test_split_used":
                False,

            "test_policy":
                (
                    "Test split remains untouched during "
                    "training and calibration preparation."
                ),

            "runtime": {
                "python":
                    str(
                        sys.version
                    ),

                "platform":
                    str(
                        platform.platform()
                    ),

                "numpy":
                    str(
                        np.__version__
                    ),

                "torch":
                    str(
                        torch.__version__
                    ),
            },

            "scientific_note":
                (
                    "This model learns temporal consistency from "
                    "unlabeled endpoint observations. "
                    "Reconstruction error is not a probability "
                    "of malicious activity."
                ),
        }


        # ========================================================
        # 8
        # ========================================================

        print()

        print(
            "[8/8] Saving safe Transformer v2 artifact..."
        )


        self.save_artifacts(
            metadata
        )


        print()

        print(
            "=" * 92
        )

        print(
            "TEMPORAL TRANSFORMER V2 TRAINING COMPLETE"
        )

        print(
            "=" * 92
        )


        print()

        print(
            "Model:"
        )

        print(
            MODEL_PATH
        )


        print()

        print(
            "Metadata:"
        )

        print(
            METADATA_PATH
        )


        print()

        print(
            "Input:"
        )

        print(
            "(batch, 8, 26)"
        )


        print()

        print(
            "Removed feature:"
        )

        print(
            FORBIDDEN_FEATURE
        )


        print()

        print(
            "Representation:"
        )

        print(
            f"{D_MODEL} dimensions"
        )


        print()

        print(
            "Safe weights_only checkpoint:"
        )

        print(
            "PASS"
        )


        print()

        print(
            "Test split used:"
        )

        print(
            "NO"
        )


        print()

        if representation_health[
            "healthy"
        ]:

            print(
                "TEMPORAL TRANSFORMER V2: PASS"
            )

        else:

            print(
                "TEMPORAL TRANSFORMER V2: REVIEW REQUIRED"
            )


        return metadata


# ================================================================
# SAFE MODEL LOADER
# ================================================================

def load_process_temporal_transformer_v2(
    model_path: str | Path = MODEL_PATH,
    device: str | torch.device = "cpu",
):

    model_path = Path(
        model_path
    )


    if not model_path.exists():

        raise FileNotFoundError(

            "Temporal Transformer v2 not found:\n"
            f"{model_path}"
        )


    # ============================================================
    # PYTORCH 2.6+ SAFE LOAD
    # ============================================================

    artifact = torch.load(

        model_path,

        map_location=
            device,

        weights_only=
            True,
    )


    required = {
        "model_state_dict",
        "model_name",
        "model_version",
        "schema_version",
        "config",
    }


    missing = (

        required

        - set(
            artifact.keys()
        )
    )


    if missing:

        raise RuntimeError(

            "Invalid Temporal Transformer v2 artifact. "
            f"Missing: {sorted(missing)}"
        )


    config = (
        artifact[
            "config"
        ]
    )


    if (

        int(
            config[
                "input_feature_count"
            ]
        )

        != INPUT_FEATURE_COUNT

    ):

        raise RuntimeError(

            "Temporal Transformer v2 feature count mismatch."
        )


    model = (
        ProcessTemporalTransformerV2(

            input_feature_count=
                int(
                    config[
                        "input_feature_count"
                    ]
                ),

            sequence_length=
                int(
                    config[
                        "sequence_length"
                    ]
                ),

            d_model=
                int(
                    config[
                        "d_model"
                    ]
                ),

            nhead=
                int(
                    config[
                        "nhead"
                    ]
                ),

            num_encoder_layers=
                int(
                    config[
                        "num_encoder_layers"
                    ]
                ),

            dim_feedforward=
                int(
                    config[
                        "dim_feedforward"
                    ]
                ),

            dropout=
                float(
                    config[
                        "dropout"
                    ]
                ),
        )
    )


    model.load_state_dict(

        artifact[
            "model_state_dict"
        ]
    )


    model = (
        model.to(
            device
        )
    )


    model.eval()


    # ============================================================
    # LOAD HUMAN-READABLE METADATA
    # ============================================================

    metadata = {}


    if METADATA_PATH.exists():

        with open(

            METADATA_PATH,

            "r",

            encoding="utf-8",

        ) as file:

            metadata = (
                json.load(
                    file
                )
            )


    artifact[
        "metadata"
    ] = metadata


    return (
        model,
        artifact,
    )


# ================================================================
# ENTRY
# ================================================================

if __name__ == "__main__":

    trainer = (
        ProcessTemporalTransformerV2Trainer()
    )


    trainer.run()