from __future__ import annotations

import copy
import hashlib
import json
import math
import platform
import random
import sys

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import torch

from torch import nn
from torch.utils.data import (
    DataLoader,
    TensorDataset,
)


# ================================================================
# SENTINEL-X TEMPORAL TRANSFORMER V1
#
# SELF-SUPERVISED TEMPORAL REPRESENTATION LEARNING
#
# Input:
#
#       (batch, 8, 27)
#
#       8 chronological endpoint observations
#       27 features per observation
#
# Training objective:
#
#       masked temporal reconstruction
#
# No malicious/benign labels are used.
#
# A timestep is hidden from the model and the Transformer must
# reconstruct it from the surrounding process behavior.
#
# This creates a temporal behavioral representation that can later
# be used for:
#
#       temporal anomaly detection
#       attack-chain reasoning
#       vector representation
#       fusion with other detection engines
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
    / "process_sequence_splits_v1.npz"
)


MODEL_DIRECTORY = (
    PROJECT_ROOT
    / "models"
    / "temporal"
)


MODEL_PATH = (
    MODEL_DIRECTORY
    / "sentinelx_process_temporal_transformer_v1.pt"
)


METADATA_PATH = (
    MODEL_DIRECTORY
    / "sentinelx_process_temporal_transformer_v1_metadata.json"
)


# ================================================================
# MODEL IDENTITY
# ================================================================

MODEL_NAME = (
    "sentinelx_process_temporal_transformer"
)


MODEL_VERSION = "v1"


MODEL_TYPE = (
    "SelfSupervisedMaskedTemporalTransformer"
)


# ================================================================
# INPUT
# ================================================================

SEQUENCE_LENGTH = 8

INPUT_FEATURE_COUNT = 27


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
# Whole timesteps are masked to force temporal reasoning.
#
# Additional individual features are also randomly masked.
# ================================================================

TIMESTEP_MASK_PROBABILITY = 0.20

FEATURE_MASK_PROBABILITY = 0.05


# ================================================================
# TRAINING
# ================================================================

BATCH_SIZE = 32

MAX_EPOCHS = 120

LEARNING_RATE = 1e-3

WEIGHT_DECAY = 1e-5

EARLY_STOPPING_PATIENCE = 15

LR_PATIENCE = 5

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
# TRANSFORMER MODEL
# ================================================================

class ProcessTemporalTransformer(
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


        self.input_feature_count = (
            int(
                input_feature_count
            )
        )


        self.sequence_length = (
            int(
                sequence_length
            )
        )


        self.d_model = (
            int(
                d_model
            )
        )


        # ========================================================
        # INPUT PROJECTION
        #
        # 27 endpoint features → 64-dimensional token
        # ========================================================

        self.input_projection = (
            nn.Linear(
                self.input_feature_count,
                self.d_model,
            )
        )


        # ========================================================
        # LEARNED POSITIONAL EMBEDDING
        #
        # Allows the Transformer to distinguish:
        #
        #       timestep 0
        #       timestep 1
        #       ...
        #       timestep 7
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
        # TRANSFORMER
        # ========================================================

        encoder_layer = (
            nn.TransformerEncoderLayer(

                d_model=
                    self.d_model,

                nhead=
                    nhead,

                dim_feedforward=
                    dim_feedforward,

                dropout=
                    dropout,

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
                    num_encoder_layers,
            )
        )


        self.output_norm = (
            nn.LayerNorm(
                self.d_model
            )
        )


        # ========================================================
        # RECONSTRUCTION HEAD
        #
        # 64 temporal representation → original 27 features
        # ========================================================

        self.reconstruction_head = (
            nn.Sequential(

                nn.Linear(
                    self.d_model,
                    self.d_model,
                ),

                nn.GELU(),

                nn.Dropout(
                    dropout
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
    ) -> Tuple[
        torch.Tensor,
        torch.Tensor,
    ]:

        if x.ndim != 3:

            raise RuntimeError(

                "Temporal Transformer input must have shape "
                "(batch, sequence, features)."
            )


        if x.shape[
            1
        ] != self.sequence_length:

            raise RuntimeError(

                "Unexpected sequence length: "
                f"{x.shape[1]}"
            )


        if x.shape[
            2
        ] != self.input_feature_count:

            raise RuntimeError(

                "Unexpected feature count: "
                f"{x.shape[2]}"
            )


        tokens = (
            self.input_projection(
                x
            )
        )


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


        # --------------------------------------------------------
        # One representation for the complete 8-step sequence.
        #
        # Mean pooling avoids introducing a special CLS token in
        # this first model.
        # --------------------------------------------------------

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
    ) -> Tuple[
        torch.Tensor,
        torch.Tensor,
        torch.Tensor,
    ]:

        (
            encoded,
            representation,

        ) = self.encode(
            x
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
                NHEAD,

            "num_encoder_layers":
                NUM_ENCODER_LAYERS,

            "dim_feedforward":
                DIM_FEEDFORWARD,

            "dropout":
                DROPOUT,

            "representation_dimension":
                self.d_model,
        }


# ================================================================
# TRAINER
# ================================================================

class ProcessTemporalTransformerTrainer:

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
            ProcessTemporalTransformer()
            .to(
                self.device
            )
        )


    # ============================================================
    # DIRECTORIES
    # ============================================================

    def ensure_directories(
        self,
    ) -> None:

        MODEL_DIRECTORY.mkdir(
            parents=True,
            exist_ok=True,
        )


    # ============================================================
    # LOAD DATA
    # ============================================================

    def load_dataset(
        self,
    ) -> Dict[str, np.ndarray]:

        if not DATASET_PATH.exists():

            raise FileNotFoundError(

                "Temporal split dataset not found:\n"
                f"{DATASET_PATH}\n\n"
                "Run the Step-21 temporal preprocessor first."
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

                "Temporal dataset missing arrays: "
                f"{sorted(missing)}"
            )


        return {
            name:
                np.asarray(
                    data[
                        name
                    ]
                )

            for name in data.files
        }


    # ============================================================
    # VALIDATE
    # ============================================================

    def validate_dataset(
        self,
        dataset: Dict[str, np.ndarray],
    ) -> None:

        X_train = (
            dataset[
                "X_train"
            ]
        )


        X_validation = (
            dataset[
                "X_validation"
            ]
        )


        X_test = (
            dataset[
                "X_test"
            ]
        )


        for (
            name,
            matrix,
        ) in [
            (
                "X_train",
                X_train,
            ),
            (
                "X_validation",
                X_validation,
            ),
            (
                "X_test",
                X_test,
            ),
        ]:

            if matrix.ndim != 3:

                raise RuntimeError(

                    f"{name} must have shape "
                    "(windows, sequence, features). "
                    f"Received {matrix.shape}"
                )


            if matrix.shape[
                1
            ] != SEQUENCE_LENGTH:

                raise RuntimeError(

                    f"{name} sequence length must be "
                    f"{SEQUENCE_LENGTH}."
                )


            if matrix.shape[
                2
            ] != INPUT_FEATURE_COUNT:

                raise RuntimeError(

                    f"{name} feature count must be "
                    f"{INPUT_FEATURE_COUNT}."
                )


            if not np.all(
                np.isfinite(
                    matrix
                )
            ):

                raise RuntimeError(

                    f"{name} contains NaN or infinity."
                )


        if (

            len(
                X_train
            )

            < MINIMUM_TRAIN_WINDOWS

        ):

            raise RuntimeError(

                f"Only {len(X_train)} training windows exist. "
                f"At least {MINIMUM_TRAIN_WINDOWS} are required."
            )


        if (

            len(
                X_validation
            )

            < MINIMUM_VALIDATION_WINDOWS

        ):

            raise RuntimeError(

                f"Only {len(X_validation)} validation windows exist. "
                f"At least {MINIMUM_VALIDATION_WINDOWS} are required."
            )


        if len(
            dataset[
                "temporal_feature_names"
            ]
        ) != INPUT_FEATURE_COUNT:

            raise RuntimeError(

                "Temporal feature-name count mismatch."
            )


    # ============================================================
    # DATA LOADERS
    # ============================================================

    def create_loaders(
        self,
        dataset: Dict[str, np.ndarray],
    ):

        X_train = torch.tensor(

            dataset[
                "X_train"
            ],

            dtype=torch.float32,
        )


        X_validation = torch.tensor(

            dataset[
                "X_validation"
            ],

            dtype=torch.float32,
        )


        train_dataset = (
            TensorDataset(
                X_train
            )
        )


        validation_dataset = (
            TensorDataset(
                X_validation
            )
        )


        train_loader = (
            DataLoader(

                train_dataset,

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

                validation_dataset,

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
    # TRAINING MASK
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


        feature_count = (
            batch.shape[
                2
            ]
        )


        # ========================================================
        # TIMESTEP MASK
        # ========================================================

        timestep_mask = (

            torch.rand(

                batch_size,
                sequence_length,

                device=
                    batch.device,
            )

            < TIMESTEP_MASK_PROBABILITY
        )


        # --------------------------------------------------------
        # Guarantee every sequence has at least one masked
        # timestep.
        # --------------------------------------------------------

        missing_mask = (

            ~timestep_mask.any(
                dim=1
            )
        )


        missing_indices = (

            torch.nonzero(
                missing_mask,
                as_tuple=False,
            )
            .flatten()
        )


        if len(
            missing_indices
        ) > 0:

            random_timesteps = (

                torch.randint(

                    low=0,

                    high=
                        sequence_length,

                    size=(
                        len(
                            missing_indices
                        ),
                    ),

                    device=
                        batch.device,
                )
            )


            timestep_mask[

                missing_indices,

                random_timesteps,

            ] = True


        timestep_mask = (

            timestep_mask
            .unsqueeze(
                -1
            )
            .expand(

                -1,
                -1,
                feature_count,
            )
        )


        # ========================================================
        # ADDITIONAL FEATURE MASK
        # ========================================================

        feature_mask = (

            torch.rand(

                batch.shape,

                device=
                    batch.device,
            )

            < FEATURE_MASK_PROBABILITY
        )


        mask = (

            timestep_mask

            | feature_mask
        )


        return mask


    # ============================================================
    # VALIDATION MASK
    #
    # Deterministic masking gives comparable validation loss across
    # epochs.
    # ============================================================

    def create_validation_mask(
        self,
        batch: torch.Tensor,
        generator: torch.Generator,
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


        feature_count = (
            batch.shape[
                2
            ]
        )


        timestep_random = torch.rand(

            (
                batch_size,
                sequence_length,
            ),

            generator=
                generator,
        )


        timestep_mask = (

            timestep_random

            < TIMESTEP_MASK_PROBABILITY
        )


        # --------------------------------------------------------
        # Guarantee one complete hidden timestep.
        # --------------------------------------------------------

        for index in range(
            batch_size
        ):

            if not bool(
                timestep_mask[
                    index
                ].any()
            ):

                timestep = int(

                    torch.randint(

                        0,
                        sequence_length,
                        (
                            1,
                        ),

                        generator=
                            generator,
                    ).item()
                )


                timestep_mask[
                    index,
                    timestep
                ] = True


        timestep_mask = (

            timestep_mask
            .unsqueeze(
                -1
            )
            .expand(

                -1,
                -1,
                feature_count,
            )
        )


        feature_mask = (

            torch.rand(

                batch.shape,

                generator=
                    generator,
            )

            < FEATURE_MASK_PROBABILITY
        )


        mask = (

            timestep_mask

            | feature_mask
        )


        return mask.to(
            batch.device
        )


    # ============================================================
    # MASKED LOSS
    # ============================================================

    def masked_mse_loss(
        self,
        reconstruction: torch.Tensor,
        target: torch.Tensor,
        mask: torch.Tensor,
    ) -> torch.Tensor:

        squared_error = (

            reconstruction
            - target

        ) ** 2


        masked_error = (
            squared_error[
                mask
            ]
        )


        if masked_error.numel() == 0:

            raise RuntimeError(

                "No masked elements available for "
                "self-supervised loss."
            )


        return torch.mean(
            masked_error
        )


    # ============================================================
    # TRAIN ONE EPOCH
    # ============================================================

    def train_epoch(
        self,
        loader: DataLoader,
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


            corrupted = (
                batch.clone()
            )


            # ----------------------------------------------------
            # Dataset has already been standardized.
            #
            # Zero represents approximately the training mean.
            # ----------------------------------------------------

            corrupted[
                mask
            ] = 0.0


            (
                reconstruction,
                _,
                _,

            ) = self.model(
                corrupted
            )


            loss = (
                self.masked_mse_loss(

                    reconstruction=
                        reconstruction,

                    target=
                        batch,

                    mask=
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


        return float(
            np.mean(
                losses
            )
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    def validation_loss(
        self,
        loader: DataLoader,
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

                batch = (
                    batch.to(
                        self.device
                    )
                )


                mask = (
                    self.create_validation_mask(

                        batch=
                            batch,

                        generator=
                            generator,
                    )
                )


                corrupted = (
                    batch.clone()
                )


                corrupted[
                    mask
                ] = 0.0


                (
                    reconstruction,
                    _,
                    _,

                ) = self.model(
                    corrupted
                )


                loss = (
                    self.masked_mse_loss(

                        reconstruction=
                            reconstruction,

                        target=
                            batch,

                        mask=
                            mask,
                    )
                )


                losses.append(
                    float(
                        loss.detach().cpu()
                    )
                )


        return float(
            np.mean(
                losses
            )
        )


    # ============================================================
    # LEAVE-ONE-TIMESTEP-OUT ERROR
    #
    # Deterministic temporal consistency score.
    #
    # For every timestep:
    #
    #       hide timestep t
    #       reconstruct timestep t
    #       calculate MSE
    #
    # Final sequence error = mean across all 8 timesteps.
    # ============================================================

    def calculate_temporal_reconstruction_errors(
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


                timestep_errors = []


                for timestep in range(
                    SEQUENCE_LENGTH
                ):

                    corrupted = (
                        batch.clone()
                    )


                    corrupted[
                        :,
                        timestep,
                        :
                    ] = 0.0


                    (
                        reconstruction,
                        _,
                        _,

                    ) = self.model(
                        corrupted
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


                    timestep_errors.append(
                        error
                    )


                stacked = torch.stack(

                    timestep_errors,

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
    # REPRESENTATIONS
    # ============================================================

    def extract_representations(
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
                    batch
                )


                representations.append(

                    representation
                    .detach()
                    .cpu()
                    .numpy()
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
    ) -> Dict[str, Any]:

        if representations.ndim != 2:

            raise RuntimeError(

                "Temporal representations must be a 2D matrix."
            )


        sample_count = (
            representations.shape[
                0
            ]
        )


        dimension_count = (
            representations.shape[
                1
            ]
        )


        dimension_stds = np.std(

            representations,

            axis=0,
        )


        active_dimensions = (

            dimension_stds
            > REPRESENTATION_STD_THRESHOLD
        )


        active_dimension_count = int(

            np.sum(
                active_dimensions
            )
        )


        active_dimension_percent = (

            active_dimension_count

            / max(
                1,
                dimension_count
            )

            * 100.0
        )


        rounded = np.round(

            representations,

            decimals=5,
        )


        unique_rows = {

            tuple(
                row.tolist()
            )

            for row in rounded
        }


        unique_count = len(
            unique_rows
        )


        unique_percent = (

            unique_count

            / max(
                1,
                sample_count
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


        rank = int(

            np.linalg.matrix_rank(
                centered
            )
        )


        mean_dimension_std = float(

            np.mean(
                dimension_stds
            )
        )


        checks = {
            "active_dimensions":
                (
                    active_dimension_percent
                    >= MIN_ACTIVE_DIMENSION_PERCENT
                ),

            "representation_diversity":
                (
                    unique_percent
                    >= MIN_UNIQUE_REPRESENTATION_PERCENT
                ),

            "nonzero_variance":
                (
                    mean_dimension_std
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
                active_dimension_count,

            "active_dimension_percent":
                active_dimension_percent,

            "mean_dimension_std":
                mean_dimension_std,

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

            "unique_representation_count":
                unique_count,

            "unique_representation_percent":
                unique_percent,

            "matrix_rank":
                rank,

            "checks":
                checks,
        }


    # ============================================================
    # TRAIN
    # ============================================================

    def train(
        self,
        dataset: Dict[str, np.ndarray],
    ) -> Dict[str, Any]:

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


            val_loss = (
                self.validation_loss(
                    validation_loader
                )
            )


            scheduler.step(
                val_loss
            )


            learning_rate = (

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
                        val_loss,

                    "learning_rate":
                        learning_rate,
                }
            )


            print(

                f"{epoch:<8}"

                f"{train_loss:>14.6f}"

                f"{val_loss:>14.6f}"

                f"{learning_rate:>14.8f}"
            )


            # ====================================================
            # BEST MODEL
            # ====================================================

            if (

                val_loss

                < best_validation_loss
                - 1e-6

            ):

                best_validation_loss = (
                    val_loss
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

                "Temporal Transformer failed to create "
                "a valid training checkpoint."
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
    # SAVE MODEL
    # ============================================================

    def save_model(
        self,
        metadata: Dict[str, Any],
    ) -> None:

        self.ensure_directories()


        artifact = {
            "model_state_dict":
                self.model.state_dict(),

            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,

            "model_type":
                MODEL_TYPE,

            "config":
                self.model.get_config(),

            "metadata":
                metadata,
        }


        torch.save(
            artifact,
            MODEL_PATH,
        )


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


    # ============================================================
    # RUN
    # ============================================================

    def run(
        self,
    ) -> Dict[str, Any]:

        self.ensure_directories()


        print()

        print(
            "=" * 86
        )

        print(
            "SENTINEL-X TEMPORAL TRANSFORMER V1"
        )

        print(
            "=" * 86
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
            "[1/7] Loading normalized temporal splits..."
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
            "[2/7] Validating temporal dataset..."
        )


        self.validate_dataset(
            dataset
        )


        print(
            "Dataset validation: PASS"
        )


        # ========================================================
        # 3
        # ========================================================

        print()

        print(
            "[3/7] Training masked temporal Transformer..."
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
        #
        # Deterministic temporal reconstruction statistics.
        #
        # TEST DATA IS NOT USED.
        # ========================================================

        print()

        print(
            "[4/7] Measuring temporal reconstruction behavior..."
        )


        train_errors = (
            self.calculate_temporal_reconstruction_errors(

                dataset[
                    "X_train"
                ]
            )
        )


        validation_errors = (
            self.calculate_temporal_reconstruction_errors(

                dataset[
                    "X_validation"
                ]
            )
        )


        train_error_stats = (
            percentile_statistics(
                train_errors
            )
        )


        validation_error_stats = (
            percentile_statistics(
                validation_errors
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
        # 5
        # ========================================================

        print()

        print(
            "[5/7] Checking temporal representation health..."
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
            "Health:",
            (
                "PASS"

                if representation_health[
                    "healthy"
                ]

                else "REVIEW"
            ),
        )


        # ========================================================
        # 6
        # METADATA
        # ========================================================

        print()

        print(
            "[6/7] Building model artifact..."
        )


        source_fingerprint = (
            sha256_file(
                DATASET_PATH
            )
        )


        metadata = {
            "model_name":
                MODEL_NAME,

            "model_version":
                MODEL_VERSION,

            "model_type":
                MODEL_TYPE,

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
                source_fingerprint,

            "architecture":
                self.model.get_config(),

            "self_supervised_objective": {
                "type":
                    "masked_temporal_reconstruction",

                "timestep_mask_probability":
                    TIMESTEP_MASK_PROBABILITY,

                "feature_mask_probability":
                    FEATURE_MASK_PROBABILITY,

                "mask_value":
                    0.0,

                "mask_value_reason":
                    (
                        "Input data is standardized; zero "
                        "approximately represents training mean."
                    ),
            },

            "training": {
                "batch_size":
                    BATCH_SIZE,

                "max_epochs":
                    MAX_EPOCHS,

                "learning_rate":
                    LEARNING_RATE,

                "weight_decay":
                    WEIGHT_DECAY,

                "gradient_clip_norm":
                    GRADIENT_CLIP_NORM,

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
                [
                    str(
                        name
                    )

                    for name in dataset[
                        "temporal_feature_names"
                    ]
                ],

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

            "test_usage":
                (
                    "The test split was not used for model "
                    "selection or anomaly calibration during "
                    "this training step."
                ),

            "runtime": {
                "python":
                    sys.version,

                "platform":
                    platform.platform(),

                "numpy":
                    np.__version__,

                "torch":
                    torch.__version__,
            },

            "scientific_note":
                (
                    "This model learns temporal consistency from "
                    "unlabeled endpoint behavior. Reconstruction "
                    "error is not malware probability and does not "
                    "by itself establish malicious activity."
                ),

            "trusted_artifact_warning":
                (
                    "Load only trusted local PyTorch artifacts."
                ),
        }


        # ========================================================
        # 7
        # SAVE
        # ========================================================

        print()

        print(
            "[7/7] Saving Temporal Transformer..."
        )


        self.save_model(
            metadata
        )


        print()

        print(
            "=" * 86
        )

        print(
            "TEMPORAL TRANSFORMER TRAINING COMPLETE"
        )

        print(
            "=" * 86
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
            "Model input:"
        )

        print(
            "(batch, 8, 27)"
        )


        print()

        print(
            "Sequence representation:"
        )

        print(
            f"{D_MODEL} dimensions"
        )


        print()

        print(
            "Validation representation health:"
        )

        print(
            (
                "PASS"

                if representation_health[
                    "healthy"
                ]

                else "REVIEW REQUIRED"
            )
        )


        return metadata


# ================================================================
# LOAD MODEL
# ================================================================

def load_process_temporal_transformer(
    model_path: Path | str = MODEL_PATH,
    device: str | torch.device = "cpu",
):

    model_path = Path(
        model_path
    )


    if not model_path.exists():

        raise FileNotFoundError(

            "Temporal Transformer artifact not found: "
            f"{model_path}"
        )


    artifact = torch.load(

        model_path,

        map_location=
            device,
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
            artifact.keys()
        )
    )


    if missing:

        raise RuntimeError(

            "Invalid Temporal Transformer artifact. "
            f"Missing: {sorted(missing)}"
        )


    config = (
        artifact[
            "config"
        ]
    )


    model = (
        ProcessTemporalTransformer(

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


    return (
        model,
        artifact,
    )


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    trainer = (
        ProcessTemporalTransformerTrainer()
    )


    trainer.run()