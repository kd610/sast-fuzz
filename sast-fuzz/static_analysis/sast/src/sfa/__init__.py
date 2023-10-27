# Copyright 2023 Stephan Lipp
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import namedtuple
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

import yaml


# fmt: off
class SanityChecks(Enum):
    """
    Options of when to run sanity checks.
    """

    ALWAYS = auto(); CMAKE = auto(); NONE = auto()
# fmt: on


ScoreWeights = namedtuple("ScoreWeights", ["flags", "tools"], defaults=[0.5, 0.5])

# SAST tool configuration
SASTToolConfig = namedtuple(
    "SASTToolConfig", ["sanity_checks", "path", "checks", "num_threads"], defaults=[SanityChecks.NONE, "", "", -1]
)


@dataclass
class AppConfig:
    """
    Application configuration.
    """

    score_weights: ScoreWeights

    flawfinder: SASTToolConfig
    semgrep: SASTToolConfig
    infer: SASTToolConfig
    codeql: SASTToolConfig
    clang_scan: SASTToolConfig

    @classmethod
    def from_yaml(cls, file: Path) -> "AppConfig":
        """
        Load configuration from a YAML file.

        :param file:
        :return:
        """
        config = yaml.safe_load(file.read_text())

        codeql_checks = [
            check.replace("%LIBRARY_PATH%", config["tools"]["codeql"]["lib_path"])
            for check in config["tools"]["codeql"]["checks"]
        ]

        return cls(
            ScoreWeights(config["scoring"]["weights"]["flags"], config["scoring"]["weights"]["tools"]),
            flawfinder=SASTToolConfig(
                SanityChecks.NONE, config["tools"]["flawfinder"]["path"], config["tools"]["flawfinder"]["checks"], -1
            ),
            semgrep=SASTToolConfig(
                SanityChecks.NONE,
                config["tools"]["semgrep"]["path"],
                config["tools"]["semgrep"]["checks"],
                config["tools"]["semgrep"]["num_threads"],
            ),
            infer=SASTToolConfig(
                SanityChecks.NONE,
                config["tools"]["infer"]["path"],
                config["tools"]["infer"]["checks"],
                config["tools"]["infer"]["num_threads"],
            ),
            codeql=SASTToolConfig(
                SanityChecks[config["tools"]["codeql"]["sanity_checks"].upper()],
                config["tools"]["codeql"]["path"],
                codeql_checks,
                config["tools"]["codeql"]["num_threads"],
            ),
            clang_scan=SASTToolConfig(
                SanityChecks.NONE, config["tools"]["clang_scan"]["path"], config["tools"]["clang_scan"]["checks"], -1
            ),
        )
