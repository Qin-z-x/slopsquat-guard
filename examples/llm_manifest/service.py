"""Synthetic LLM-generated service used by the slopsquat-guard evidence capture.

The imports mix standard-library modules (ignored), real distributions, curated
alias imports (PIL -> Pillow, yaml -> PyYAML), a local module (ignored) and one
clearly-invented module name (flagged).
"""

import json
import os

import requests
from PIL import Image
import yaml
from langchain_core.prompts import ChatPromptTemplate
from llm_utils_magic import enchant  # invented: absent from PyPI (capture time)

import local_helpers  # local module in this directory: skipped


def build_prompt(payload: dict) -> str:
    return json.dumps({"image": str(Image.new("RGB", (1, 1))), "yaml": yaml.safe_dump(payload)})


def main() -> None:
    print(build_prompt({"env": bool(os.environ)}), requests.__name__, ChatPromptTemplate.__name__, enchant, local_helpers.VALUE)


if __name__ == "__main__":
    main()
