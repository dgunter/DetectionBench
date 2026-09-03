"""Bundled example rules for the top-bar chips."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

EXAMPLES_DIR = Path(__file__).resolve().parent / "resources" / "examples"


@dataclass(frozen=True)
class Example:
    id: str
    label: str
    blurb: str
    title: str
    yaml: str

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "label": self.label, "blurb": self.blurb, "title": self.title, "yaml": self.yaml}


@lru_cache(maxsize=1)
def load_examples(directory: Path = EXAMPLES_DIR) -> tuple[Example, ...]:
    with (directory / "index.json").open(encoding="utf-8") as fh:
        index = json.load(fh)
    examples = []
    for entry in index:
        text = (directory / f"{entry['id']}.yml").read_text(encoding="utf-8")
        title = str(yaml.safe_load(text).get("title", entry["id"]))
        examples.append(Example(id=entry["id"], label=entry["label"], blurb=entry["blurb"], title=title, yaml=text))
    return tuple(examples)
