import re
from pathlib import Path

from app.context.schemas import ContextChunk

DEFAULT_CONTEXT_DIR = Path(__file__).resolve().parents[1] / "data" / "context"


class ContextLoader:
    """
    Load enterprise context markdown files into searchable chunks.

    Parameters:
     context_dir - local directory containing enterprise context documents

    Returns:
     A context loader for asset, owner, whitelist, WAF policy, and playbook data

    Raises:
     None
    """

    def __init__(self, context_dir: Path = DEFAULT_CONTEXT_DIR) -> None:
        """
        Initialize the context loader.

        Parameters:
         context_dir - local directory containing enterprise context documents

        Returns:
         None

        Raises:
         None
        """

        self.context_dir = context_dir

    def load_chunks(self) -> list[ContextChunk]:
        """
        Load all markdown context files as searchable chunks.

        Parameters:
         None

        Returns:
         List of enterprise context chunks

        Raises:
         None
        """

        chunks: list[ContextChunk] = []

        if not self.context_dir.exists():
            return chunks

        for file_path in sorted(self.context_dir.glob("*.md")):
            chunks.extend(self._load_file(file_path))

        return chunks

    def _load_file(self, file_path: Path) -> list[ContextChunk]:
        """
        Load one context markdown file and split it by second-level headings.

        Parameters:
         file_path - context markdown file path

        Returns:
         Searchable context chunks extracted from the file

        Raises:
         None
        """

        text = file_path.read_text(encoding="utf-8")
        chunks: list[ContextChunk] = []
        current_title = file_path.stem
        current_lines: list[str] = []

        for line in text.splitlines():
            if line.startswith("## "):
                self._append_chunk(chunks, file_path.name, current_title, current_lines)
                current_title = line.removeprefix("## ").strip()
                current_lines = [line]
                continue

            current_lines.append(line)

        self._append_chunk(chunks, file_path.name, current_title, current_lines)
        return chunks

    def _append_chunk(
        self,
        chunks: list[ContextChunk],
        source: str,
        title: str,
        lines: list[str],
    ) -> None:
        """
        Append one non-empty context chunk.

        Parameters:
         chunks - destination context chunk list
         source - source markdown file name
         title - section title
         lines - markdown lines belonging to the section

        Returns:
         None

        Raises:
         None
        """

        content = "\n".join(lines).strip()

        if not content:
            return

        metadata = self._metadata(lines)
        text = f"{source}\n{title}\n{content}\n{' '.join(metadata.values())}"
        chunks.append(
            ContextChunk(
                chunk_id=f"{Path(source).stem}:{len(chunks) + 1}",
                source=source,
                title=title,
                category=self._category(Path(source)),
                content=content,
                metadata=metadata,
                keywords=self._keywords(text),
            )
        )

    def _metadata(self, lines: list[str]) -> dict[str, str]:
        """
        Extract simple key-value metadata from markdown lines.

        Parameters:
         lines - markdown lines belonging to one context section

        Returns:
         Extracted metadata mapping

        Raises:
         None
        """

        metadata: dict[str, str] = {}

        for line in lines:
            if line.startswith("#") or ":" not in line:
                continue

            key, value = line.split(":", 1)
            normalized_key = key.strip().lower()
            normalized_value = value.strip()

            if re.fullmatch(r"[a-z_]+", normalized_key) and normalized_value:
                metadata[normalized_key] = normalized_value

        return metadata

    def _category(self, file_path: Path) -> str:
        """
        Infer context category from file name.

        Parameters:
         file_path - context file path

        Returns:
         Context category

        Raises:
         None
        """

        name = file_path.stem.lower()

        if "asset" in name:
            return "asset"

        if "owner" in name:
            return "owner"

        if "scanner" in name or "whitelist" in name:
            return "scanner_whitelist"

        if "waf" in name:
            return "waf_policy"

        if "playbook" in name:
            return "playbook"

        if "change" in name:
            return "change_calendar"

        return "context"

    def _keywords(self, text: str) -> list[str]:
        """
        Extract normalized search terms from context text.

        Parameters:
         text - source text used for keyword extraction

        Returns:
         List of lowercase search terms

        Raises:
         None
        """

        return re.findall(r"[a-z0-9_./'-]+", text.lower())
