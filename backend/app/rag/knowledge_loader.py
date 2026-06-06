import re
from pathlib import Path

from app.rag.schemas import KnowledgeChunk

DEFAULT_KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "data" / "knowledge_base"


class KnowledgeLoader:
    """
    Load local markdown security knowledge into searchable chunks.

    Parameters:
     knowledge_dir - local directory containing markdown knowledge documents

    Returns:
     A loader instance that can read local security knowledge documents

    Raises:
     None
    """

    def __init__(self, knowledge_dir: Path = DEFAULT_KNOWLEDGE_DIR) -> None:
        """
        Initialize the local knowledge loader.

        Parameters:
         knowledge_dir - local directory containing markdown knowledge documents

        Returns:
         None

        Raises:
         None
        """

        self.knowledge_dir = knowledge_dir

    def load_chunks(self) -> list[KnowledgeChunk]:
        """
        Load all markdown knowledge files as searchable chunks.

        Parameters:
         None

        Returns:
         List of searchable knowledge chunks

        Raises:
         None
        """

        chunks: list[KnowledgeChunk] = []

        if not self.knowledge_dir.exists():
            return chunks

        for file_path in sorted(self.knowledge_dir.glob("*.md")):
            chunks.extend(self._load_file(file_path))

        return chunks

    def _load_file(self, file_path: Path) -> list[KnowledgeChunk]:
        """
        Load one markdown file and split it by second-level headings.

        Parameters:
         file_path - markdown knowledge file path

        Returns:
         Searchable chunks extracted from the markdown file

        Raises:
         None
        """

        text = file_path.read_text(encoding="utf-8")
        chunks: list[KnowledgeChunk] = []
        current_title = file_path.stem
        current_lines: list[str] = []

        for line in text.splitlines():
            if line.startswith("## "):
                self._append_chunk(
                    chunks,
                    file_path.name,
                    current_title,
                    current_lines,
                )
                current_title = line.removeprefix("## ").strip()
                current_lines = [line]
                continue

            current_lines.append(line)

        self._append_chunk(chunks, file_path.name, current_title, current_lines)
        return chunks

    def _append_chunk(
        self,
        chunks: list[KnowledgeChunk],
        source: str,
        title: str,
        lines: list[str],
    ) -> None:
        """
        Append one non-empty markdown chunk to the chunk list.

        Parameters:
         chunks - destination chunk list
         source - source markdown file name
         title - chunk title
         lines - markdown lines belonging to the chunk

        Returns:
         None

        Raises:
         None
        """

        content = "\n".join(lines).strip()

        if not content:
            return

        chunks.append(
            KnowledgeChunk(
                source=source,
                title=title,
                content=content,
                keywords=self._keywords(f"{title}\n{content}"),
            )
        )

    def _keywords(self, text: str) -> list[str]:
        """
        Extract normalized searchable keywords from text.

        Parameters:
         text - source text used for keyword extraction

        Returns:
         List of lowercase keywords

        Raises:
         None
        """

        return re.findall(r"[a-z0-9_./'-]+", text.lower())
