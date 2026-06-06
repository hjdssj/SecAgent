import re
from pathlib import Path

from app.rag.schemas import KnowledgeChunk, KnowledgeDocument

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

    def load_documents(self) -> list[KnowledgeDocument]:
        """
        Load all markdown files as structured knowledge documents.

        Parameters:
         None

        Returns:
         List of structured security knowledge documents

        Raises:
         None
        """

        documents: list[KnowledgeDocument] = []

        if not self.knowledge_dir.exists():
            return documents

        for file_path in sorted(self.knowledge_dir.glob("*.md")):
            text = file_path.read_text(encoding="utf-8")
            documents.append(
                KnowledgeDocument(
                    doc_id=file_path.stem,
                    title=self._document_title(text, file_path.stem),
                    category=self._category(file_path),
                    source=file_path.name,
                    tags=self._tags(f"{file_path.stem}\n{text}"),
                    content=text,
                )
            )

        return documents

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

        doc_id = Path(source).stem
        category = self._category(Path(source))
        title_and_content = f"{title}\n{content}"

        chunks.append(
            KnowledgeChunk(
                chunk_id=f"{doc_id}:{len(chunks) + 1}",
                doc_id=doc_id,
                source=source,
                title=title,
                category=category,
                content=content,
                tags=self._tags(title_and_content),
                keywords=self._keywords(title_and_content),
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

    def _document_title(self, text: str, fallback: str) -> str:
        """
        Extract the first markdown title from a knowledge document.

        Parameters:
         text - markdown document content
         fallback - fallback title used when no markdown title exists

        Returns:
         Document title

        Raises:
         None
        """

        for line in text.splitlines():
            if line.startswith("# "):
                return line.removeprefix("# ").strip()

        return fallback

    def _category(self, file_path: Path) -> str:
        """
        Infer a knowledge category from the source file name.

        Parameters:
         file_path - knowledge file path or file-like path

        Returns:
         Knowledge category used for filtering and reporting

        Raises:
         None
        """

        name = file_path.stem.lower()

        if "mitre" in name:
            return "mitre"

        if "cve" in name:
            return "cve"

        if "crs" in name or "waf" in name:
            return "waf_rule"

        if "remediation" in name:
            return "remediation"

        if "attack" in name:
            return "attack"

        return "general"

    def _tags(self, text: str) -> list[str]:
        """
        Extract security-oriented tags from knowledge text.

        Parameters:
         text - source text used to infer security tags

        Returns:
         Deduplicated tag list

        Raises:
         None
        """

        lower_text = text.lower()
        tag_rules = {
            "sqli": ["sql injection", "sqli", "942", "sqlmap", "information_schema"],
            "xss": ["xss", "cross site scripting", "941", "<script", "javascript:"],
            "path_traversal": ["path traversal", "directory traversal", "930", "../", "/etc/passwd"],
            "command_injection": ["command injection", "932", "t1059", "whoami", "$("],
            "scanner": ["scanner", "sqlmap", "nikto", "acunetix", "nessus", "913"],
            "mitre": ["mitre", "attack", "t1190", "t1189", "t1059"],
            "remediation": ["remediation", "修复", "处置", "加固"],
        }
        tags: list[str] = []

        for tag, needles in tag_rules.items():
            if any(needle in lower_text for needle in needles):
                tags.append(tag)

        for technique_id in re.findall(r"\bt\d{4}\b", lower_text):
            tags.append(technique_id.upper())

        for rule_id in re.findall(r"\b9\d{5}\b|\b9\d{2}\b", lower_text):
            tags.append(rule_id)

        return list(dict.fromkeys(tags))
