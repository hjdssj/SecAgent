from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.api.analyze import orchestrator
from app.rag.knowledge_repository import KnowledgeRepository
from app.rag.schemas import KnowledgeDocument, KnowledgeUploadRequest, KnowledgeUploadResponse

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])
repository = KnowledgeRepository()


@router.get("/documents", response_model=list[KnowledgeDocument])
def list_knowledge_documents() -> list[KnowledgeDocument]:
    """
    List local RAG knowledge documents.

    Parameters:
     None

    Returns:
     Knowledge documents currently stored on disk

    Raises:
     None
    """

    return repository.list_documents()


@router.get("/documents/{source}", response_model=KnowledgeDocument)
def get_knowledge_document(source: str) -> KnowledgeDocument:
    """
    Read one local RAG knowledge document.

    Parameters:
     source - markdown source file name

    Returns:
     Knowledge document content and metadata

    Raises:
     HTTPException - returned when the document does not exist
    """

    document = repository.get_document(source)

    if document is None:
        raise HTTPException(status_code=404, detail="Knowledge document not found")

    return document


@router.post("/documents", response_model=KnowledgeUploadResponse)
def save_knowledge_document(request: KnowledgeUploadRequest) -> KnowledgeUploadResponse:
    """
    Save one markdown document into the RAG knowledge base from JSON.

    Parameters:
     request - markdown document upload request

    Returns:
     Saved knowledge document metadata

    Raises:
     HTTPException - returned when the request cannot be saved
    """

    try:
        result = repository.save_document(
            filename=request.filename,
            content=request.content,
            overwrite=request.overwrite,
        )
    except FileExistsError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    orchestrator.rag_agent.refresh()
    return result


@router.post("/documents/upload", response_model=KnowledgeUploadResponse)
async def upload_knowledge_document(
    file: UploadFile = File(...),
    overwrite: bool = Form(default=False),
) -> KnowledgeUploadResponse:
    """
    Save one uploaded markdown file into the RAG knowledge base.

    Parameters:
     file - uploaded markdown file
     overwrite - whether an existing document may be replaced

    Returns:
     Saved knowledge document metadata

    Raises:
     HTTPException - returned when the upload cannot be saved
    """

    filename = file.filename or ""

    if not filename.lower().endswith(".md"):
        raise HTTPException(status_code=422, detail="Only markdown .md files are supported")

    raw_content = await file.read()

    try:
        content = raw_content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=422, detail="Knowledge document must be UTF-8") from error

    try:
        result = repository.save_document(
            filename=filename,
            content=content,
            overwrite=overwrite,
        )
    except FileExistsError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    orchestrator.rag_agent.refresh()
    return result
