# SecRAG Agent Coding Rules

## Docstring Style

All Python classes and functions in this project must use the following grouped docstring style.

Use this format for every class, method, and function:

```python
"""
Short description of what this class or function does.

Parameters:
 param1 - description of the first parameter
 param2 - description of the second parameter

Returns:
 Description of what is returned

Raises:
 KeyError - description of when this exception is raised
"""
```

## Rules

1. Every public class must have a docstring.
2. Every public function or method must have a docstring.
3. Use the exact section names:
   - `Parameters:`
   - `Returns:`
   - `Raises:`
4. If a function has no parameters, write:

```python
Parameters:
 None
```

5. If a function returns nothing, write:

```python
Returns:
 None
```

6. If a function does not intentionally raise exceptions, write:

```python
Raises:
 None
```

7. Parameter descriptions should use this format:

```text
parameter_name - description
```

8. Keep descriptions concise and practical. Explain behavior, not obvious type information.

## Example

```python
def analyze_event(event: SecurityEvent) -> SecurityAlert:
    """
    Analyze a normalized security event and generate a security alert.

    Parameters:
     event - normalized WAF, Nginx, or firewall security event

    Returns:
     A structured security alert containing attack type, risk level, evidence, and recommendations

    Raises:
     None
    """
```

## Git Rules

Follow these rules when using Git in this project.

1. Check the working tree before committing.

```bash
git status
```

2. Review changed files before staging.

```bash
git diff
```

3. Stage only files related to the current task.

Do not use broad staging commands when unrelated changes may exist.

Avoid:

```bash
git add .
```

Prefer:

```bash
git add path/to/file.py
git add path/to/doc.md
```

4. Do not revert changes you did not make.

If the working tree contains unfamiliar changes, treat them as user changes. Do not run commands that discard them.

Avoid destructive commands unless explicitly requested:

```bash
git reset --hard
git checkout -- .
git clean -fd
```

5. Commit messages should be concise and describe the actual change.

Recommended format:

```text
type: short description
```

Examples:

```text
docs: add first-stage testing notes
feat: add security alert model
fix: handle waf rule based attack detection
```

6. Before committing code, run available checks when possible.

Examples:

```bash
python -m compileall backend/app
pytest
```

7. Do not commit generated runtime files unless they are intentionally part of the project.

Usually avoid committing:

```text
__pycache__/
.pytest_cache/
.env
*.log
```

8. Keep commits focused.

One commit should correspond to one clear unit of work, such as:

```text
add event models
add log parser agent
add analyze api
update project documentation
```

9. If a file contains both your changes and unrelated user changes, review it carefully before staging.

Use targeted staging when needed:

```bash
git add -p path/to/file.py
```

10. Never commit secrets.

Do not commit API keys, tokens, passwords, private endpoints, or real threat intelligence credentials. Use `.env` and `.env.example` instead.
