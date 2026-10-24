# ADR-0004: ADR-0002 amendment for PK AST tooling

Status: superseded

Standing supervisor approval, 2026-10-20:
https://github.com/Tanveerahamed-Dev/atlas-brain-staging/pull/67#issuecomment-6297326921
Supersedes ADR-0003; retains its K grants and the 22 ADR-0002 global APIs unchanged.
T = atlas_brain/evidence/parsekit/token_lint.py; A = atlas_brain/evidence/parsekit/token_audit.py.
Only exact paths below gain their used APIs. Types inspect syntax; dump compares
syntax, parse builds trees, walk/iter_child_nodes traverse; get_source_segment reads text.

| API | Using paths |
|---|---|
| ast.AnnAssign | T |
| ast.arg | T |
| ast.Assign | T |
| ast.AST | T, A |
| ast.AsyncFunctionDef | T, A |
| ast.Attribute | T |
| ast.Call | T |
| ast.ClassDef | A |
| ast.Compare | T |
| ast.Constant | T |
| ast.Dict | T |
| ast.dump | T |
| ast.ExceptHandler | T |
| ast.expr | T |
| ast.FunctionDef | T, A |
| ast.get_source_segment | A |
| ast.If | T |
| ast.IfExp | T |
| ast.In | T |
| ast.iter_child_nodes | T |
| ast.Lambda | T, A |
| ast.List | T |
| ast.Match | T |
| ast.MatchAs | T |
| ast.Module | A |
| ast.Name | T |
| ast.NodeVisitor | A |
| ast.NotIn | T |
| ast.parse | T, A |
| ast.Raise | T |
| ast.Return | T |
| ast.Slice | T |
| ast.Starred | T |
| ast.stmt | T |
| ast.Subscript | T |
| ast.Tuple | T |
| ast.walk | T, A |

Runtime paths cannot borrow tooling modules, aliases or re-exports. No wildcard,
execution, compilation, reflection or process grant is added. Hosted CI proves
actual source inventory/admission plus unlisted/outside-file/re-export refusals.
Policy/tool acceptance does not certify PK logic, truth or runtime qualification.
Every grant change requires a C1 ADR amendment and independent MERGE-READY.
Approval must be explicit or within standing bounds; Linux/Windows CI is mandatory.
