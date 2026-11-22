"""Metadata-only exception diagnostics. Never inspect messages, locals or paths."""

STAGES = frozenset(('direct', 'frame-layout', 'frame-validation', 'digest-accounting',
                    'command-observation', 'stream-close', 'transport', 'coverage'))
CLASSES = {kind: kind.__name__ for kind in
           (AssertionError, ValueError, TypeError, KeyError, IndexError, RuntimeError, OSError)}


def detail(error, stage, codes, audit_error):
    # Exact types prevent arbitrary __str__, class names and exception attributes
    # from becoming diagnostic data. Code labels are trusted static call-site data.
    result = dict(stage=stage if type(stage) is str and stage in STAGES else 'direct',
                  exceptionClass=('AuditError' if type(error) is audit_error
                                  else CLASSES.get(type(error), 'OtherException')), locations=[])
    current = BaseException.__traceback__.__get__(error)
    for _ in range(16):
        if current is None:
            break
        label = codes.get(current.tb_frame.f_code)
        if label is not None:
            result['locations'].append(dict(code=label, line=current.tb_lineno))
        current = current.tb_next
    return result
