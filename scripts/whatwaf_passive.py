"""Run an installed WhatWaf signature set on one captured response, offline.

Uses upstream detect(content, headers=..., status=...) functions. This adapter
loads only HTTP_HEADER constants from settings, without starting WhatWaf's CLI.
"""
import ast
import json
from pathlib import Path
import socket
import sys


def main():
    root, capture = map(Path, sys.argv[1:3])
    data = json.loads(capture.read_text())
    tree = ast.parse((root / 'lib/settings.py').read_text())
    fields = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == 'HTTP_HEADER':
            for field in node.body:
                if isinstance(field, ast.Assign) and isinstance(field.targets[0], ast.Name):
                    fields[field.targets[0].id] = ast.literal_eval(field.value)
    if not fields: raise ValueError('Unsupported WhatWaf settings format')
    class Headers(dict):
        def get(self, key, default=None): return super().get(key.lower(), default)
        def __getitem__(self, key): return super().__getitem__(key.lower())
        def __contains__(self, key): return super().__contains__(key.lower())
    headers = Headers((k.lower(), v) for k,v in data['headers'])
    def denied(*a, **kw): raise RuntimeError('Network disabled in signature worker')
    socket.socket = socket.create_connection = socket.getaddrinfo = denied
    detected, errors, checked = [], [], 0
    for file in sorted((root / 'content/plugins').glob('*.py')):
        if file.name.startswith('_'): continue
        try:
            plugin = ast.parse(file.read_text())
            plugin.body = [node for node in plugin.body if not
                (isinstance(node, ast.ImportFrom) and node.module == 'lib.settings')]
            ns = {'HTTP_HEADER': type('HTTP_HEADER', (), fields), '__name__': 'whatwaf_signature'}
            exec(compile(plugin, str(file), 'exec'), ns)
            if callable(ns.get('detect')):
                checked += 1
                if ns['detect'](data['body'], headers=headers, status=data['status']):
                    detected.append(str(ns.get('__product__', file.stem))[:160])
        except Exception:
            errors.append(file.stem)
    print(json.dumps({'detections': sorted(set(detected)), 'checked': checked, 'errors': errors}))


if __name__ == '__main__': main()
