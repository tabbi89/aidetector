"""Real parser/opcode execution with inert, locally recorded external effects.

Never calls pickle.loads on arbitrary globals, runs a command, resolves a URL,
reads a file, or starts a listener. The only allowed pickle global is replaced
with an inert recording function. Expat's external resolver returns empty text.
"""
import io
import pickle
import shlex
from xml.parsers import expat

from fastapi import FastAPI
from fastapi.responses import JSONResponse


def parser_target(*, secure: bool):
    app = FastAPI()
    outbound: list[str] = []

    @app.post('/xml')
    def xml(body: dict):
        parser = expat.ParserCreate()

        def resolve(context, base, system_id, public_id):
            if secure or not system_id.startswith('http://'):
                return 0
            outbound.append(system_id)
            parser.ExternalEntityParserCreate(context).Parse('', True)
            return 1

        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_ALWAYS)
        parser.ExternalEntityRefHandler = resolve
        try:
            parser.Parse(body['data'], True)
        except expat.ExpatError:
            return JSONResponse({'error': 'invalid XML'}, status_code=400)
        return {'ok': True}

    class ControlledUnpickler(pickle.Unpickler):
        def find_class(self, module, name):
            if secure or (module, name) != ('os', 'system'):
                raise pickle.UnpicklingError('global disabled')

            def record(command):
                parts = shlex.split(command)
                if len(parts) != 2 or parts[0] != 'curl' or not parts[1].startswith('http://'):
                    raise pickle.UnpicklingError('unsupported command')
                outbound.append(parts[1])
                return 0

            return record

    @app.post('/deserialize')
    def deserialize(body: dict):
        try:
            ControlledUnpickler(io.BytesIO(body['data'].encode())).load()
        except (pickle.UnpicklingError, EOFError, ValueError, TypeError):
            return JSONResponse({'error': 'invalid pickle'}, status_code=400)
        return {'ok': True}

    return app, outbound
