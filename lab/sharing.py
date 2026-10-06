from pathlib import Path
import re

QUICK_ORIGIN = re.compile(r'https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com')


def public_origin(settings):
    if settings.public_origin:
        return settings.public_origin
    path = settings.data / 'public-origin'
    try:
        if path.is_symlink() or path.stat().st_size > 256:
            return ''
        value = path.read_text().strip()
        return value if QUICK_ORIGIN.fullmatch(value) else ''
    except OSError:
        return ''
