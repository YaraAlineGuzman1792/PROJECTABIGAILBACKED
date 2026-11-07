#!/usr/bin/env python3
"""Crea o actualiza la cuenta de administración.

Uso:  python scripts/crear_admin.py <usuario>
La contraseña se pide por consola y nunca aparece en el historial del shell.
"""
import getpass
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import FabricaSesion, crear_tablas      # noqa: E402
from app.models import Administrador                      # noqa: E402
from app.security.cripto import hash_password             # noqa: E402

MINIMO = 12


def main() -> int:
    usuario = sys.argv[1] if len(sys.argv) > 1 else "admin"
    password = getpass.getpass(f"Contraseña para «{usuario}»: ")
    if len(password) < MINIMO:
        print(f"La contraseña debe tener al menos {MINIMO} caracteres.")
        print(f"Sugerencia: {secrets.token_urlsafe(18)}")
        return 1
    if password != getpass.getpass("Repite la contraseña: "):
        print("Las contraseñas no coinciden.")
        return 1

    crear_tablas()
    with FabricaSesion() as bd:
        cuenta = bd.get(Administrador, usuario)
        if cuenta is None:
            cuenta = Administrador(usuario=usuario, password_hash=hash_password(password))
            bd.add(cuenta)
            accion = "creada"
        else:
            cuenta.password_hash = hash_password(password)
            cuenta.intentos_fallidos = 0
            cuenta.bloqueado_hasta = None
            accion = "actualizada"
        bd.commit()
    print(f"Cuenta «{usuario}» {accion}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
