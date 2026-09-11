"""Remapea exam_results huérfanos a su examen actual (Hipótesis #1).

Causa: `orden` de contenidos LMS es mutable (mover hace swap, eliminar
renumera). Los intentos guardados con `orden_examen` viejo dejan de matchear
los exámenes actuales -> el participante ve "Debe aprobar con >=80%" y su
nota ni siquiera aparece en listados internos.

Estrategia: match por `titulo_examen` normalizado (strip + casefold) contra
los exámenes actuales del mismo evento. Solo match único se remapea; lo
ambiguo o sin match se reporta y NO se toca.

Seguridad:
- `--dry-run` por defecto (no escribe). Solo `--apply` modifica.
- Idempotente: marca `_remap_orden_previo`; re-ejecución no duplica cambios.
- Nunca toca docs cuyo `orden_examen` ya matchea un examen actual.
- Nunca modifica calificacion/respuestas, solo `orden_examen` (+`examen_id`).
- Requiere respaldo previo de `exam_results` (mongodump) antes de --apply.

Uso:
    python scripts/remap_ordenes_examen.py --evento EVT001
    python scripts/remap_ordenes_examen.py --evento EVT001 --apply
    python scripts/remap_ordenes_examen.py --all --apply
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymongo import MongoClient  # noqa: E402

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "certi_css"


def norm(s):
    return (s or "").strip().casefold()


def analizar_evento(col_eva, col_res, codigo_evento):
    examenes = list(
        col_eva.find(
            {"codigo_evento": codigo_evento, "tipo": "examen"},
            {"orden": 1, "titulo": 1},
        ).sort("orden", 1)
    )
    ordenes_actuales = {ex.get("orden") for ex in examenes}
    por_titulo = {}
    for ex in examenes:
        por_titulo.setdefault(norm(ex.get("titulo")), []).append(ex)

    huerfanos = list(
        col_res.find({"codigo_evento": codigo_evento, "formativo": {"$ne": True}})
    )
    # Solo los que NO matchean orden actual (los sanos se ignoran)
    huerfanos = [r for r in huerfanos if r.get("orden_examen") not in ordenes_actuales]

    plan = []  # (doc, nuevo_orden|None, motivo)
    for r in huerfanos:
        cands = por_titulo.get(norm(r.get("titulo_examen")), [])
        if len(cands) == 1:
            plan.append((r, cands[0].get("orden"), str(cands[0].get("_id")), "ok"))
        elif len(cands) == 0:
            plan.append((r, None, None, "sin-match-titulo"))
        else:
            plan.append((r, None, None, "ambiguo-multi-match"))
    return examenes, plan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evento", help="Código de evento a procesar")
    ap.add_argument("--all", action="store_true", help="Procesar todos los eventos")
    ap.add_argument("--apply", action="store_true", help="Escribir cambios (sin esto: dry-run)")
    args = ap.parse_args()

    if not args.evento and not args.all:
        ap.error("Indica --evento CODIGO o --all")

    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    col_eva, col_res = db["eva"], db["exam_results"]

    if args.all:
        eventos = sorted(col_eva.distinct("codigo_evento"))
    else:
        eventos = [args.evento]

    total_ok = total_amb = total_sin = 0
    for evt in eventos:
        examenes, plan = analizar_evento(col_eva, col_res, evt)
        oks = [p for p in plan if p[3] == "ok"]
        amb = [p for p in plan if p[3] == "ambiguo-multi-match"]
        sin = [p for p in plan if p[3] == "sin-match-titulo"]
        total_ok += len(oks)
        total_amb += len(amb)
        total_sin += len(sin)
        print(f"[{evt}] examenes_actuales={len(examenes)} huerfanos={len(plan)} "
              f"remapeables={len(oks)} ambiguos={len(amb)} sin_match={len(sin)}")
        for r, nuevo, examen_id, motivo in plan:
            print(f"  - {r.get('cedula_participante')} orden={r.get('orden_examen')} "
                  f"titulo={r.get('titulo_examen')!r} motivo={motivo}"
                  + (f" -> nuevo_orden={nuevo}" if nuevo is not None else ""))
            if args.apply and motivo == "ok":
                col_res.update_one(
                    {"_id": r["_id"]},
                    {"$set": {
                        "orden_examen": nuevo,
                        "examen_id": examen_id,
                        "_remap_orden_previo": r.get("orden_examen"),
                    }},
                )

    print(f"TOTAL remapeables={total_ok} ambiguos={total_amb} sin_match={total_sin} "
          f"modo={'APPLY' if args.apply else 'DRY-RUN'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
