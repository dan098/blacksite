from pathlib import Path
from xml.sax.saxutils import escape
import json

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


def render_pdf(job, destination: Path):
    font_path = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    font = "Helvetica"
    if font_path.exists():
        if "LabSans" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("LabSans", str(font_path)))
        font = "LabSans"
    styles = getSampleStyleSheet()
    for style in styles.byName.values():
        style.fontName = font
        style.wordWrap = "CJK"
    styles.add(ParagraphStyle("Evidence", fontName=font, fontSize=8, leading=12, spaceAfter=4, wordWrap="CJK"))
    styles["Title"].textColor = colors.HexColor("#B51F40")
    styles["Heading2"].textColor = colors.HexColor("#0F172A")
    story = []

    def p(text, style="BodyText", max_length=6000):
        value = str(text if text is not None else "—")
        if len(value) > max_length:
            value = value[:max_length] + " [troncato: dettagli nell'artefatto JSON]"
        return Paragraph(escape(value).replace("\n", "<br/>"), styles[style])

    def section(title):
        story.extend([Spacer(1, 5 * mm), p(title, "Heading2")])

    def table(headers, rows, widths=None):
        rows = list(rows)
        if not rows:
            story.append(p("Nessun dato raccolto in questa sezione; non è un verdetto di innocuità."))
            return
        data = [[p(text, "Evidence", 2000) for text in headers]]
        data += [[p(text, "Evidence", 2500) for text in row] for row in rows[:150]]
        t = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E7EFF5")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(t)
        if len(rows) > 150:
            story.append(p(f"Mostrate 150 righe su {len(rows)}. Tutte le evidenze restano negli artefatti JSON/EVTX/PML/PCAP.", "Evidence"))

    story += [p("BLACKSITE · Analysis report", "Title"), p("Detonate. Trace. Contain.", "Evidence"), p(job["name"], "Heading2"), p("SHA-256: " + job["sha256"], "Evidence"), p("Stato: " + job["status"] + " · Data UTC: " + job["created_at"], "Evidence")]
    section("Sintesi e interpretazione")
    summary = job.get("summary", {})
    story += [p(summary.get("verdict", "not_evaluated")), p(summary.get("detail", "Nessun verdetto automatico."))]
    story.append(p("Quattro profili della stessa immagine Windows, non quattro sistemi operativi diversi. Ogni run usa disco, TPM e UEFI usa-e-getta. La policy e le prove di rete sono riportate per ciascuna esecuzione: la rete è offline per impostazione predefinita. Internet richiede un opt-in e un gateway che confina l'accesso a IPv4 pubblici, bloccando host, LAN, reti private e IPv6. Defender resta attivo. Nessun contenimento o sensore garantisce copertura completa. Un campione può rilevare l'ambiente, non eseguire o essere bloccato.", "Evidence"))
    for warning in job.get("warnings", []):
        story.append(p("Avviso: " + warning, "Evidence"))
    table(["Profilo", "Stato", "Processi correlati", "Eventi correlati"], [(run.get("profile_name", run["profile"]), run["status"], run.get("dynamic", {}).get("counts", {}).get("related_processes", "—"), run.get("dynamic", {}).get("counts", {}).get("related_events", "—")) for run in job.get("runs", [])], [52 * mm, 27 * mm, 45 * mm, 44 * mm])
    section("Analisi statica")
    static = job.get("static", {})
    table(["Proprietà", "Risultato"], [("Tipo", static.get("type", {}).get("description", "—") if isinstance(static.get("type"), dict) else static.get("type")), ("Dimensione", static.get("size")), *static.get("hashes", {}).items()], [40 * mm, 128 * mm])
    for name in ("yara", "floss", "capa", "av", "byovd", "hybrid_analysis", "reputation"):
        value = static.get(name, {})
        story.append(p(name.upper(), "Heading3"))
        story.append(p(json.dumps(value, ensure_ascii=False, default=str), "Evidence", 6000))
    table(["Sensore statico", "Stato/copertura"], [(name, json.dumps(value, ensure_ascii=False)) for name, value in static.get("capabilities", {}).items()], [42 * mm, 126 * mm])
    for run in job.get("runs", []):
        story.append(PageBreak())
        story.append(p(run.get("profile_name", run["profile"]), "Heading1"))
        story.append(p("Stato: " + run["status"] + "; finestra UTC: " + run.get("started_at", "—") + " → " + run.get("finished_at", "—"), "Evidence"))
        dynamic = run.get("dynamic", {})
        section("Sensori e rilevamenti")
        table(["Sensore", "Copertura effettiva"], [(name, json.dumps(value, ensure_ascii=False)) for name, value in dynamic.get("capabilities", {}).items()], [38 * mm, 130 * mm])
        story.append(p("Defender: " + json.dumps(dynamic.get("defender", {}), ensure_ascii=False), "Evidence", 5000))
        elastic = dynamic.get("elastic", {})
        story.append(p("Elastic EDR: " + str(elastic.get("status", "unavailable")) + " · " + elastic.get("detail", ""), "Evidence"))
        for warning in run.get("warnings", []) + dynamic.get("warnings", []):
            story.append(p("Avviso: " + warning, "Evidence"))
        findings = dynamic.get("findings", [])
        table(["Severità", "Evidenza", "Motivo"], [(f.get("severity"), f.get("title", f.get("name", f.get("id"))), f.get("description", f.get("detail", f.get("rationale", "")))) for f in findings], [25 * mm, 55 * mm, 88 * mm])
        section("Process tree correlato al sample")
        processes = [value for value in dynamic.get("processes", []) if value.get("related")]
        table(["PID / padre", "Immagine", "Comando"], [(str(value.get("pid")) + " / " + str(value.get("ppid")), value.get("image"), value.get("command_line")) for value in processes], [25 * mm, 60 * mm, 83 * mm])
        section("Registro, file e rete: eventi correlati")
        events = [value for value in dynamic.get("events", []) if value.get("related")]
        table(["Tempo", "Categoria / azione", "Destinazione"], [(value.get("time"), str(value.get("category")) + " / " + str(value.get("action")), value.get("target")) for value in events], [38 * mm, 46 * mm, 84 * mm])
        story.append(p("Il filtro usa GUID/ascendenza e finestra di lancio; i dati globali e il rumore di sistema rimangono conservati separatamente.", "Evidence"))
        section("Modifiche prima/dopo e driver")
        story.append(p(json.dumps(dynamic.get("changes", {}), ensure_ascii=False), "Evidence", 8000))
        story.append(p("Driver: " + json.dumps(dynamic.get("drivers", []), ensure_ascii=False), "Evidence", 6000))
        section("Tracing kernel Microsoft ETW")
        kernel = dynamic.get("kernel", {})
        story.append(p("Stato: " + str(kernel.get("status", "unavailable")) + " · " + json.dumps(kernel.get("counts", {}), ensure_ascii=False), "Evidence"))
        story.append(p("Copertura: " + json.dumps(kernel.get("coverage", {}), ensure_ascii=False), "Evidence", 6000))
        story.append(p("Eventi SystemCall e stackwalk osservati dal collector kernel WPR, separati dagli hook user-mode. Gli indirizzi grezzi non sono simboli risolti; gli stack non costituiscono una call chain causale completa. Buffer, ring e limiti di decodifica possono lasciare lacune: consultare ETL e ricevute.", "Evidence"))
        table(["Evento / tempo", "PID / TID", "Syscall / stato / stack"], [(str(value.get("kind")) + " / " + str(value.get("time")), str(value.get("pid")) + "/" + str(value.get("tid")), json.dumps({"address": value.get("syscall_address"), "ntstatus": value.get("ntstatus"), "stack": value.get("stack_addresses", [])}, ensure_ascii=False)) for value in kernel.get("events", []) if value.get("related")], [48 * mm, 25 * mm, 95 * mm])
        section("API, call chain e Nt* user-mode")
        story.append(p("Nt* intercettate in user-mode non equivalgono a syscall kernel complete. La raccolta Frida qui è separata dal tracing kernel ETW sopra; nessuno stack ricostruisce chiamate non catturate.", "Evidence"))
        table(["API", "PID/thread", "Stack osservato"], [(value.get("api", value.get("name")), str(value.get("pid")) + "/" + str(value.get("tid", value.get("thread_id"))), json.dumps(value.get("stack", value.get("backtrace", [])), ensure_ascii=False)) for value in dynamic.get("api_calls", [])], [40 * mm, 28 * mm, 100 * mm])
        section("Rete e download")
        isolation = dynamic.get("isolation", {})
        story.append(p("Policy/prova del run: " + json.dumps({key: isolation.get(key) for key in ("network_mode", "guest_internet", "guest_lan", "guest_host", "internet_verified", "public_identity_state", "public_identity_limits")}, ensure_ascii=False), "Evidence"))
        pcap = dynamic.get("pcap", {})
        story.append(p(pcap.get("detail", "PCAP non elaborato"), "Evidence"))
        table(["Origine", "Destinazione", "Protocollo/pacchetti"], [(str(value.get("src")) + ":" + str(value.get("src_port")), str(value.get("dst")) + ":" + str(value.get("dst_port")), str(value.get("protocol")) + "/" + str(value.get("packets"))) for value in pcap.get("flows", [])], [58 * mm, 58 * mm, 52 * mm])
        payloads = dynamic.get("payloads", {})
        story.append(p("Payload secondari: " + str(payloads.get("status", "unavailable")) + ". I byte esportati vengono verificati per hash e dimensione sull'host. Provenienza e uso rimangono metadati guest non affidabili; file mancanti, rifiutati e oltre budget restano segnalati.", "Evidence"))
        table(["File / stato", "SHA-256", "Artefatto verificato"], [(str(value.get("source_path")) + " / " + str(value.get("status")), value.get("sha256"), value.get("artifact_name", value.get("artifact"))) for value in payloads.get("payloads", [])], [64 * mm, 62 * mm, 42 * mm])
    section("Artefatti disponibili nell'interfaccia autenticata")
    table(["Nome", "Tipo", "Byte"], [(value.get("name"), value.get("kind"), value.get("size")) for value in job.get("artifacts", [])], [90 * mm, 40 * mm, 38 * mm])
    doc = SimpleDocTemplate(str(destination), pagesize=A4, rightMargin=21 * mm, leftMargin=21 * mm, topMargin=18 * mm, bottomMargin=20 * mm, title="BLACKSITE analysis report", author="BLACKSITE")

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont(font, 8)
        canvas.setFillColor(colors.HexColor("#475569"))
        canvas.drawString(21 * mm, 11 * mm, "BLACKSITE · Laboratory evidence · UTC")
        canvas.drawRightString(189 * mm, 11 * mm, str(document.page))
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return destination
