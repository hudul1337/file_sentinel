import logging
from pathlib import Path

logger = logging.getLogger("file_sentinel.prompts")


def ask_user_action(file_path: Path, malicious_count: int) -> str:
    """Opens a modal dialog asking whether to delete or quarantine a flagged file.
    Falls back to a console prompt if no display / Tkinter is available."""
    message = (
        f"Downloaded file: {file_path.name}\n"
        f"VirusTotal detections: {malicious_count} security vendors flagged this file.\n\n"
        f"Delete it permanently?\n\n"
        f"- Yes: the file will be permanently DELETED.\n"
        f"- No: the file will be moved to the quarantine folder."
    )

    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        response = messagebox.askyesno(
            title="Malicious file detected", message=message, icon="warning"
        )
        root.destroy()
        return "delete" if response else "quarantine"
    except Exception as exc:
        logger.warning("No GUI available (%s); falling back to console prompt.", exc)
        answer = input(f"{message}\n[d]elete / [q]uarantine? ").strip().lower()
        return "delete" if answer.startswith("d") else "quarantine"
