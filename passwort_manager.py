import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import secrets
import string
import os

DATENBANK = "passwoerter.db"

# ─── Datenbank ────────────────────────────────────────────────────────────────

def datenbank_erstellen():
    """Tabellen anlegen falls sie noch nicht existieren."""
    con = sqlite3.connect(DATENBANK)
    cur = con.cursor()

    # Tabelle für den Master-Login
    cur.execute("""
        CREATE TABLE IF NOT EXISTS master (
            id      INTEGER PRIMARY KEY,
            passwort_hash TEXT NOT NULL
        )
    """)

    # Tabelle für gespeicherte Passwörter
    cur.execute("""
        CREATE TABLE IF NOT EXISTS eintraege (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            webseite TEXT NOT NULL,
            benutzername TEXT NOT NULL,
            passwort TEXT NOT NULL
        )
    """)
    con.commit()
    con.close()


def passwort_hashen(passwort):
    """Passwort mit SHA-256 hashen (einfach & sicher für dieses Projekt)."""
    return hashlib.sha256(passwort.encode()).hexdigest()


def master_existiert():
    con = sqlite3.connect(DATENBANK)
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM master")
    anzahl = cur.fetchone()[0]
    con.close()
    return anzahl > 0


def master_setzen(passwort):
    con = sqlite3.connect(DATENBANK)
    cur = con.cursor()
    cur.execute("INSERT INTO master (passwort_hash) VALUES (?)", (passwort_hashen(passwort),))
    con.commit()
    con.close()


def master_pruefen(passwort):
    con = sqlite3.connect(DATENBANK)
    cur = con.cursor()
    cur.execute("SELECT passwort_hash FROM master")
    row = cur.fetchone()
    con.close()
    if row:
        return row[0] == passwort_hashen(passwort)
    return False


def eintrag_speichern(webseite, benutzername, passwort):
    con = sqlite3.connect(DATENBANK)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO eintraege (webseite, benutzername, passwort) VALUES (?, ?, ?)",
        (webseite, benutzername, passwort)
    )
    con.commit()
    con.close()


def alle_eintraege_laden():
    con = sqlite3.connect(DATENBANK)
    cur = con.cursor()
    cur.execute("SELECT id, webseite, benutzername, passwort FROM eintraege ORDER BY webseite")
    rows = cur.fetchall()
    con.close()
    return rows


def eintrag_loeschen(eintrag_id):
    con = sqlite3.connect(DATENBANK)
    cur = con.cursor()
    cur.execute("DELETE FROM eintraege WHERE id = ?", (eintrag_id,))
    con.commit()
    con.close()


def passwort_generieren(laenge=16):
    """Sicheres zufälliges Passwort generieren."""
    zeichen = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(zeichen) for _ in range(laenge))


# ─── Login-Fenster ────────────────────────────────────────────────────────────

class LoginFenster:
    def __init__(self, root, bei_erfolg):
        self.root = root
        self.bei_erfolg = bei_erfolg

        self.root.title("Passwort-Manager — Login")
        self.root.geometry("420x320")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        self._ui_aufbauen()

    def _ui_aufbauen(self):
        # Titel
        tk.Label(
            self.root, text="🔐", font=("Helvetica", 36),
            bg="#1e1e2e", fg="#cdd6f4"
        ).pack(pady=(32, 4))

        if master_existiert():
            titel_text = "Willkommen zurück"
            btn_text = "Einloggen"
            self.aktion = self._einloggen
        else:
            titel_text = "Master-Passwort festlegen"
            btn_text = "Passwort speichern"
            self.aktion = self._registrieren

        tk.Label(
            self.root, text=titel_text,
            font=("Helvetica", 16, "bold"),
            bg="#1e1e2e", fg="#cdd6f4"
        ).pack()

        tk.Label(
            self.root, text="Dein Master-Passwort schützt alle gespeicherten Passwörter.",
            font=("Helvetica", 10),
            bg="#1e1e2e", fg="#6c7086", wraplength=360
        ).pack(pady=(4, 16))

        # Eingabe
        self.eingabe = tk.Entry(
            self.root, show="•",
            font=("Helvetica", 14),
            bg="#313244", fg="#cdd6f4",
            insertbackground="#cdd6f4",
            relief="flat", bd=0
        )
        self.eingabe.pack(ipady=10, ipadx=10, padx=40, fill="x")
        self.eingabe.bind("<Return>", lambda e: self.aktion())
        self.eingabe.focus()

        # Button
        tk.Button(
            self.root, text=btn_text,
            font=("Helvetica", 12, "bold"),
            bg="#89b4fa", fg="#1e1e2e",
            activebackground="#74c7ec",
            relief="flat", bd=0,
            padx=20, pady=10,
            cursor="hand2",
            command=self.aktion
        ).pack(pady=16)

    def _einloggen(self):
        pw = self.eingabe.get()
        if master_pruefen(pw):
            self.bei_erfolg()
        else:
            messagebox.showerror("Fehler", "Falsches Master-Passwort!")
            self.eingabe.delete(0, tk.END)

    def _registrieren(self):
        pw = self.eingabe.get()
        if len(pw) < 6:
            messagebox.showwarning("Hinweis", "Das Passwort muss mindestens 6 Zeichen lang sein.")
            return
        master_setzen(pw)
        messagebox.showinfo("Gespeichert", "Master-Passwort wurde gesetzt!")
        self.bei_erfolg()


# ─── Haupt-App ────────────────────────────────────────────────────────────────

class PasswortManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Passwort-Manager")
        self.root.geometry("700x520")
        self.root.resizable(False, False)
        self.root.configure(bg="#1e1e2e")

        self._ui_aufbauen()
        self._tabelle_aktualisieren()

    def _ui_aufbauen(self):
        # ── Kopfzeile ──
        kopf = tk.Frame(self.root, bg="#181825", pady=14)
        kopf.pack(fill="x")

        tk.Label(
            kopf, text="🔐  Passwort-Manager",
            font=("Helvetica", 18, "bold"),
            bg="#181825", fg="#cdd6f4"
        ).pack(side="left", padx=20)

        tk.Button(
            kopf, text="Neu generieren",
            font=("Helvetica", 10),
            bg="#a6e3a1", fg="#1e1e2e",
            activebackground="#94e2d5",
            relief="flat", bd=0,
            padx=10, pady=6,
            cursor="hand2",
            command=self._passwort_generieren
        ).pack(side="right", padx=20)

        # ── Eingabeformular ──
        form = tk.Frame(self.root, bg="#1e1e2e", pady=12)
        form.pack(fill="x", padx=20)

        felder = [("Webseite / App", "webseite"), ("Benutzername / E-Mail", "benutzer"), ("Passwort", "passwort")]
        self.felder = {}

        for i, (label, key) in enumerate(felder):
            tk.Label(
                form, text=label,
                font=("Helvetica", 10),
                bg="#1e1e2e", fg="#6c7086"
            ).grid(row=0, column=i, sticky="w", padx=(0 if i == 0 else 8, 0))

            zeige = "•" if key == "passwort" else ""
            entry = tk.Entry(
                form,
                show=zeige,
                font=("Helvetica", 12),
                bg="#313244", fg="#cdd6f4",
                insertbackground="#cdd6f4",
                relief="flat", bd=0
            )
            entry.grid(row=1, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0), ipady=8, ipadx=8)
            self.felder[key] = entry

        form.columnconfigure(0, weight=2)
        form.columnconfigure(1, weight=2)
        form.columnconfigure(2, weight=2)

        tk.Button(
            form, text="+ Speichern",
            font=("Helvetica", 11, "bold"),
            bg="#89b4fa", fg="#1e1e2e",
            activebackground="#74c7ec",
            relief="flat", bd=0,
            padx=14, pady=8,
            cursor="hand2",
            command=self._eintrag_speichern
        ).grid(row=1, column=3, padx=(10, 0), pady=(14, 0))

        # Trennlinie
        tk.Frame(self.root, bg="#313244", height=1).pack(fill="x", padx=20, pady=(8, 0))

        # ── Tabelle ──
        tabelle_frame = tk.Frame(self.root, bg="#1e1e2e")
        tabelle_frame.pack(fill="both", expand=True, padx=20, pady=12)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
            background="#313244",
            foreground="#cdd6f4",
            fieldbackground="#313244",
            rowheight=32,
            font=("Helvetica", 11)
        )
        style.configure("Treeview.Heading",
            background="#181825",
            foreground="#89b4fa",
            font=("Helvetica", 11, "bold"),
            relief="flat"
        )
        style.map("Treeview", background=[("selected", "#45475a")])

        spalten = ("webseite", "benutzername", "passwort")
        self.tabelle = ttk.Treeview(
            tabelle_frame,
            columns=spalten,
            show="headings",
            selectmode="browse"
        )

        self.tabelle.heading("webseite", text="Webseite / App")
        self.tabelle.heading("benutzername", text="Benutzername / E-Mail")
        self.tabelle.heading("passwort", text="Passwort")

        self.tabelle.column("webseite", width=180)
        self.tabelle.column("benutzername", width=220)
        self.tabelle.column("passwort", width=180)

        scrollbar = ttk.Scrollbar(tabelle_frame, orient="vertical", command=self.tabelle.yview)
        self.tabelle.configure(yscrollcommand=scrollbar.set)

        self.tabelle.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # ── Aktionsleiste ──
        aktionen = tk.Frame(self.root, bg="#1e1e2e")
        aktionen.pack(fill="x", padx=20, pady=(0, 16))

        tk.Button(
            aktionen, text="📋  Passwort kopieren",
            font=("Helvetica", 11),
            bg="#313244", fg="#cdd6f4",
            activebackground="#45475a",
            relief="flat", bd=0,
            padx=12, pady=7,
            cursor="hand2",
            command=self._passwort_kopieren
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            aktionen, text="🗑  Eintrag löschen",
            font=("Helvetica", 11),
            bg="#313244", fg="#f38ba8",
            activebackground="#45475a",
            relief="flat", bd=0,
            padx=12, pady=7,
            cursor="hand2",
            command=self._eintrag_loeschen
        ).pack(side="left")

        self.status = tk.Label(
            aktionen, text="",
            font=("Helvetica", 10),
            bg="#1e1e2e", fg="#6c7086"
        )
        self.status.pack(side="right")

    def _tabelle_aktualisieren(self):
        for zeile in self.tabelle.get_children():
            self.tabelle.delete(zeile)

        self.eintraege = alle_eintraege_laden()
        for eintrag in self.eintraege:
            _, webseite, benutzername, passwort = eintrag
            verdeckt = "•" * len(passwort)
            self.tabelle.insert("", "end", values=(webseite, benutzername, verdeckt))

        self.status.config(text=f"{len(self.eintraege)} Einträge gespeichert")

    def _eintrag_speichern(self):
        webseite = self.felder["webseite"].get().strip()
        benutzer = self.felder["benutzer"].get().strip()
        passwort = self.felder["passwort"].get().strip()

        if not webseite or not benutzer or not passwort:
            messagebox.showwarning("Hinweis", "Bitte alle Felder ausfüllen!")
            return

        eintrag_speichern(webseite, benutzer, passwort)

        for entry in self.felder.values():
            entry.delete(0, tk.END)

        self._tabelle_aktualisieren()

    def _passwort_generieren(self):
        """Zufälliges Passwort generieren und ins Passwort-Feld einfügen."""
        pw = passwort_generieren()
        self.felder["passwort"].delete(0, tk.END)
        self.felder["passwort"].insert(0, pw)
        self.felder["passwort"].config(show="")  # kurz sichtbar machen

    def _passwort_kopieren(self):
        """Passwort des ausgewählten Eintrags in die Zwischenablage kopieren."""
        auswahl = self.tabelle.selection()
        if not auswahl:
            messagebox.showwarning("Hinweis", "Bitte zuerst einen Eintrag auswählen.")
            return

        index = self.tabelle.index(auswahl[0])
        echtes_passwort = self.eintraege[index][3]

        self.root.clipboard_clear()
        self.root.clipboard_append(echtes_passwort)
        self.status.config(text="✓ Passwort kopiert!")
        self.root.after(3000, lambda: self.status.config(text=f"{len(self.eintraege)} Einträge gespeichert"))

    def _eintrag_loeschen(self):
        auswahl = self.tabelle.selection()
        if not auswahl:
            messagebox.showwarning("Hinweis", "Bitte zuerst einen Eintrag auswählen.")
            return

        index = self.tabelle.index(auswahl[0])
        eintrag_id = self.eintraege[index][0]
        webseite = self.eintraege[index][1]

        if messagebox.askyesno("Löschen?", f'Eintrag für "{webseite}" wirklich löschen?'):
            eintrag_loeschen(eintrag_id)
            self._tabelle_aktualisieren()


# ─── Start ────────────────────────────────────────────────────────────────────

def app_starten():
    """Nach erfolgreichem Login die Haupt-App öffnen."""
    for widget in root.winfo_children():
        widget.destroy()
    root.geometry("700x520")
    PasswortManager(root)


if __name__ == "__main__":
    datenbank_erstellen()
    root = tk.Tk()
    LoginFenster(root, bei_erfolg=app_starten)
    root.mainloop()
