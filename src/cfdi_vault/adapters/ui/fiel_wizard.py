"""Local Tkinter wizard for FIEL/e.firma onboarding.

Security contract: see docs/adr/0003-fiel-local-onboarding-wizard.md.

This window is a local, offline desktop process only. It never starts a
network listener, never auto-discovers or reads the phrase from any file,
and never calls SAT campaign creation/authorization/run. The phrase widget
value is read once into a local variable at submit time, handed straight to
``fiel_wizard_logic.run_wizard_setup``, and cleared from both Tk variables
immediately after.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from cfdi_vault.adapters.ui.fiel_wizard_logic import (
    DEFAULT_LOCAL_DATABASE_URL,
    DEFAULT_LOCAL_RABBITMQ_URL,
    DEFAULT_LOCAL_REDIS_URL,
    default_local_commit_ref,
    default_local_storage_root,
    load_existing_profile_for_prefill,
    run_diagnostic_command,
    run_wizard_setup,
)


class FielOnboardingWizard(tk.Tk):
    """Local desktop window for onboarding one FIEL profile."""

    def __init__(self) -> None:
        super().__init__()
        self.title("CFDI Vault MX - FIEL onboarding local")
        self.resizable(False, False)

        self.profile_id_var = tk.StringVar(value="default")
        self.rfc_var = tk.StringVar()
        self.certificate_path_var = tk.StringVar()
        self.private_key_path_var = tk.StringVar()
        self.credential_mode_var = tk.StringVar(value="referenced")
        self.database_url_var = tk.StringVar(value=DEFAULT_LOCAL_DATABASE_URL)
        self.storage_root_var = tk.StringVar(value=default_local_storage_root(self.profile_id_var.get()))
        self.rabbitmq_url_var = tk.StringVar(value=DEFAULT_LOCAL_RABBITMQ_URL)
        self.redis_url_var = tk.StringVar(value=DEFAULT_LOCAL_REDIS_URL)
        self.commit_ref_var = tk.StringVar(value=default_local_commit_ref() or "")
        self._phrase_entry: tk.Entry
        self._confirm_entry: tk.Entry

        self._build_form()
        self._build_diagnostics()
        self._build_output()

    def _build_form(self) -> None:
        form = ttk.LabelFrame(self, text="Perfil FIEL local")
        form.grid(row=0, column=0, padx=12, pady=12, sticky="ew")

        ttk.Label(form, text="Perfil:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(form, textvariable=self.profile_id_var, width=40).grid(row=0, column=1, padx=4, pady=4)
        ttk.Button(form, text="Cargar existente", command=self._load_existing_profile).grid(row=0, column=2, padx=4, pady=4)

        ttk.Label(form, text="RFC:").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(form, textvariable=self.rfc_var, width=40).grid(row=1, column=1, padx=4, pady=4)

        ttk.Label(form, text="Certificado (.cer):").grid(row=2, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(form, textvariable=self.certificate_path_var, width=40, state="readonly").grid(row=2, column=1, padx=4, pady=4)
        ttk.Button(form, text="Elegir...", command=self._choose_certificate).grid(row=2, column=2, padx=4, pady=4)

        ttk.Label(form, text="Llave privada (.key):").grid(row=3, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(form, textvariable=self.private_key_path_var, width=40, state="readonly").grid(row=3, column=1, padx=4, pady=4)
        ttk.Button(form, text="Elegir...", command=self._choose_private_key).grid(row=3, column=2, padx=4, pady=4)

        ttk.Label(form, text="Modo de credencial:").grid(row=4, column=0, sticky="w", padx=4, pady=4)
        ttk.Combobox(
            form,
            textvariable=self.credential_mode_var,
            values=("referenced", "copied"),
            state="readonly",
            width=37,
        ).grid(row=4, column=1, padx=4, pady=4)

        ttk.Label(form, text="Frase de la llave privada:").grid(row=5, column=0, sticky="w", padx=4, pady=4)
        self._phrase_entry = ttk.Entry(form, width=40, show="*")
        self._phrase_entry.grid(row=5, column=1, padx=4, pady=4)

        ttk.Label(form, text="Confirmar frase:").grid(row=6, column=0, sticky="w", padx=4, pady=4)
        self._confirm_entry = ttk.Entry(form, width=40, show="*")
        self._confirm_entry.grid(row=6, column=1, padx=4, pady=4)

        ttk.Button(form, text="Validar y guardar", command=self._on_submit).grid(row=7, column=0, columnspan=3, pady=8)

        warning = (
            "La frase nunca se guarda en archivos, logs, ni en el portapapeles.\n"
            "Se guarda unicamente en el almacen de credenciales del sistema operativo."
        )
        ttk.Label(form, text=warning, foreground="#555").grid(row=8, column=0, columnspan=3, sticky="w", padx=4, pady=(0, 4))

    def _build_diagnostics(self) -> None:
        diagnostics = ttk.LabelFrame(self, text="Diagnostico local (sin contactar al SAT)")
        diagnostics.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="ew")

        ttk.Label(diagnostics, text="Database URL (local, no es secreto real):").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(diagnostics, textvariable=self.database_url_var, width=52).grid(row=0, column=1, columnspan=2, padx=4, pady=4, sticky="w")

        ttk.Label(diagnostics, text="Storage root (fuera del repo):").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(diagnostics, textvariable=self.storage_root_var, width=52).grid(row=1, column=1, columnspan=2, padx=4, pady=4, sticky="w")

        ttk.Label(diagnostics, text="RabbitMQ URL (local, no es secreto real):").grid(row=2, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(diagnostics, textvariable=self.rabbitmq_url_var, width=52).grid(row=2, column=1, columnspan=2, padx=4, pady=4, sticky="w")

        ttk.Label(diagnostics, text="Redis URL (local):").grid(row=3, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(diagnostics, textvariable=self.redis_url_var, width=52).grid(row=3, column=1, columnspan=2, padx=4, pady=4, sticky="w")

        ttk.Label(diagnostics, text="Commit ref (opaco, no es secreto):").grid(row=4, column=0, sticky="w", padx=4, pady=4)
        ttk.Entry(diagnostics, textvariable=self.commit_ref_var, width=52).grid(row=4, column=1, columnspan=2, padx=4, pady=4, sticky="w")

        ttk.Button(diagnostics, text="Estado del perfil", command=lambda: self._run_diagnostic("status")).grid(row=5, column=0, padx=4, pady=6)
        ttk.Button(diagnostics, text="Doctor", command=lambda: self._run_diagnostic("doctor")).grid(row=5, column=1, padx=4, pady=6)
        ttk.Button(diagnostics, text="Preflight", command=lambda: self._run_diagnostic("preflight")).grid(row=5, column=2, padx=4, pady=6)

    def _build_output(self) -> None:
        output_frame = ttk.LabelFrame(self, text="Resultado (siempre redactado)")
        output_frame.grid(row=2, column=0, padx=12, pady=(0, 12), sticky="ew")
        self._output = tk.Text(output_frame, width=64, height=12, state="disabled", wrap="word")
        self._output.grid(row=0, column=0, padx=4, pady=4)

    def _choose_certificate(self) -> None:
        path = filedialog.askopenfilename(title="Selecciona el archivo .cer", filetypes=[("Certificado", "*.cer")])
        if path:
            self.certificate_path_var.set(path)

    def _choose_private_key(self) -> None:
        path = filedialog.askopenfilename(title="Selecciona el archivo .key", filetypes=[("Llave privada", "*.key")])
        if path:
            self.private_key_path_var.set(path)

    def _load_existing_profile(self) -> None:
        profile_id = self.profile_id_var.get()
        self.storage_root_var.set(default_local_storage_root(profile_id))
        fields = load_existing_profile_for_prefill(profile_id)
        if fields is None:
            messagebox.showinfo("Cargar perfil", f"No hay un perfil guardado con el id '{profile_id}'.")
            return
        self.rfc_var.set(fields.rfc)
        self.certificate_path_var.set(fields.certificate_path)
        self.private_key_path_var.set(fields.private_key_path)
        self.credential_mode_var.set(fields.credential_mode)
        messagebox.showinfo(
            "Cargar perfil",
            "Datos no secretos precargados. La frase de la llave privada no se precarga: "
            "dejala vacia si solo vas a usar los diagnosticos, o volvela a escribir si "
            "queres reemplazarla.",
        )

    def _on_submit(self) -> None:
        phrase_value = self._phrase_entry.get()
        phrase_confirmation = self._confirm_entry.get()
        try:
            certificate_path = Path(self.certificate_path_var.get())
            private_key_path = Path(self.private_key_path_var.get())
            if not self.certificate_path_var.get() or not self.private_key_path_var.get():
                messagebox.showerror("Perfil FIEL", "Selecciona el certificado y la llave privada.")
                return
            outcome = run_wizard_setup(
                profile_id=self.profile_id_var.get(),
                rfc=self.rfc_var.get(),
                certificate_path=certificate_path,
                private_key_path=private_key_path,
                phrase_value=phrase_value,
                phrase_confirmation=phrase_confirmation,
                credential_mode=self.credential_mode_var.get(),
            )
        finally:
            phrase_value = ""
            phrase_confirmation = ""
            self._phrase_entry.delete(0, tk.END)
            self._confirm_entry.delete(0, tk.END)

        if outcome.ok:
            self._show_output(
                "Perfil listo.\n"
                f"Perfil: {outcome.profile_id}\n"
                f"RFC: {outcome.redacted_rfc}\n"
                f"Modo de credencial: {outcome.credential_mode}\n"
                f"Huella del certificado: {outcome.redacted_fingerprint}\n"
                f"Verificacion local: {outcome.credential_check_detail}"
            )
        else:
            self._show_output("No se pudo completar el onboarding:\n- " + "\n- ".join(outcome.messages))

    def _run_diagnostic(self, command: str) -> None:
        text = run_diagnostic_command(
            command,
            profile_id=self.profile_id_var.get(),
            database_url=self.database_url_var.get() or None,
            storage_root=self.storage_root_var.get() or None,
            rabbitmq_url=self.rabbitmq_url_var.get() or None,
            redis_url=self.redis_url_var.get() or None,
            commit_ref=self.commit_ref_var.get() or None,
        )
        self._show_output(text)

    def _show_output(self, text: str) -> None:
        self._output.configure(state="normal")
        self._output.delete("1.0", tk.END)
        self._output.insert(tk.END, text)
        self._output.configure(state="disabled")


def main() -> None:
    """Launch the local FIEL onboarding wizard."""

    app = FielOnboardingWizard()
    app.mainloop()


if __name__ == "__main__":
    main()
