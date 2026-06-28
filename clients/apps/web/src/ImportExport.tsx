import { useState } from "react";
import {
  type Session,
  type VaultItem,
  type ItemFields,
  toCSV,
  toPlaintextJSON,
  parseVaultImport,
  importItems,
} from "@passwd/api-client";
import { encryptBackup, decryptBackup, isBackupEnvelope } from "@passwd/crypto";
import { PasswordField } from "./components/PasswordField";
import { AsyncButton } from "./components/AsyncButton";
import { Icon } from "./components/Icon";

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function download(filename: string, text: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : "Something went wrong.";
}

export function ImportExport(props: {
  session: Session;
  items: VaultItem[];
  onClose: () => void;
  onImported: () => void;
}) {
  const [exportPass, setExportPass] = useState("");
  const [exportErr, setExportErr] = useState<string | null>(null);

  // Import is a small state machine: pick file -> (maybe decrypt) -> preview ->
  // confirm. `encrypted` holds the raw envelope while we wait for a passphrase.
  const [encrypted, setEncrypted] = useState<string | null>(null);
  const [importPass, setImportPass] = useState("");
  const [parsed, setParsed] = useState<ItemFields[] | null>(null);
  const [importErr, setImportErr] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);

  function resetImport() {
    setEncrypted(null);
    setImportPass("");
    setParsed(null);
    setImportErr(null);
    setResult(null);
    setProgress(null);
  }

  function exportPlain(kind: "json" | "csv") {
    const text = kind === "csv" ? toCSV(props.items) : toPlaintextJSON(props.items);
    download(`passwd-export-${today()}.${kind}`, text, kind === "csv" ? "text/csv" : "application/json");
  }

  async function exportEncrypted(): Promise<boolean> {
    setExportErr(null);
    if (exportPass.length < 8) {
      setExportErr("Use a backup passphrase of at least 8 characters.");
      return false;
    }
    const text = await encryptBackup(toPlaintextJSON(props.items), exportPass);
    download(`passwd-backup-${today()}.json`, text, "application/json");
    setExportPass("");
    return true;
  }

  function tryParse(text: string) {
    try {
      setParsed(parseVaultImport(text));
      setImportErr(null);
    } catch (e) {
      setParsed(null);
      setImportErr(errMsg(e));
    }
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    resetImport();
    const file = e.target.files?.[0];
    e.target.value = ""; // allow re-selecting the same file
    if (!file) return;
    const text = await file.text();
    if (isBackupEnvelope(text)) setEncrypted(text);
    else tryParse(text);
  }

  async function decrypt() {
    if (!encrypted) return;
    setImportErr(null);
    try {
      tryParse(await decryptBackup(encrypted, importPass));
    } catch (e) {
      setImportErr(errMsg(e));
    }
  }

  async function runImport() {
    if (!parsed) return;
    setProgress({ done: 0, total: parsed.length });
    const res = await importItems(props.session, parsed, (done, total) => setProgress({ done, total }));
    setProgress(null);
    setParsed(null);
    setResult(`Imported ${res.added} item${res.added === 1 ? "" : "s"}${res.failed ? `, ${res.failed} failed` : ""}.`);
    props.onImported();
  }

  return (
    <div className="modal-backdrop" onClick={props.onClose}>
      <div className="card modal" onClick={(e) => e.stopPropagation()}>
        <h2>Import / export</h2>

        <section className="ie-section">
          <h3>Export</h3>
          <p className="muted">{props.items.length} item{props.items.length === 1 ? "" : "s"} in this vault.</p>

          <div className="warn-banner">
            Plain exports are <strong>unencrypted</strong> and contain every password in clear text. Store them
            briefly, then delete.
          </div>
          <div className="row">
            <button className="ghost" onClick={() => exportPlain("json")}>
              Plain JSON
            </button>
            <button className="ghost" onClick={() => exportPlain("csv")}>
              CSV
            </button>
          </div>

          <label>Encrypted backup passphrase</label>
          <PasswordField value={exportPass} onChange={setExportPass} placeholder="protects the backup file" />
          {exportErr && <div className="error">{exportErr}</div>}
          <AsyncButton variant="primary" loadingLabel="Encrypting" successLabel="Downloaded" onClick={exportEncrypted}>
            <span className="btn-ico">
              <Icon name="download" size={16} /> Download encrypted backup
            </span>
          </AsyncButton>
        </section>

        <section className="ie-section">
          <h3>Import</h3>
          <p className="muted">
            From a passwd backup, plain JSON, or a CSV exported by another manager (Bitwarden, Chrome, and similar).
          </p>
          <input type="file" accept=".json,.csv,.txt" onChange={onFile} />

          {encrypted && !parsed && (
            <>
              <label>Backup passphrase</label>
              <PasswordField value={importPass} onChange={setImportPass} placeholder="passphrase for this backup" />
              <div className="row">
                <button className="ghost" onClick={decrypt}>
                  Decrypt
                </button>
              </div>
            </>
          )}

          {importErr && <div className="error">{importErr}</div>}

          {parsed && (
            <>
              <div className="warn-banner">
                Ready to import <strong>{parsed.length}</strong> item{parsed.length === 1 ? "" : "s"}. They are added to
                your vault (existing items are kept).
              </div>
              <div className="row">
                <button className="ghost" onClick={resetImport}>
                  Cancel
                </button>
                <AsyncButton variant="primary" loadingLabel="Importing" successLabel="Done" onClick={runImport}>
                  Import {parsed.length} item{parsed.length === 1 ? "" : "s"}
                </AsyncButton>
              </div>
            </>
          )}

          {progress && (
            <p className="muted">
              Importing {progress.done} / {progress.total}...
            </p>
          )}
          {result && <div className="ie-result">{result}</div>}
        </section>

        <div className="row end">
          <button className="ghost" onClick={props.onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
