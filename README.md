# DSFM (DavShopFrameworkM)

DSFM è un progetto Python 3 singolo-file (`app.py`) che avvia nello stesso processo:

- pannello admin Flask
- bot Telegram (`pyTelegramBotAPI`)
- database SQLite

Il bot e il web server girano insieme: Flask nel thread principale, polling Telegram in thread dedicato.

## Funzioni principali

- Setup iniziale admin (primo account = `superadmin`)
- Login/logout sicuro con CSRF e session hardening
- Costruttore menu Telegram ad albero (nodi, pulsanti, media, import/export JSON)
- Flusso ordini con carrello, modifica elementi, invio ordine in chat admin
- Chat supporto controllata (una chat aperta per utente, reply da pannello, close/reopen/sospensione)
- Notifica utente quando admin chiude la richiesta
- Statistiche + export CSV/JSON
- Logging avanzato:
  - file continuo `logs/bot_activity.log`
  - log strutturati su DB (`activity_logs`) con `level` e `source`
  - pagina log admin con filtri e tail del file live

## Gestione Admin e Ruoli

- Primo account creato in `/setup` => `superadmin`
- Il `superadmin` può:
  - creare altri admin
  - trasferire il ruolo `superadmin` a un altro admin
- Un `superadmin` non può eliminare il proprio account finché non trasferisce il ruolo
- Dopo il trasferimento, l’ex superadmin diventa admin normale e può eliminare il suo account
- Ogni admin può:
  - cambiare username
  - cambiare password
  - eliminare il proprio account (se consentito dai vincoli)

## Requisiti

- Python 3.10+
- Linux/macOS consigliati per deploy VPS

## Installazione

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.example.toml config.toml
```

Configura token e segreti:

- consigliato via env:

```bash
export DSFM_BOT_TOKEN="TOKEN_BOT"
export DSFM_SECRET_KEY="CHIAVE_RANDOM_LUNGA"
```

- oppure in `config.toml` (meno consigliato per ambienti condivisi)

## Avvio

```bash
python app.py
```

Poi apri:

- `http://<host>:<port>/setup` (solo primo avvio)
- `http://<host>:<port>/login`

## Test

```bash
./venv/bin/pytest -q
```

## Struttura

- `app.py`: logica completa app + bot
- `templates/`: pagine HTML pannello
- `static/`: CSS e JS
- `logs/`: file log runtime
- `uploads/`: media caricati dal pannello
- `tests/`: test automatici
- `docs/`: documentazione operativa

## Note sicurezza operative

- Se un token bot è stato condiviso pubblicamente, rigeneralo subito su BotFather
- Usa `DSFM_SECRET_KEY` forte e stabile
- Attiva HTTPS su VPS e imposta `session_cookie_secure = true` in produzione
- Esegui backup periodico di `dsfm.sqlite3` e `logs/`
