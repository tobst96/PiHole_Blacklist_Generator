import requests
import re
import sqlite3
import threading
import configparser
import os
from urllib.parse import urlparse
from tqdm import tqdm  # Fortschrittsanzeige
from threading import Lock
import logging
import os
import time

# Logger konfigurieren
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("blocklist.log"),
                        logging.StreamHandler()
                    ])

# SQLite-Datenbank initialisieren
db_lock = Lock()  # Lock für den Datenbankzugriff
# Maximale Größe für eine Blocklist-Datei (24 MB)
MAX_FILE_SIZE_MB = 24
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


def init_db():
    conn = sqlite3.connect('blocklist.db', check_same_thread=False)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS urls (url TEXT UNIQUE)''')
    conn.commit()
    conn.close()

# URLs aus einer heruntergeladenen Liste extrahieren und in SQLite speichern
def save_urls_to_db(content):
    regex = r'\d{1,3}(?:\.\d{1,3}){3}\s+(\S+)'
    matches = re.findall(regex, content)
    
    with db_lock:
        conn = sqlite3.connect('blocklist.db', check_same_thread=False)
        c = conn.cursor()
        for match in matches:
            try:
                c.execute('INSERT OR IGNORE INTO urls (url) VALUES (?)', (match,))
            except sqlite3.IntegrityError:
                pass
        conn.commit()
        conn.close()

# Prüft, ob die URL gültig ist
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# URL aus der blocklist.ini löschen
def remove_url_from_ini(url):
    config = configparser.ConfigParser()
    config.read('blocklist.ini')

    urls = config['blocklist']['urls'].splitlines()
    urls = [u.strip() for u in urls if u.strip() and u.strip() != url]

    config['blocklist']['urls'] = "\n".join(urls)

    with open('blocklist.ini', 'w') as configfile:
        config.write(configfile)
    
    logging.info(f"URL entfernt: {url} aus blocklist.ini")

# Datei herunterladen und verarbeiten
def download_and_process(url, progress_bar, retries=3, delay=2):
    if not is_valid_url(url):
        logging.warning(f"Ungültige URL übersprungen: {url}")
        progress_bar.update(1)  # Fortschrittsanzeige aktualisieren
        return

    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=30)  # Setze ein Timeout von 10 Sekunden
            if response.status_code == 200:
                save_urls_to_db(response.text)
                break
            elif response.status_code == 404:
                logging.info(f"404 Fehler: {url} wird aus blocklist.ini entfernt.")
                remove_url_from_ini(url)  # Entferne URL aus blocklist.ini
                break
            else:
                logging.error(f"Fehler beim Herunterladen der Liste: {url} (Status: {response.status_code})")
        except requests.ConnectionError as e:
            logging.debug(f"Verbindungsfehler: {e}. Versuch {attempt + 1} von {retries}.")
        except requests.Timeout:
            logging.debug(f"Timeout bei der Anfrage an {url}. Versuch {attempt + 1} von {retries}.")
        except requests.RequestException as e:
            logging.error(f"Fehler bei der Anfrage: {e}")
        time.sleep(delay)  # Wartezeit zwischen den Versuchen
    else:
        logging.error(f"Alle Versuche fehlgeschlagen für: {url}")

    progress_bar.update(1)  # Fortschrittsanzeige aktualisieren

# Blocklist.ini parsen
def parse_blocklist_ini():
    config = configparser.ConfigParser()
    config.read('blocklist.ini')
    urls = config['blocklist']['urls'].splitlines()
    return [url.strip() for url in urls if url.strip()]

# URLs aus der Datenbank in blocklist.txt speichern
def save_to_blocklist_txt():
    # Datei-Index für gesplittete Dateien
    file_index = 1
    current_file_size = 0

    # Dateiname für die erste Blocklist-Datei
    blocklist_filename = f'blocklist_{file_index}.txt'
    
    # Lösche alte Blocklist-Dateien, falls sie existieren
    for file in os.listdir('.'):
        if file.startswith('blocklist_') and file.endswith('.txt'):
            os.remove(file)

    with db_lock:
        conn = sqlite3.connect('blocklist.db', check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT DISTINCT url FROM urls')
        unique_urls = c.fetchall()
        conn.close()

    # Öffne die erste Datei
    blocklist_file = open(blocklist_filename, 'w')
    
    for url in unique_urls:
        url_line = f"{url[0]}\n"
        
        # Prüfe, ob das Hinzufügen dieser URL die Dateigröße über 24 MB bringt
        if current_file_size + len(url_line.encode('utf-8')) > MAX_FILE_SIZE_BYTES:
            # Datei schließen und eine neue Datei öffnen
            blocklist_file.close()
            file_index += 1
            blocklist_filename = f'blocklist_{file_index}.txt'
            blocklist_file = open(blocklist_filename, 'w')
            current_file_size = 0  # Zurücksetzen der Dateigröße für die neue Datei
            
        # Schreibe die URL in die aktuelle Datei und aktualisiere die Dateigröße
        blocklist_file.write(url_line)
        current_file_size += len(url_line.encode('utf-8'))

    # Schließe die letzte Datei
    blocklist_file.close()

    logging.info(f"Blocklist wurde in {file_index} Datei(en) gespeichert.")

# Funktion zum Hinzufügen von URLs aus everyblocklist.txt
def add_urls_from_everyblocklist():
    everyblocklist_file = 'everyblocklist.txt'

    # Wenn die Datei nicht existiert, wird sie angelegt
    if not os.path.exists(everyblocklist_file):
        logging.info(f"{everyblocklist_file} nicht gefunden. Datei wird erstellt.")
        open(everyblocklist_file, 'w').close()  # Leere Datei erstellen
        return  # Keine weiteren Schritte nötig, da keine URLs hinzugefügt werden

    # URLs aus everyblocklist.txt lesen
    with open(everyblocklist_file, 'r') as f:
        additional_urls = [line.strip() for line in f if line.strip()]

    if not additional_urls:
        logging.info(f"Keine zusätzlichen URLs in {everyblocklist_file} gefunden.")
        return

    # Fortschrittsanzeige initialisieren
    progress_bar = tqdm(total=len(additional_urls), desc="Hinzufügen von zusätzlichen URLs", unit="URL")

    # URLs zur Datenbank hinzufügen
    with db_lock:
        conn = sqlite3.connect('blocklist.db', check_same_thread=False)
        c = conn.cursor()
        for url in additional_urls:
            try:
                c.execute('INSERT OR IGNORE INTO urls (url) VALUES (?)', (url,))
                logging.info(f"Zusätzliche URL hinzugefügt: {url}")
            except sqlite3.IntegrityError:
                pass  # Doppelte URLs ignorieren

            progress_bar.update(1)  # Fortschrittsbalken aktualisieren

        conn.commit()
        conn.close()

    progress_bar.close()  # Fortschrittsanzeige schließen

# Filter anwenden auf URLs
def whitelist_regex(filters):
    if not os.path.exists('blocklist.txt'):
        logging.warning("blocklist.txt existiert nicht!")
        return

    # Lade alle URLs aus der Datenbank
    with db_lock:
        conn = sqlite3.connect('blocklist.db', check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT DISTINCT url FROM urls')
        db_urls = {row[0].strip() for row in c.fetchall()}  # Alle URLs aus der DB laden
        conn.close()

    # Lies die Zeilen aus blocklist.txt
    with open('blocklist.txt', 'r') as f:
        lines = f.readlines()

    # Initialisiere die Fortschrittsanzeige für die Filterung
    progress_bar = tqdm(total=len(lines), desc="Whitelist Regex", unit="Zeile")

    # Liste, um die gefilterten URLs zu speichern
    filtered_urls = set()

    for line in lines:
        url = line.strip()

        # Überprüfe die URL mit jedem Filter
        for filter_regex in filters:
            if re.search(filter_regex, url):
                logging.debug(f"URL {url} wurde durch Filter {filter_regex} entfernt")
                filtered_urls.add(url)  # Die gefilterte URL speichern
                break  # Wenn ein Filter zutrifft, wird diese URL nicht weiter geprüft

        progress_bar.update(1)

    progress_bar.close()

    # Entferne die gefilterten URLs aus der Datenbank
    with db_lock:
        conn = sqlite3.connect('blocklist.db', check_same_thread=False)
        c = conn.cursor()

        for url in filtered_urls:
            if url in db_urls:
                c.execute("DELETE FROM urls WHERE url = ?", (url,))
                logging.debug(f"WHITELIST - URL {url} aus der Datenbank gelöscht.")

        conn.commit()
        conn.close()

    # Lösche die alte blocklist.txt und erstelle eine neue
    if os.path.exists('blocklist.txt'):
        os.remove('blocklist.txt')
    save_to_blocklist_txt()  # Speichere die neue Blockliste
    logging.info("Blocklist wurde nach der Filterung neu generiert.")

# Funktion zum Entfernen von URLs basierend auf whitelist.txt
def process_whitelist():
    whitelist_file = 'whitelist.txt'

    # Wenn die Datei nicht existiert, wird sie erstellt
    if not os.path.exists(whitelist_file):
        logging.info(f"{whitelist_file} nicht gefunden. Datei wird erstellt.")
        open(whitelist_file, 'w').close()  # Leere Datei erstellen
        return  # Keine weiteren Schritte, da keine URLs zum Entfernen vorliegen

    # URLs aus whitelist.txt lesen
    with open(whitelist_file, 'r') as f:
        whitelist_urls = [line.strip() for line in f if line.strip()]

    if not whitelist_urls:
        logging.info(f"Keine URLs in {whitelist_file} gefunden.")
        return

    # Fortschrittsanzeige initialisieren
    progress_bar = tqdm(total=len(whitelist_urls), desc="Whitelist Verarbeitung", unit="URL")

    # URLs aus der Datenbank entfernen
    with db_lock:
        conn = sqlite3.connect('blocklist.db', check_same_thread=False)
        c = conn.cursor()
        for url in whitelist_urls:
            try:
                c.execute('DELETE FROM urls WHERE url = ?', (url,))
                logging.debug(f"URL aus der Whitelist entfernt: {url}")
            except sqlite3.Error as e:
                logging.error(f"Fehler beim Entfernen der URL {url} aus der Datenbank: {e}")

            progress_bar.update(1)  # Fortschrittsbalken aktualisieren

        conn.commit()
        conn.close()

    progress_bar.close()  # Fortschrittsanzeige schließen

# Funktion zur Ausgabe der Anzahl von Zeilen in blocklist.txt
def count_blocklist_lines():
    blocklist_file = 'blocklist.txt'
    
    if not os.path.exists(blocklist_file):
        logging.warning(f"{blocklist_file} existiert nicht.")
        return 0

    with open(blocklist_file, 'r') as f:
        lines = f.readlines()

    line_count = len(lines)
    logging.info(f"Anzahl der Zeilen in {blocklist_file}: {line_count}")
    return line_count

# Hauptprogramm
def main():
    init_db()
    urls = parse_blocklist_ini()
    
    progress_bar = tqdm(total=len(urls), desc="Download-Fortschritt", unit="url")
    
    threads = []
    for url in urls:
        t = threading.Thread(target=download_and_process, args=(url, progress_bar))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    progress_bar.close()

    save_to_blocklist_txt()

    filters = [
        r'www\.([a-zA-Z0-9._-]*)',  
        r'\s-\s',                   
        r'\s!\s',                   
        r'\s#\s'
    ]
    
    whitelist_regex(filters)

    # Zusätzliche URLs aus everyblocklist.txt hinzufügen
    add_urls_from_everyblocklist()

    #0 Blocklist.txt erneut speichern mit den zusätzlichen URLs
    save_to_blocklist_txt()

    # Whitelist URLs entfernen und blocklist.txt neu generieren
    process_whitelist()

    # Anzahl der Zeilen in blocklist.txt ausgeben
    count_blocklist_lines()

if __name__ == '__main__':
    main()

