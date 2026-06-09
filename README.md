# Kaskad UFW — каскадный прокси‑сервер на базе UFW

**Форк** оригинального репозитория [anten‑ka/kaskad](https://github.com/anten-ka/kaskad), переработанный для работы через **UFW** (Uncomplicated Firewall) вместо `iptables-persistent`.

Скрипт создаёт «мост» (каскад) между вашим клиентом и зарубежным VPN/прокси‑сервером через промежуточный VPS. Входящий трафик на VPS перенаправляется на удалённый сервер, а ответы — обратно клиенту.

## ⚡ Отличия от оригинала

| Характеристика | Оригинал (iptables) | Эта версия (UFW) |
|----------------|----------------------|------------------|
| Базовый инструмент | `iptables` + `iptables-persistent` | **UFW** |
| Хранение правил | `iptables-save` | `/etc/ufw/before.rules` в конец |
| Полная очистка | Удаляет все цепочки iptables | Удаляет только правила внесенные скриптом |
| Конфликты с UFW | Возможны | Полная совместимость |

## 🚀 Быстрая установка

**Одной командой (рекомендуется):**

```bash
curl -sSL https://raw.githubusercontent.com/hargluk/kaskad_ufw_only/refs/heads/main/install_clean.sh | sudo bash
```

Или через wget:
```bash
wget -qO- https://raw.githubusercontent.com/hargluk/kaskad_ufw_only/refs/heads/main/install_clean.sh | sudo bash
```

После первого запуска скрипт сам скопирует себя в /usr/local/bin/gokaskad – в дальнейшем вызывайте его просто командой
```bash
sudo gokaskad.
```

Установка с сохранением файла
```bash
wget -O install.sh https://raw.githubusercontent.com/hargluk/kaskad_ufw_only/refs/heads/main/install_clean.sh && chmod +x install.sh && sudo ./install.sh
```
## Возможности

- Проброс UDP (WireGuard, AmneziaWG) и TCP (VLESS, XRay, MTProto)
- Кастомные правила с разными входящим/исходящим портами
- Включение IP Forwarding и BBR
- Просмотр, удаление одного правила, полная очистка только своих правил
- Автоматическое создание команды `gokaskad` после первого запуска
- Порт SSH (22) всегда открыт

## Пример настройки каскада

1. На зарубежном сервере работает WireGuard (UDP, порт 41999, IP 124.105.244.155)
2. Запустите скрипт на вашем VPS
3. Выберите пункт меню **1** (AmneziaWG / WireGuard)
4. Введите IP назначения: `124.105.244.155`
5. Введите порт: `41999`

Готово. Теперь в конфигурации клиента укажите **IP вашего VPS** вместо оригинального зарубежного IP.

## Управление правилами
После запуска скрипта появится меню:
1. Настроить AmneziaWG / WireGuard (UDP)
2. Настроить VLESS / XRay / TProxy / MTProto (TCP)
3. Кастомное правило (разные порты, любой протокол)
4. Показать активные правила
5. Удалить одно правило
7. Сбросить ВСЕ правила (только добавленные скриптом)
8. Инструкция
0. Выход

## Требования
- Ubuntu / Debian (или любой дистрибутив с UFW)
- Права root (скрипт сам проверит)
- Доступ в интернет (для установки UFW, если он не установлен)

![Bash](https://img.shields.io/badge/Language-Bash-green)
![System](https://img.shields.io/badge/OS-Ubuntu%20%7C%20Debian-orange)
![License](https://img.shields.io/badge/License-MIT-blue)

Создано без знаний програмирования, мучением китайского агента ИИ
